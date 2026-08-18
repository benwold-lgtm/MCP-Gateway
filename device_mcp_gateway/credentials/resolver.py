# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Resolve a credential reference to material, at dispatch time (ADR-0018 §1/§2).

The registry stores a **reference** and the gateway holds an identity allowed to dereference
it. Nothing here persists what it resolves: the material is returned to the caller for one
dispatch and is not written back, cached to disk, or included in an archive.

    secret://t-3f9a1c2b7d4e8065/devices/prism#api-key

**The scheme is backend-neutral on purpose**, settling ADR-0018's open question in the
direction it leaned. Naming the backend in the reference (``vault://``) would bake a
deployment choice into every device record, so an archive could only be restored into a stack
using the same product. ``secret://`` names *what it is*; how it is fetched is configuration.

**Two failure kinds, never one** (ADR-0018 §7). A bad reference is one device's
misconfiguration and is permanent; an unreachable store is the whole fleet's problem and is
transient. Collapsing them makes a sealed store look like twenty broken devices, and opens
every device's breaker on a fault none of them had.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable
from urllib.parse import urlsplit

SCHEME = "secret"

#: One path segment. Deliberately strict — a reference is written by an operator or a
#: console, not by a user, so there is no case for permissiveness here. Excluding ``.`` and
#: ``..`` at the pattern level is what makes traversal unrepresentable rather than filtered:
#: a check that strips ``..`` has to be correct at every call site, and a pattern that cannot
#: express it has to be correct once.
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ResolverError(Exception):
    """Base for resolution failures. Never carries credential material."""


class ReferenceInvalid(ResolverError):
    """This device's reference does not name a secret that exists, or is malformed.

    **Permanent, and scoped to one device.** No retry and no breaker: retrying a typo is
    noise, and a device whose reference is wrong should be marked faulted with a reason its
    operator can act on. The rest of the fleet is unaffected.
    """


class StoreUnavailable(ResolverError):
    """The secret store could not be reached or read.

    **Transient, and fleet-wide.** Every device resolving through this backend is affected,
    for a reason that is neither the device's fault nor the tenant's. ADR-0018 §7 puts the
    circuit breaker here — one per backend — rather than on each device, so that when the
    store returns, one probe re-admits the whole fleet instead of each device serving out an
    independent reset timeout it never earned.
    """


class CredentialRef:
    """A parsed ``secret://`` reference.

    Parsing is separated from resolution so a malformed reference is caught at registration
    rather than at 3am on a dispatch — the same reason the egress policy moved into
    ``register_device`` (F-67) instead of living in one route.
    """

    __slots__ = ("namespace", "path", "key", "raw")

    def __init__(self, namespace: str, path: tuple[str, ...], key: str, raw: str) -> None:
        self.namespace = namespace
        self.path = path
        self.key = key
        self.raw = raw

    @classmethod
    def parse(cls, raw: str) -> "CredentialRef":
        """Parse ``secret://<namespace>/<path...>#<key>``.

        Raises :class:`ReferenceInvalid` for anything else. The error names what was wrong
        and **never echoes a resolved value**, because a reference is often pasted from a
        place where the secret is nearby.
        """
        if not isinstance(raw, str) or not raw.strip():
            raise ReferenceInvalid("credential reference is empty")

        parts = urlsplit(raw.strip())
        if parts.scheme != SCHEME:
            raise ReferenceInvalid(
                f"credential reference must start with {SCHEME}://, got {parts.scheme or '(none)'!r}. "
                "The scheme is backend-neutral by design (ADR-0018) — do not name the store here."
            )
        if parts.query:
            raise ReferenceInvalid("credential reference must not carry a query string")

        namespace = parts.netloc
        if not _SEGMENT.match(namespace):
            raise ReferenceInvalid(f"credential reference has an invalid namespace {namespace!r}")

        segments = tuple(s for s in parts.path.split("/") if s)
        if not segments:
            raise ReferenceInvalid("credential reference names no path within the namespace")
        for seg in segments:
            if not _SEGMENT.match(seg):
                # Covers `..` and `.` without a special case: neither matches a pattern that
                # requires an alphanumeric first character.
                raise ReferenceInvalid(f"credential reference has an invalid path segment {seg!r}")

        key = parts.fragment
        if not key:
            raise ReferenceInvalid("credential reference names no key (expected a #fragment)")
        if not _SEGMENT.match(key):
            raise ReferenceInvalid(f"credential reference has an invalid key {key!r}")

        return cls(namespace=namespace, path=segments, key=key, raw=raw.strip())

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.raw

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"CredentialRef({self.raw!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CredentialRef) and other.raw == self.raw

    def __hash__(self) -> int:
        return hash(self.raw)


@runtime_checkable
class CredentialResolver(Protocol):
    """Reference in, material out. One method, because that is the whole contract.

    Implementations MUST distinguish :class:`ReferenceInvalid` from :class:`StoreUnavailable`
    (ADR-0018 §7); returning a generic error is the collapse that section exists to prevent.
    """

    async def resolve(self, ref: CredentialRef) -> str: ...  # pragma: no cover - protocol

    @property
    def backend(self) -> str: ...  # pragma: no cover - protocol


class MountedFilesResolver:
    """Resolve against a directory tree of secret files.

    This single backend covers two of ADR-0018 §2's three rows, because they are the same
    thing at the filesystem: a **Kubernetes Secret or CSI volume mounted into the pod** is a
    directory whose files are the keys, and a **local file tree** is what Lite and embedded
    mode already effectively have. Only the provisioning differs, and provisioning is not this
    module's business.

        <root>/<namespace>/<path...>/<key>

    The networked backends (Vault, a cloud secret manager) are a separate implementation and
    arrive with the circuit breaker of §7, which they are the reason for.

    **Mode is checked, and the check is not merely advisory.** A credential file readable by
    group or world on a shared host is a credential the host's other users hold. Kubernetes
    mounts are 0644 inside a pod-private volume, which is why the check is opt-out via
    ``require_private`` rather than unconditional — but it defaults to on, so the insecure
    posture is never what you get by omission.
    """

    def __init__(self, root: str | os.PathLike[str], *, require_private: bool = True) -> None:
        self._root = Path(root)
        self._require_private = require_private

    @property
    def backend(self) -> str:
        return f"files:{self._root}"

    def _path_for(self, ref: CredentialRef) -> Path:
        candidate = self._root.joinpath(ref.namespace, *ref.path, ref.key)
        # Belt and braces. `CredentialRef.parse` already makes traversal unrepresentable, so
        # this cannot trigger today — but a future reference format that admits a new segment
        # shape would be caught here rather than reading outside the mount. The cost is one
        # comparison; the failure it guards against is arbitrary file read.
        try:
            resolved = candidate.resolve()
            root = self._root.resolve()
        except OSError as exc:  # pragma: no cover - depends on a broken mount
            raise StoreUnavailable(f"secret store at {self._root} is not readable: {type(exc).__name__}") from exc
        if not resolved.is_relative_to(root):
            raise ReferenceInvalid(f"credential reference {ref.raw!r} escapes the secret store root")
        return resolved

    async def resolve(self, ref: CredentialRef) -> str:
        """Read the material for ``ref``.

        The ordering below is the decision, not an implementation detail: **the store is
        checked before the individual secret.** A missing root means the mount failed and
        every device is affected (``StoreUnavailable``); a missing file under a healthy root
        means this one reference is wrong (``ReferenceInvalid``). Checking the file first
        would report a failed mount as N independent bad references, which is exactly the
        misdiagnosis ADR-0018 §7 is written against.
        """
        if not self._root.is_dir():
            raise StoreUnavailable(
                f"secret store root {self._root} is not present — the volume is unmounted or the "
                "path is misconfigured. This affects every device, not this one."
            )

        path = self._path_for(ref)
        try:
            st = path.stat()
        except FileNotFoundError as exc:
            raise ReferenceInvalid(f"no secret at {ref.raw!r}") from exc
        except PermissionError as exc:
            # Denied on a present root is an access-policy problem with this path, not an
            # outage: the store is up and answering, and it is answering "no".
            raise ReferenceInvalid(f"permission denied reading {ref.raw!r}") from exc
        except OSError as exc:
            raise StoreUnavailable(f"secret store I/O error: {type(exc).__name__}") from exc

        if self._require_private and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ReferenceInvalid(
                f"secret for {ref.raw!r} is group/world accessible (mode {stat.filemode(st.st_mode)}); "
                "refusing to read it. chmod 600 the file, or set require_private=false for a "
                "pod-private mount where the mode is set by the platform."
            )

        try:
            material = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise StoreUnavailable(f"secret store read failed: {type(exc).__name__}") from exc

        # A trailing newline is what `echo secret > file` produces, and a credential with one
        # appended fails upstream authentication in a way that looks like a wrong password.
        material = material.rstrip("\r\n")
        if not material:
            raise ReferenceInvalid(f"secret at {ref.raw!r} is empty")
        return material


def build_resolver(cfg: dict) -> Optional[CredentialResolver]:
    """Build the configured resolver, or ``None`` when credential-by-reference is off.

    Returning ``None`` rather than a no-op resolver is deliberate: during the ADR-0018
    migration a stack may still hold encrypted credentials inline, and a resolver that
    silently resolved nothing would make "not configured" indistinguishable from "configured
    and empty" — the shape of defect ``entitled_tenants`` and the ``last_check`` fix both came
    from.
    """
    creds = (cfg.get("gateway", {}) or {}).get("credentials", {}) or {}
    root = creds.get("root") or os.getenv("MCP_CREDENTIAL_ROOT")
    if not root:
        return None
    require_private = bool(creds.get("require_private", True))
    return MountedFilesResolver(root, require_private=require_private)
