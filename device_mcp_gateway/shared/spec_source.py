# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Where a device's spec comes from — decided once (ADR-0020 §4b, LR-46).

§4b originally said a device claimed from a catalog is built by "an internal construction
path". Counted in the code there are **five** spec-acquisition sites, and registration is
only the first:

    registry/server.py::_provision_device      embedded, at registration
    registry/server.py::_health_check_one      embedded, every health cycle
    registry/pod_supervisor.py::spawn          embedded, on spawn and on replace
    worker/runner.py::_fetch_spec              distributed, cold path
    worker/health.py::_fetch_spec              distributed, health loop

The last four run **on a timer, forever**. A curated device unrecognised by any one of them
has its snapshot replaced by whatever the live endpoint serves on the next cycle — the pinned
version silently becoming a live-fetched one, which is the drift §4a exists to prevent — and
because `fetch_spec` returns "did it change", the pod is then replaced on the strength of it.

So the *decision* lives here, in one function, and every site asks rather than each
remembering. What deliberately does **not** consolidate is the live fetch: the worker's two
implementations differ on purpose (concurrent probing on the cold path, serial polling in the
health loop, for the reasons `worker/runner.py` gives), and collapsing those would be a
different and unwanted change. One choke point for *whether* to fetch; five implementations of
*how*, unchanged.

This module lives in `shared/` beside `keys.py` and `session_owners.py` because the callers
span `registry/` (embedded) and `worker/` (distributed) and both already import from here.
Copying it into each would collapse five sites into two and leave the identical failure at
smaller scale — the trade this record's own history argues against (`worker/runner.py`:
*"Because there are two of them, an upstream kind added to one and not the other fails only on
the path that was missed."*).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional

from loguru import logger


class CuratedSpecInvalid(Exception):
    """The stored snapshot is not a document this gateway can parse.

    Its own condition rather than a generic failure because the remedy differs: a live fetch
    that fails is usually transient and worth retrying, while a snapshot that does not parse
    is inert — it will fail identically on every cycle until the version is re-curated.
    """


@dataclass(frozen=True)
class CuratedSpec:
    """A provider-curated document carried on the device record (ADR-0020 §4a).

    Holds the **text**, not a parsed object, because §4b's hash is computed over the bytes
    that were curated. Parsing and re-serialising would change them.
    """

    document: str

    def parsed(self) -> dict[str, Any]:
        try:
            value = json.loads(self.document)
        except ValueError as exc:
            raise CuratedSpecInvalid(f"curated spec is not valid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise CuratedSpecInvalid(f"curated spec must be a JSON object, got {type(value).__name__}")
        return value

    def content_sha256(self) -> str:
        """Full digest of the stored bytes — the catalog's `curated_document_sha256` recomputed.

        ADR-0020 §4b: the hash a catalog version carries is what curation *asserted*, and the
        gateway derives its own rather than copying it. Free here, since the bytes are already
        in hand and nothing is fetched.
        """
        return hashlib.sha256(self.document.encode("utf-8")).hexdigest()


def resolve_spec_source(cfg: Any) -> Optional[CuratedSpec]:
    """The one decision: a curated snapshot, or ``None`` meaning "fetch it live, as before".

    Takes the stored ``DeviceConfig`` rather than a runtime profile so both the embedded and
    the distributed callers can ask the same question — the profile exists only in embedded
    mode. Duck-typed for the same reason `shared/` does not import from `registry/`.
    """
    document = getattr(cfg, "curated_spec", None)
    if not document:
        return None
    return CuratedSpec(document)


def spec_hash(parsed: Any) -> str:
    """The gateway's own spec hash, computed the way `SpecService.fetch_spec` computes it.

    Deliberately the same function rather than a better one. `spec_hash` is compared against
    the value a previous cycle stored, so a curated device and a live-fetched device must
    produce hashes on the same scale — changing the algorithm here would make every existing
    device look changed exactly once, replacing every pod in the fleet.
    """
    return hashlib.sha256(str(parsed).encode()).hexdigest()[:16]


def apply_curated_spec(profile: Any, curated: CuratedSpec) -> bool:
    """Put the snapshot on an embedded profile. Returns "did the tool set change".

    Mirrors what `SpecService.fetch_spec` records — ``spec_data``, ``spec_hash`` — minus
    everything that only makes sense for a fetch. ``last_check`` is deliberately **not**
    touched: it means "when did we last contact this device", and a snapshot contacts
    nothing. Writing it here would report a reachability measurement that never happened,
    which is the defect F-66 fixed for `reachable`.

    Persistence is the caller's, because only the caller holds the backend.
    """
    parsed = curated.parsed()
    new_hash = spec_hash(parsed)
    old_hash = profile.config.spec_hash
    profile.spec_data = parsed
    profile.config.spec_hash = new_hash
    changed = old_hash is not None and new_hash != old_hash
    if changed:
        logger.info(f"Curated spec changed for {profile.hostname}: {old_hash} → {new_hash}")
    return changed
