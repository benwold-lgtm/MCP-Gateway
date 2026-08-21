# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0018 §7c — the backend discriminator is declared, not inferred.

Three behaviours branch on which class of store is in use: the resolution cache, the circuit
breaker, and the metrics. §7c requires that they read one **declared** property rather than
each recovering it from the ``backend`` display string.

The load-bearing test here is `test_nothing_infers_the_backend_class_from_a_string`. The others
pin the declared values; that one pins the *rule*, and it is the one that will fail if a future
change quietly reintroduces the thing this section exists to prevent.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from device_mcp_gateway.credentials import (
    CredentialResolver,
    MountedFilesResolver,
    ResolverKind,
)

_SRC = pathlib.Path(__file__).resolve().parent.parent / "device_mcp_gateway"


def test_mounted_files_declares_its_kind():
    assert MountedFilesResolver("/run/secrets/mcp").kind is ResolverKind.MOUNTED_FILES


def test_mounted_files_does_not_fail_transiently_at_dispatch():
    """§7a measured this: the volume is mounted before the pod is ready, or it never is."""
    assert ResolverKind.MOUNTED_FILES.fails_transiently_at_dispatch is False


def test_networked_does_fail_transiently_at_dispatch():
    """The breaker exists for this case, and only for it."""
    assert ResolverKind.NETWORKED.fails_transiently_at_dispatch is True


def test_mounted_files_is_read_through():
    """0 is a decision, not an omission — a cache would hold plaintext for no benefit (§7c)."""
    assert ResolverKind.MOUNTED_FILES.default_cache_ttl_seconds == 0


def test_networked_ttl_is_the_value_the_adr_settled():
    assert ResolverKind.NETWORKED.default_cache_ttl_seconds == 300


def test_the_two_properties_agree_on_every_kind():
    """A kind that caches but cannot fail transiently, or vice versa, is a contradiction.

    Both properties describe the same underlying fact — whether a store is reached over the
    network at dispatch time. Deriving them from one `is NETWORKED` check today makes that
    true by construction; this pins it so a future kind cannot set them independently and
    leave the cache and the breaker disagreeing about the same backend.
    """
    for kind in ResolverKind:
        assert kind.fails_transiently_at_dispatch == (kind.default_cache_ttl_seconds > 0)


def test_the_protocol_requires_a_kind():
    """A resolver that satisfies the old contract must no longer satisfy the new one."""

    class OldStyleResolver:
        async def resolve(self, ref):  # pragma: no cover - never called
            return "x"

        @property
        def backend(self) -> str:
            return "files:/run/secrets/mcp"

    assert not isinstance(OldStyleResolver(), CredentialResolver)
    assert isinstance(MountedFilesResolver("/run/secrets/mcp"), CredentialResolver)


def _is_backend_expr(node: ast.AST) -> bool:
    """True for `something.backend` or a bare `backend` name."""
    if isinstance(node, ast.Attribute) and node.attr == "backend":
        return True
    return isinstance(node, ast.Name) and node.id == "backend"


def test_nothing_infers_the_backend_class_from_a_string():
    """No module may recover the backend class by parsing `backend`.

    §7c names this exactly: conditioning on ``backend.startswith(...)`` puts a policy decision
    behind a string prefix — correct today, and silently wrong the first time a backend arrives
    whose display name does not fit the assumed pattern. `resolver.py` is allowed to *build*
    that string; nobody is allowed to take it apart.

    Parsed with `ast` rather than matched with a regex, so prose that *describes* the forbidden
    pattern — including this module's own docstrings — is not mistaken for code that does it.
    """
    string_ops = {"startswith", "endswith", "split", "partition", "rpartition", "removeprefix"}
    offenders = []

    for path in _SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            hit = None
            # backend.startswith(...) / .split(...) / ...
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in string_ops and _is_backend_expr(node.func.value):
                    hit = f"{node.func.attr}() on `backend`"
                # backend.lower().startswith(...)
                elif node.func.attr in string_ops and isinstance(node.func.value, ast.Call):
                    inner = node.func.value.func
                    if isinstance(inner, ast.Attribute) and _is_backend_expr(inner.value):
                        hit = f"{node.func.attr}() on `backend.{inner.attr}()`"
            # backend[:5], backend == "files:..."
            elif isinstance(node, ast.Subscript) and _is_backend_expr(node.value):
                hit = "slicing `backend`"
            elif isinstance(node, ast.Compare) and _is_backend_expr(node.left):
                if any(isinstance(c, ast.Constant) and isinstance(c.value, str) for c in node.comparators):
                    hit = "comparing `backend` to a string literal"

            if hit:
                offenders.append(f"{path.relative_to(_SRC.parent)}:{node.lineno}: {hit}")

    assert not offenders, (
        "Backend class inferred from the `backend` display string. Read `resolver.kind` "
        "instead — ADR-0018 §7c.\n" + "\n".join(offenders)
    )


@pytest.mark.parametrize("kind", list(ResolverKind))
def test_kind_is_stable_on_the_wire(kind):
    """The value is a metric label and may end up in config; it must not drift with the name."""
    assert kind.value in {"mounted_files", "networked"}
    assert str(kind.value) == kind.value
