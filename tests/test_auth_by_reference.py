# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0018 — an API key held by reference rather than inline.

The migration rule is **exclusive per device**: a record holds its secret inline *or* by
reference, never both. These pin the three properties that make that safe — the exclusivity
itself, that an unbound handler refuses to dispatch rather than sending a placeholder, and
that serialising a bound handler writes the reference back rather than the material.

That last one is the quiet one. Everything else fails loudly when it regresses; writing a
resolved secret back into the registry succeeds, and undoes ADR-0018 for that device with no
symptom at all.
"""

from __future__ import annotations

import pytest

from device_mcp_gateway.auth.api_key import ApiKeyAuth
from device_mcp_gateway.auth.base import CredentialNotBound
from device_mcp_gateway.credentials import CredentialRef, ReferenceInvalid, StoreUnavailable

REF = "secret://t-3f9a1c2b7d4e8065/devices/prism#api-key"


class _Resolver:
    """Minimal stand-in. Deliberately not the real MountedFilesResolver: these tests are
    about the *handler's* behaviour, and a filesystem here would make a failure ambiguous
    between the two. The real resolver has its own file."""

    def __init__(self, value="resolved-key", raises=None):
        self._value = value
        self._raises = raises
        self.calls: list[str] = []

    @property
    def backend(self) -> str:
        return "test"

    async def resolve(self, ref: CredentialRef) -> str:
        self.calls.append(ref.raw)
        if self._raises is not None:
            raise self._raises
        return self._value


# --- Exclusivity -------------------------------------------------------------


def test_inline_and_reference_together_are_refused():
    """Both is refused rather than resolved by precedence.

    Any precedence rule makes the losing value invisible, so a reference that never took
    effect would look exactly like one that did — and the operator would believe the device
    had been migrated.
    """
    with pytest.raises(ValueError, match="mutually exclusive") as exc:
        ApiKeyAuth(api_key="inline", credential_ref=REF)
    # The message must name the field the API actually accepts. The first version derived it
    # as `api_key_ref`, which does not exist — an operator would go looking for it.
    assert "credential_ref" in str(exc.value)
    assert "api_key_ref" not in str(exc.value)


def test_neither_inline_nor_reference_is_refused():
    """A device that cannot authenticate should fail at registration, not at 3am."""
    with pytest.raises(ValueError, match="required"):
        ApiKeyAuth()


def test_a_malformed_reference_is_refused_at_construction():
    """Parsed when the device is registered, not when it is first called.

    A reference validated only at dispatch means a device that looked fine when added starts
    failing the first time someone uses it, which is the worst possible moment to learn it.
    """
    with pytest.raises(ReferenceInvalid):
        ApiKeyAuth(credential_ref="vault://ns/x#k")


# --- Binding -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_binding_resolves_the_reference():
    auth = ApiKeyAuth(credential_ref=REF)
    await auth.bind(_Resolver("s3cr3t"))
    assert (await auth.get_headers()) == {"X-API-Key": "s3cr3t"}


@pytest.mark.asyncio
async def test_an_unbound_handler_refuses_rather_than_sending_a_placeholder():
    """The failure mode this prevents is diagnostic, not just cosmetic.

    Sending `Bearer None` upstream returns 401, which reads as a wrong credential and sends
    the operator to check their secret store — when the gateway simply skipped a step.
    """
    auth = ApiKeyAuth(credential_ref=REF)
    with pytest.raises(CredentialNotBound):
        await auth.get_headers()


@pytest.mark.asyncio
async def test_binding_an_inline_handler_is_a_no_op():
    """Inline devices are untouched by ADR-0018, so the dispatch path can call bind()
    unconditionally rather than branching — a branch every caller must remember is the
    shape of defect this session has already found twice."""
    resolver = _Resolver()
    auth = ApiKeyAuth(api_key="inline")
    await auth.bind(resolver)
    assert resolver.calls == []
    assert (await auth.get_headers()) == {"X-API-Key": "inline"}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [ReferenceInvalid("bad ref"), StoreUnavailable("sealed")])
async def test_resolution_failures_propagate_unchanged(failure):
    """§7's distinction has to survive the handler.

    Wrapping both in one auth error here would collapse them one layer up from where the
    resolver carefully separated them, and the dispatch path could no longer tell a device's
    misconfiguration from a fleet-wide outage.
    """
    auth = ApiKeyAuth(credential_ref=REF)
    with pytest.raises(type(failure)):
        await auth.bind(_Resolver(raises=failure))


# --- Serialisation -----------------------------------------------------------


def test_a_reference_round_trips():
    auth = ApiKeyAuth(credential_ref=REF, location="query", name="key")
    restored = ApiKeyAuth.from_dict(auth.to_dict())
    assert restored.credential_ref == REF
    assert restored.api_key is None
    assert restored.location == "query"
    assert restored.name == "key"


@pytest.mark.asyncio
async def test_serialising_a_bound_handler_writes_the_reference_not_the_secret():
    """The quiet regression, and the reason this file exists.

    A bound handler holds live material. If `to_dict` emitted it, the next registry write —
    a metadata update, a health-driven field change — would persist the secret back into the
    record and undo ADR-0018 for that device. Nothing would fail; the device keeps working.
    """
    auth = ApiKeyAuth(credential_ref=REF)
    await auth.bind(_Resolver("s3cr3t"))

    data = auth.to_dict()
    assert data["credential_ref"] == REF
    assert "api_key" not in data
    assert "s3cr3t" not in str(data)


def test_an_inline_handler_still_serialises_as_before():
    """Existing records must round-trip unchanged — the migration is per device, so both
    shapes coexist in one registry for as long as it takes."""
    data = ApiKeyAuth(api_key="inline", header_name="X-Key").to_dict()
    assert data["api_key"] == "inline"
    assert "credential_ref" not in data
    assert ApiKeyAuth.from_dict(data).api_key == "inline"


def test_legacy_records_without_the_new_field_still_load():
    """A record written before this change has no `credential_ref` key at all."""
    auth = ApiKeyAuth.from_dict({"type": "api_key", "api_key": "old", "header_name": "X-API-Key"})
    assert auth.api_key == "old"
    assert auth.credential_ref is None


@pytest.mark.asyncio
async def test_the_placement_options_all_work_by_reference():
    """`apply()` is a separate path from `get_headers()`, and a query- or cookie-located key
    reaches `_value` through it — so the unbound guard has to hold there too."""
    for location, field in (("query", "params"), ("cookie", "cookies"), ("header", "headers")):
        auth = ApiKeyAuth(credential_ref=REF, location=location, name="k")
        with pytest.raises(CredentialNotBound):
            await auth.apply()
        await auth.bind(_Resolver("v"))
        assert getattr(await auth.apply(), field) == {"k": "v"}


@pytest.mark.asyncio
async def test_a_non_ascii_credential_in_a_header_is_named_not_opaque():
    """Found on a live cluster with a secret that had two Cyrillic characters in it.

    httpx raises ``'ascii' codec can't encode characters in position 14-15``, which names
    neither the device nor the credential — and because it happened during MCP discovery, the
    device recorded only "No spec available", pointing an operator at the upstream. The
    refusal must say it is the credential and that headers are latin-1.
    """
    auth = ApiKeyAuth(credential_ref=REF)
    await auth.bind(_Resolver("key-\u043e\u0442-store"))
    with pytest.raises(CredentialNotBound) as exc:
        await auth.apply()
    assert "HTTP header" in str(exc.value)
    assert "latin-1" in str(exc.value)


@pytest.mark.asyncio
async def test_a_non_ascii_credential_is_fine_outside_a_header():
    """Only headers are constrained; the transport encodes a query or cookie value, so
    refusing those too would reject credentials that work."""
    auth = ApiKeyAuth(credential_ref=REF, location="query", name="k")
    await auth.bind(_Resolver("key-\u043e\u0442-store"))
    assert (await auth.apply()).params == {"k": "key-\u043e\u0442-store"}
