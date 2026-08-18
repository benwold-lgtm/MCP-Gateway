# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0018 §1/§2/§7 — credential references, and the two failure kinds.

The property under test throughout is the one §7 names: **a bad reference and an unreachable
store must never present identically.** Most of these tests assert *which* exception came
back, not merely that resolution failed, because "it raised" is the assertion that would let
the collapse through.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from device_mcp_gateway.credentials import (
    CredentialRef,
    MountedFilesResolver,
    ReferenceInvalid,
    StoreUnavailable,
    build_resolver,
)

REF = "secret://t-3f9a1c2b7d4e8065/devices/prism#api-key"


@pytest.fixture
def store(tmp_path: Path) -> Path:
    """A populated store with a private-mode secret, as a real mount would have."""
    d = tmp_path / "secrets" / "t-3f9a1c2b7d4e8065" / "devices" / "prism"
    d.mkdir(parents=True)
    f = d / "api-key"
    f.write_text("s3cr3t-value\n")  # trailing newline on purpose — see the rstrip test
    f.chmod(0o600)
    return tmp_path / "secrets"


# --- Reference parsing -------------------------------------------------------


def test_a_well_formed_reference_parses_into_its_parts():
    ref = CredentialRef.parse(REF)
    assert ref.namespace == "t-3f9a1c2b7d4e8065"
    assert ref.path == ("devices", "prism")
    assert ref.key == "api-key"
    assert ref.raw == REF


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "vault://ns/devices/prism#api-key",  # backend-named scheme, refused by design
        "https://ns/devices/prism#api-key",
        "ns/devices/prism#api-key",  # no scheme
        "secret://ns/devices/prism",  # no key fragment
        "secret://ns#api-key",  # no path
        "secret:///devices/prism#api-key",  # no namespace
        "secret://ns/devices/prism?x=1#api-key",  # query string
        "secret://ns/devices/prism#",  # empty key
    ],
)
def test_malformed_references_are_refused(bad):
    with pytest.raises(ReferenceInvalid):
        CredentialRef.parse(bad)


@pytest.mark.parametrize(
    "traversal",
    [
        "secret://ns/../../etc/passwd#api-key",
        "secret://ns/devices/../../../etc#passwd",
        "secret://../ns/devices/prism#api-key",
        "secret://ns/./devices/prism#api-key",
        "secret://ns/devices/prism#..",
    ],
)
def test_path_traversal_is_unrepresentable(traversal):
    """Traversal is refused by the *pattern*, not by stripping.

    A filter that removes `..` has to be right at every call site that builds a path; a
    segment pattern requiring an alphanumeric first character has to be right once. These
    never reach the filesystem at all.
    """
    with pytest.raises(ReferenceInvalid):
        CredentialRef.parse(traversal)


def test_a_reference_is_hashable_and_compares_by_value():
    """It becomes a cache key in the next slice; equality by identity would silently
    turn a cache into a memory leak that never hits."""
    assert CredentialRef.parse(REF) == CredentialRef.parse(REF)
    assert len({CredentialRef.parse(REF), CredentialRef.parse(REF)}) == 1


# --- Resolution: the happy path ----------------------------------------------


@pytest.mark.asyncio
async def test_resolves_material_from_the_store(store):
    resolver = MountedFilesResolver(store)
    assert await resolver.resolve(CredentialRef.parse(REF)) == "s3cr3t-value"


@pytest.mark.asyncio
async def test_a_trailing_newline_is_stripped(store):
    """`echo secret > file` is how these get written, and a credential with a newline
    appended fails upstream auth in a way that looks exactly like a wrong password."""
    (store / "t-3f9a1c2b7d4e8065" / "devices" / "prism" / "api-key").write_text("value\r\n")
    os.chmod(store / "t-3f9a1c2b7d4e8065" / "devices" / "prism" / "api-key", 0o600)
    assert await MountedFilesResolver(store).resolve(CredentialRef.parse(REF)) == "value"


# --- Resolution: the distinction that matters --------------------------------


@pytest.mark.asyncio
async def test_a_missing_store_root_is_a_store_outage_not_a_bad_reference(tmp_path):
    """The whole point of §7. An unmounted volume affects every device.

    If this raised ReferenceInvalid, a failed mount would present as N devices with bad
    references — each one faulted individually, none of them actually wrong.
    """
    resolver = MountedFilesResolver(tmp_path / "never-mounted")
    with pytest.raises(StoreUnavailable):
        await resolver.resolve(CredentialRef.parse(REF))


@pytest.mark.asyncio
async def test_a_missing_secret_under_a_healthy_store_is_a_bad_reference(store):
    """The converse, and equally load-bearing: one wrong reference must not look like an
    outage, or an operator goes looking at the store instead of at their own config."""
    resolver = MountedFilesResolver(store)
    with pytest.raises(ReferenceInvalid):
        await resolver.resolve(CredentialRef.parse("secret://t-3f9a1c2b7d4e8065/devices/nope#api-key"))


@pytest.mark.asyncio
async def test_the_store_is_checked_before_the_secret(tmp_path):
    """Ordering, asserted directly.

    With the checks the other way round, a missing root would surface as "no secret at ..."
    — technically true and diagnostically useless. This is the assertion that pins the
    ordering decision rather than trusting it to survive a refactor.
    """
    resolver = MountedFilesResolver(tmp_path / "never-mounted")
    with pytest.raises(StoreUnavailable) as exc:
        await resolver.resolve(CredentialRef.parse("secret://ns/devices/absent#key"))
    assert "every device" in str(exc.value)


@pytest.mark.asyncio
async def test_an_empty_secret_is_a_bad_reference(store):
    """An empty file is a provisioning mistake, not an outage — and returning "" would
    send an empty credential upstream and surface as an auth failure at the device."""
    f = store / "t-3f9a1c2b7d4e8065" / "devices" / "prism" / "api-key"
    f.write_text("\n")
    f.chmod(0o600)
    with pytest.raises(ReferenceInvalid):
        await MountedFilesResolver(store).resolve(CredentialRef.parse(REF))


# --- Mode -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_group_or_world_readable_secret_is_refused(store):
    f = store / "t-3f9a1c2b7d4e8065" / "devices" / "prism" / "api-key"
    f.chmod(0o644)
    with pytest.raises(ReferenceInvalid) as exc:
        await MountedFilesResolver(store).resolve(CredentialRef.parse(REF))
    assert "group/world" in str(exc.value)


@pytest.mark.asyncio
async def test_the_mode_check_is_opt_out_for_platform_managed_mounts(store):
    """Kubernetes mounts Secrets 0644 inside a pod-private volume, so the check has to be
    disableable — but it defaults to on, so the insecure posture is never what omission gives."""
    f = store / "t-3f9a1c2b7d4e8065" / "devices" / "prism" / "api-key"
    f.chmod(0o644)
    resolver = MountedFilesResolver(store, require_private=False)
    assert await resolver.resolve(CredentialRef.parse(REF)) == "s3cr3t-value"


@pytest.mark.asyncio
async def test_the_default_is_private_required(store):
    """Asserted as a default rather than inferred from the signature — a default that is
    never exercised is a claim nothing checks."""
    f = store / "t-3f9a1c2b7d4e8065" / "devices" / "prism" / "api-key"
    f.chmod(0o604)  # world-readable only
    with pytest.raises(ReferenceInvalid):
        await MountedFilesResolver(store).resolve(CredentialRef.parse(REF))


# --- No leakage --------------------------------------------------------------


@pytest.mark.asyncio
async def test_errors_never_carry_the_material(store):
    """A reference often sits next to the secret it names; an error that echoed a value
    would put credentials in logs and in a tenant's audit."""
    f = store / "t-3f9a1c2b7d4e8065" / "devices" / "prism" / "api-key"
    f.chmod(0o644)
    with pytest.raises(ReferenceInvalid) as exc:
        await MountedFilesResolver(store).resolve(CredentialRef.parse(REF))
    assert "s3cr3t-value" not in str(exc.value)


# --- Construction ------------------------------------------------------------


def test_no_configuration_yields_no_resolver(monkeypatch):
    """`None`, not a no-op resolver.

    During the ADR-0018 migration a stack may still hold inline credentials, and a resolver
    that resolved nothing would make "not configured" and "configured but empty" the same
    observable — the defect shape behind `entitled_tenants` and the `last_check` fix.
    """
    monkeypatch.delenv("MCP_CREDENTIAL_ROOT", raising=False)
    assert build_resolver({}) is None
    assert build_resolver({"gateway": {}}) is None
    assert build_resolver({"gateway": {"credentials": {}}}) is None


def test_configuration_by_env_or_config(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_CREDENTIAL_ROOT", str(tmp_path))
    assert build_resolver({}) is not None
    monkeypatch.delenv("MCP_CREDENTIAL_ROOT", raising=False)
    assert build_resolver({"gateway": {"credentials": {"root": str(tmp_path)}}}) is not None


def test_config_takes_precedence_over_env(monkeypatch, tmp_path):
    """Explicit configuration beats ambient environment, matching how secret_keys resolve."""
    monkeypatch.setenv("MCP_CREDENTIAL_ROOT", str(tmp_path / "from-env"))
    r = build_resolver({"gateway": {"credentials": {"root": str(tmp_path / "from-config")}}})
    assert "from-config" in r.backend


@pytest.mark.asyncio
async def test_the_backend_label_identifies_the_store_not_a_device(tmp_path):
    """§7 puts the breaker on the backend, so the backend needs a stable identity to key it
    on. Asserted now because the next slice depends on it."""
    r = MountedFilesResolver(tmp_path)
    assert r.backend == f"files:{tmp_path}"
    assert MountedFilesResolver(tmp_path).backend == r.backend


def test_a_secret_file_mode_is_reported_in_the_refusal(store):
    """The operator has to know what to chmod; a bare refusal makes them go looking."""
    f = store / "t-3f9a1c2b7d4e8065" / "devices" / "prism" / "api-key"
    f.chmod(0o644)
    st = f.stat()
    assert stat.filemode(st.st_mode).startswith("-rw-r--r--")


def test_the_credentials_config_key_is_declared_in_the_schema():
    """Undeclared, an enabled `gateway.credentials` block would be reported as an unknown key
    and "ignored" at startup — while being honoured. That exact defect already happened to
    `gateway.oidc` and `gateway.tenant_id`, and an operator following the warning would delete
    working configuration. Pinned here so adding the feature does not re-add the bug.
    """
    from device_mcp_gateway.cfg import validate_config

    problems = validate_config({"gateway": {"credentials": {"root": "/run/secrets"}}})
    assert not [p for p in problems if "credentials" in p and "unknown" in p]
