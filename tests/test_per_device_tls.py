# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Per-device outbound TLS trust — the TG-4 residual (F-31 follow-up).

Before this, ``security.mtls`` was fleet-global: one ``ca_bundle`` per process, so a
single self-signed device forced its trust set onto every other outbound call the
gateway or worker made. These tests cover the overlay resolution, the fail-closed
startup preflight, and — the part that matters — a real two-server handshake proving
trust granted to one device is **not** granted to another.

That last test carries its own positive control: the same call that must fail under
per-device trust is shown to *succeed* under the old fleet-global configuration. Without
it, a broken TLS setup would make the test pass for the wrong reason.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from device_mcp_gateway import cfg as cfg_mod
from device_mcp_gateway.security import mtls
from device_mcp_gateway.security.mtls import TlsProfiles


@pytest.fixture(autouse=True)
def _clear_context_cache():
    mtls.reset_cache()
    yield
    mtls.reset_cache()


# ---------------------------------------------------------------------------
# Resolution — a device block layered over the fleet block
# ---------------------------------------------------------------------------

FLEET = {"ca_bundle": "/fleet/ca.pem", "client_cert": "/fleet/c.crt", "client_key": "/fleet/c.key"}


def test_device_without_a_block_resolves_to_the_fleet_profile():
    cfg = {**FLEET, "devices": {"other": {"verify": False}}}
    assert mtls._resolve(cfg, "unlisted") == mtls._resolve(cfg, None)


def test_device_block_overrides_only_the_keys_it_names():
    cfg = {**FLEET, "devices": {"switch-a": {"ca_bundle": "/vendor-a/ca.pem"}}}
    resolved = mtls._resolve(cfg, "switch-a")
    assert resolved["ca_bundle"] == "/vendor-a/ca.pem"  # overridden
    assert resolved["client_cert"] == "/fleet/c.crt"  # inherited
    assert resolved["verify"] is True


def test_one_device_opting_out_of_verification_leaves_the_others_verifying():
    # The whole point of the feature: `verify: false` for a UniFi console must not
    # silently disable certificate checking for every other device in the fleet.
    cfg = {"devices": {"unifi": {"verify": False}}}
    assert mtls._resolve(cfg, "unifi")["verify"] is False
    assert mtls._resolve(cfg, "switch-a")["verify"] is True
    assert mtls._resolve(cfg, None)["verify"] is True

    assert mtls.build_verify(cfg, "unifi").verify_mode == ssl.CERT_NONE
    assert mtls.build_verify(cfg, "switch-a") is True  # untouched httpx default


def test_a_named_device_beats_the_fleet_env_switch(monkeypatch):
    # MCP_MTLS_VERIFY is a fleet-level control; naming a device is more specific, so a
    # device that says verify:true keeps verifying even when the fleet switch is off.
    monkeypatch.setenv(mtls.ENV_VERIFY, "false")
    cfg = {"devices": {"prod-switch": {"verify": True}}}
    assert mtls._resolve(cfg, "prod-switch")["verify"] is True
    assert mtls._resolve(cfg, "lab-box")["verify"] is False  # no block → env applies


def test_env_password_unlocks_the_fleet_key_but_is_not_lent_to_a_device_key(monkeypatch):
    monkeypatch.setenv(mtls.ENV_KEY_PASSWORD, "fleet-pw")
    cfg = {
        **FLEET,
        "client_key_password": "config-pw",
        "devices": {
            "inherits": {"ca_bundle": "/vendor/ca.pem"},
            "own-key": {"client_cert": "/vendor/c.crt", "client_key": "/vendor/c.key"},
            "own-key-and-pw": {"client_cert": "/v/c.crt", "client_key": "/v/c.key", "client_key_password": "vendor-pw"},
        },
    }
    # Inherits the fleet cert → the fleet password is the right one to try.
    assert mtls._resolve(cfg, "inherits")["client_key_password"] == "fleet-pw"
    # Brings its own key → neither the env nor the fleet config password belongs to it.
    assert mtls._resolve(cfg, "own-key")["client_key_password"] is None
    # ...unless it names one.
    assert mtls._resolve(cfg, "own-key-and-pw")["client_key_password"] == "vendor-pw"


def test_devices_resolving_to_the_same_profile_share_one_context(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(_ca_pem())
    cfg = {"ca_bundle": str(ca), "devices": {"a": {"ca_bundle": str(ca)}}}
    # "a" spells out what "b" inherits — same resolved inputs, so one context and one
    # file read, which is what keeps the cache bounded by profiles rather than devices.
    assert mtls.build_verify(cfg, "a") is mtls.build_verify(cfg, "b")


def test_describe_reports_the_source_without_leaking_the_path():
    cfg = {"ca_bundle": "/etc/mcp/tls/fleet-ca.pem", "devices": {"a": {"ca_bundle": "/etc/mcp/tls/vendor-a-ca.pem"}}}
    assert mtls.describe(cfg, "a") == {
        "source": "device",
        "verify": True,
        "ca_bundle": "vendor-a-ca.pem",  # basename only
        "client_cert": False,
    }
    assert mtls.describe(cfg, "b")["source"] == "fleet"
    assert "/etc/mcp" not in str(mtls.describe(cfg, "a"))


# ---------------------------------------------------------------------------
# Preflight — fail at startup, not at first contact with the device
# ---------------------------------------------------------------------------


def test_preflight_refuses_an_unknown_key_in_a_device_block():
    # A misspelt `ca_bundle` would leave the device on the fleet trust set while
    # looking configured — a silent security downgrade, so it must not boot.
    cfg = {"devices": {"switch-a": {"ca-bundle": "/vendor/ca.pem"}}}
    with pytest.raises(ValueError) as exc:
        mtls.preflight(cfg)
    assert "ca-bundle" in str(exc.value)
    assert "switch-a" in str(exc.value)


def test_preflight_refuses_an_unreadable_ca_and_names_the_device(tmp_path):
    cfg = {"devices": {"switch-a": {"ca_bundle": str(tmp_path / "missing.pem")}}}
    with pytest.raises(ValueError) as exc:
        mtls.preflight(cfg)
    assert "switch-a" in str(exc.value)


def test_preflight_refuses_a_devices_block_that_is_not_a_mapping():
    with pytest.raises(ValueError):
        mtls.preflight({"devices": ["switch-a"]})


def test_preflight_returns_the_validated_hostnames(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(_ca_pem())
    cfg = {"devices": {"b": {"ca_bundle": str(ca)}, "a": {"verify": False}}}
    assert mtls.preflight(cfg) == ["a", "b"]


def test_preflight_is_a_no_op_without_a_devices_block():
    assert mtls.preflight(None) == []
    assert mtls.preflight({"verify": True}) == []


def test_registry_refuses_to_start_on_a_broken_device_profile(tmp_path):
    # The wiring, not just the helper: a bad per-device profile must stop the process,
    # the same way a bad fleet profile always has.
    from device_mcp_gateway.registry.server import Registry

    config = {"security": {"mtls": {"devices": {"switch-a": {"ca_bundle": str(tmp_path / "nope.pem")}}}}}
    with pytest.raises(ValueError) as exc:
        Registry(config=config)
    assert "switch-a" in str(exc.value)


@pytest.mark.asyncio
async def test_registry_reports_each_devices_resolved_profile(tmp_path):
    # What GET /devices/{h}/diagnostics reads. Resolved live from config rather than
    # stored on the device, so it can't drift from what the process actually presents.
    from device_mcp_gateway.registry.server import Registry

    ca = tmp_path / "vendor-a-ca.pem"
    ca.write_bytes(_ca_pem())
    reg = Registry(config={"security": {"mtls": {"devices": {"switch-a": {"ca_bundle": str(ca)}}}}})
    try:
        assert reg.tls_profile_for("switch-a") == {
            "source": "device",
            "verify": True,
            "ca_bundle": "vendor-a-ca.pem",
            "client_cert": False,
        }
        assert reg.tls_profile_for("ordinary")["source"] == "fleet"
    finally:
        await reg.shutdown()


# ---------------------------------------------------------------------------
# Config schema (F-50) — hostnames are data, not typos
# ---------------------------------------------------------------------------


def test_hostnames_under_the_devices_block_are_not_reported_as_unknown_keys():
    problems = cfg_mod.validate_config(
        {"security": {"mtls": {"devices": {"switch-a.internal": {"ca_bundle": "/x.pem", "verify": False}}}}}
    )
    assert problems == []


def test_a_bad_key_inside_a_device_block_is_still_reported_with_its_full_path():
    problems = cfg_mod.validate_config({"security": {"mtls": {"devices": {"switch-a": {"verify": "yes"}}}}})
    assert any("security.mtls.devices.switch-a.verify" in p for p in problems)


def test_a_device_entry_that_is_not_a_mapping_is_reported():
    problems = cfg_mod.validate_config({"security": {"mtls": {"devices": {"switch-a": "ca.pem"}}}})
    assert any("security.mtls.devices.switch-a" in p for p in problems)


def test_unsafe_settings_names_the_devices_that_skip_verification():
    warnings = cfg_mod.warn_unsafe_settings(
        {"security": {"mtls": {"devices": {"unifi": {"verify": False}, "ok": {"ca_bundle": "/x.pem"}}}}},
        mode="embedded",
        auth_enabled=True,
    )
    tls_warnings = [w for w in warnings if "verification is DISABLED" in w]
    assert len(tls_warnings) == 1
    assert "unifi" in tls_warnings[0]
    assert "ok" not in tls_warnings[0].replace("Prefer a ca_bundle", "")


# ---------------------------------------------------------------------------
# Client pooling — one client per profile, not one per service
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spec_service_pools_a_separate_client_per_profile(tmp_path):
    from device_mcp_gateway.core.backoff import RetryPolicy
    from device_mcp_gateway.registry.spec_service import SpecService
    from device_mcp_gateway.shared.registry_backend import MemoryRegistryBackend

    ca = tmp_path / "ca.pem"
    ca.write_bytes(_ca_pem())
    profiles = TlsProfiles({"devices": {"special": {"ca_bundle": str(ca)}}})
    svc = SpecService(backend=MemoryRegistryBackend(), config={}, tls_profiles=profiles, retry_policy=RetryPolicy())
    try:
        # Different profile → different client. Sharing one would put every device back
        # on a single trust set, which is the limitation this change removes.
        assert svc.client("special") is not svc.client("ordinary")
        # Same profile → the same client, so connections stay warm.
        assert svc.client("ordinary") is svc.client("also-ordinary")
        assert len(svc._http_clients) == 2
    finally:
        await svc.aclose()


@pytest.mark.asyncio
async def test_worker_health_loop_pools_a_separate_client_per_profile(tmp_path):
    from device_mcp_gateway.shared.registry_backend import MemoryRegistryBackend
    from device_mcp_gateway.worker.health import WorkerHealthLoop

    ca = tmp_path / "ca.pem"
    ca.write_bytes(_ca_pem())
    loop = WorkerHealthLoop(
        "w",
        MemoryRegistryBackend(),
        None,
        tls_profiles=TlsProfiles({"devices": {"special": {"ca_bundle": str(ca)}}}),
    )
    try:
        assert loop._client("special") is not loop._client("ordinary")
        assert loop._client("ordinary") is loop._client("also-ordinary")
    finally:
        await loop.close()


# ---------------------------------------------------------------------------
# The real handshake — trust granted to one device is not granted to another
# ---------------------------------------------------------------------------


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _ca_cert(key, name="test-ca"):
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def _ca_pem() -> bytes:
    """A throwaway CA certificate in PEM form — for tests that only need a loadable file."""
    return _ca_cert(_ec_key()).public_bytes(serialization.Encoding.PEM)


def _server_cert(key, ca_key, ca_cert, common_name):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


class _OkHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_a):
        pass


def _serve_tls(cert_path, key_path):
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(cert_path), str(key_path))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.socket.getsockname()[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.25)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.05)
    return httpd, thread, port


@pytest.fixture
def two_devices_one_ca(tmp_path):
    """Two HTTPS servers whose certificates are signed by the SAME private CA.

    That is the shape of the risk this feature addresses. Under fleet-global trust,
    trusting that CA for device A also trusts anything else it has signed — including
    device B, and including a certificate an attacker could obtain from it.
    """
    ca_key = _ec_key()
    ca = _ca_cert(ca_key, "vendor-a-ca")
    ca_path = tmp_path / "vendor-a-ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    servers = {}
    for name in ("a", "b"):
        key = _ec_key()
        cert = _server_cert(key, ca_key, ca, f"device-{name}")
        cert_path = tmp_path / f"{name}.crt"
        key_path = tmp_path / f"{name}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        servers[name] = _serve_tls(cert_path, key_path)

    yield str(ca_path), servers["a"][2], servers["b"][2]

    for httpd, thread, _port in servers.values():
        httpd.shutdown()
        thread.join(timeout=5)


def _get(verify, port):
    with httpx.Client(verify=verify) as client:
        return client.get(f"https://localhost:{port}/", timeout=5)


def test_per_device_trust_does_not_extend_to_another_device(two_devices_one_ca):
    ca_path, port_a, port_b = two_devices_one_ca
    cfg = {"devices": {"device-a": {"ca_bundle": ca_path}}}

    # device-a names the CA, so its own call verifies and succeeds.
    assert _get(mtls.build_verify(cfg, "device-a"), port_a).status_code == 200

    # device-b did not, so it resolves to the fleet profile (public roots) and the
    # handshake fails — the trust granted to device-a was not lent to it.
    with pytest.raises((httpx.TransportError, ssl.SSLError)):
        _get(mtls.build_verify(cfg, "device-b"), port_b)


def test_positive_control_the_old_fleet_wide_config_does_trust_the_other_device(two_devices_one_ca):
    # The control for the test above. Same CA, same servers, same call to device-b —
    # but configured the way it had to be before per-device trust existed. It succeeds,
    # which is exactly the widening that was the TG-4 residual: one device's private CA
    # became a trust anchor for every outbound call the process made.
    ca_path, _port_a, port_b = two_devices_one_ca
    fleet_wide = {"ca_bundle": ca_path}
    assert _get(mtls.build_verify(fleet_wide, "device-b"), port_b).status_code == 200


def test_a_devices_own_ca_is_used_even_when_the_fleet_trusts_nothing_useful(two_devices_one_ca, tmp_path):
    # The inverse arrangement: an unrelated fleet CA, with the real one named only on
    # the device. Proves the overlay replaces the fleet anchor rather than being
    # ignored when the fleet block is already set.
    ca_path, port_a, _port_b = two_devices_one_ca
    unrelated = tmp_path / "unrelated-ca.pem"
    unrelated.write_bytes(_ca_pem())
    cfg = {"ca_bundle": str(unrelated), "devices": {"device-a": {"ca_bundle": ca_path}}}

    assert _get(mtls.build_verify(cfg, "device-a"), port_a).status_code == 200
    with pytest.raises((httpx.TransportError, ssl.SSLError)):
        _get(mtls.build_verify(cfg, "device-b"), port_a)
