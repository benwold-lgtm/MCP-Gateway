# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for outbound mutual-TLS to devices (F-31).

Covers the `security.mtls` → httpx `verify=` resolution (build_verify), the
config/env precedence for the client-key password, and a real end-to-end mutual
handshake against a TLS server that *requires* a client certificate — proving
the context the gateway builds is actually presented and enforced.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import certifi
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from device_mcp_gateway.security import mtls


@pytest.fixture(autouse=True)
def _clear_context_cache():
    mtls.reset_cache()
    yield
    mtls.reset_cache()


# ---------------------------------------------------------------------------
# build_verify — resolution logic
# ---------------------------------------------------------------------------


def test_nothing_configured_returns_true():
    # No block / empty block → httpx default (certifi server verification), so
    # non-mTLS deployments are byte-for-byte unchanged.
    assert mtls.build_verify(None) is True
    assert mtls.build_verify({}) is True
    assert mtls.build_verify({"verify": True}) is True
    assert mtls.is_configured(None) is False
    assert mtls.is_configured({}) is False


def test_verify_false_builds_unverified_context():
    ctx = mtls.build_verify({"verify": False})
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert mtls.is_configured({"verify": False}) is True


def test_ca_bundle_builds_context():
    ctx = mtls.build_verify({"ca_bundle": certifi.where()})
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED  # still verifies the server
    assert mtls.is_configured({"ca_bundle": certifi.where()}) is True


def test_context_is_cached_by_signature():
    a = mtls.build_verify({"ca_bundle": certifi.where()})
    b = mtls.build_verify({"ca_bundle": certifi.where()})
    assert a is b  # same resolved inputs → same built context (no re-read from disk)


def test_key_password_env_overrides_config(monkeypatch):
    monkeypatch.setenv(mtls.ENV_KEY_PASSWORD, "from-env")
    resolved = mtls._resolve({"client_key_password": "from-config"})
    assert resolved["client_key_password"] == "from-env"
    monkeypatch.delenv(mtls.ENV_KEY_PASSWORD, raising=False)
    assert mtls._resolve({"client_key_password": "from-config"})["client_key_password"] == "from-config"


# ---------------------------------------------------------------------------
# Certificate fixtures + a real mutual-TLS handshake
# ---------------------------------------------------------------------------


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ca(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def _leaf(key, common_name, ca_key, ca_cert, sans=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def _write_pem(path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path, key, password=None):
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, enc))


@pytest.fixture
def pki(tmp_path):
    """A CA plus CA-signed server and client leaf certs written to tmp_path."""
    ca_key = _rsa_key()
    ca_cert = _ca(ca_key)
    server_key = _rsa_key()
    server_cert = _leaf(
        server_key,
        "localhost",
        ca_key,
        ca_cert,
        sans=[x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
    )
    client_key = _rsa_key()
    client_cert = _leaf(client_key, "mcp-gateway-client", ca_key, ca_cert)

    paths = {
        "ca": tmp_path / "ca.pem",
        "server_cert": tmp_path / "server.crt",
        "server_key": tmp_path / "server.key",
        "client_cert": tmp_path / "client.crt",
        "client_key": tmp_path / "client.key",
    }
    _write_pem(paths["ca"], ca_cert)
    _write_pem(paths["server_cert"], server_cert)
    _write_key(paths["server_key"], server_key)
    _write_pem(paths["client_cert"], client_cert)
    _write_key(paths["client_key"], client_key)
    return {k: str(v) for k, v in paths.items()}


class _OkHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_a):  # silence the test server
        pass


@pytest.fixture
def mtls_server(pki):
    """An HTTPS server that REQUIRES a client cert signed by the test CA."""
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(pki["server_cert"], pki["server_key"])
    sctx.verify_mode = ssl.CERT_REQUIRED
    sctx.load_verify_locations(pki["ca"])

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.socket.getsockname()[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    # Wait until the listener accepts TCP before handing the port to the test.
    deadline = time.time() + 5
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.25)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.05)

    yield port, pki
    httpd.shutdown()
    thread.join(timeout=5)


def test_mutual_tls_handshake_succeeds_with_client_cert(mtls_server):
    port, pki = mtls_server
    verify = mtls.build_verify(
        {"client_cert": pki["client_cert"], "client_key": pki["client_key"], "ca_bundle": pki["ca"]}
    )
    with httpx.Client(verify=verify) as client:
        resp = client.get(f"https://localhost:{port}/", timeout=5)
    assert resp.status_code == 200
    assert resp.text == "ok"


def test_handshake_rejected_without_client_cert(mtls_server):
    port, pki = mtls_server
    # Trust the server's CA but present NO client cert → the server (CERT_REQUIRED)
    # aborts the handshake. Proves mutual auth is actually enforced, not optional.
    verify = mtls.build_verify({"ca_bundle": pki["ca"]})
    with httpx.Client(verify=verify) as client:
        # TLS 1.3 sends the "certificate required" alert after the server's
        # flight, so the abort can surface as a connect- or read-side transport
        # error; either way the request must not succeed.
        with pytest.raises((httpx.TransportError, ssl.SSLError)):
            client.get(f"https://localhost:{port}/", timeout=5)


def test_encrypted_client_key_unlocked_by_env_password(mtls_server, monkeypatch, tmp_path):
    port, pki = mtls_server
    # Re-encrypt the existing client key under a password and unlock it via env.
    key = serialization.load_pem_private_key(open(pki["client_key"], "rb").read(), password=None)
    enc_path = tmp_path / "client-enc.key"
    _write_key(enc_path, key, password="s3cret")
    monkeypatch.setenv(mtls.ENV_KEY_PASSWORD, "s3cret")
    verify = mtls.build_verify({"client_cert": pki["client_cert"], "client_key": str(enc_path), "ca_bundle": pki["ca"]})
    with httpx.Client(verify=verify) as client:
        resp = client.get(f"https://localhost:{port}/", timeout=5)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Wiring — components pick up the configured context
# ---------------------------------------------------------------------------


def test_device_pod_uses_configured_verify():
    from device_mcp_gateway.core.translator import McpManifest
    from device_mcp_gateway.pods.device_pod import DevicePod

    ctx = mtls.build_verify({"verify": False})
    pod = DevicePod(
        hostname="dev",
        manifest=McpManifest(server_name="dev", server_version="1", hostname="dev", tools=[]),
        base_url="https://dev.local",
        tls_verify=ctx,
    )
    assert pod._tls_verify is ctx
    assert pod._client()._transport is not None  # client builds with the context, no error
