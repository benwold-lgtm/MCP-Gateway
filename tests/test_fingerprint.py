"""Tests for endpoint fingerprinting (ADR-0015, F-69).

The classification rules carry most of the weight here. A single undifferentiated
"fingerprint changed" alarm would fire mostly on certificate renewals and version bumps,
and an operator trained to click through those will click through the one that matters —
so the tests that assert a change does *not* alarm are as important as the ones that
assert it does.
"""

from __future__ import annotations

import pytest

from device_mcp_gateway.security import fingerprint as fp


def obs(**kw):
    return fp.Observation(**kw)


class TestCompare:
    def test_first_observation_is_a_first_pin(self):
        assert fp.compare(obs(), obs(tls_spki_sha256="K1")) == fp.VERDICT_FIRST_PIN

    def test_identical_is_unchanged(self):
        a = obs(tls_spki_sha256="K1", tls_cert_sha256="C1", declared_name="prism", declared_version="1.0")
        assert fp.compare(a, a) == fp.VERDICT_UNCHANGED

    def test_renewal_with_the_same_key_does_not_alarm(self):
        """The case the whole SPKI-over-cert decision exists for.

        An ACME renewal reissues the certificate every 60-90 days against the same key. If
        this alarmed, every device in the fleet would raise a quarterly false positive and
        operators would learn to approve without looking — or switch the feature off.
        """
        stored = obs(tls_spki_sha256="K1", tls_cert_sha256="C1")
        seen = obs(tls_spki_sha256="K1", tls_cert_sha256="C2")
        verdict = fp.compare(stored, seen)
        assert verdict == fp.VERDICT_CERT_ROTATED
        assert verdict not in fp.NEEDS_APPROVAL

    def test_key_change_needs_approval(self):
        stored = obs(tls_spki_sha256="K1", tls_cert_sha256="C1")
        seen = obs(tls_spki_sha256="K2", tls_cert_sha256="C2")
        assert fp.compare(stored, seen) == fp.VERDICT_KEY_CHANGED
        assert fp.VERDICT_KEY_CHANGED in fp.NEEDS_APPROVAL

    def test_key_and_declared_change_is_the_strongest_signal(self):
        stored = obs(tls_spki_sha256="K1", declared_name="prism", declared_version="1.0")
        seen = obs(tls_spki_sha256="K2", declared_name="something-else", declared_version="9.9")
        assert fp.compare(stored, seen) == fp.VERDICT_KEY_AND_DECLARED_CHANGED

    def test_version_bump_alone_is_informational(self):
        stored = obs(tls_spki_sha256="K1", declared_name="prism", declared_version="1.0")
        seen = obs(tls_spki_sha256="K1", declared_name="prism", declared_version="1.1")
        verdict = fp.compare(stored, seen)
        assert verdict == fp.VERDICT_DECLARED_CHANGED
        assert verdict not in fp.NEEDS_APPROVAL

    def test_a_probe_that_learned_nothing_is_not_a_change(self):
        """An unreachable device, or a probe that failed before the handshake, has no
        observation. Absence of evidence must not read as evidence of change, or every
        transient outage becomes a fingerprint alarm."""
        stored = obs(tls_spki_sha256="K1", declared_name="prism")
        assert fp.compare(stored, obs()) == fp.VERDICT_UNCHANGED

    def test_missing_declared_field_is_not_a_change(self):
        """A terse upstream that omits `version` must not look like a downgrade."""
        stored = obs(tls_spki_sha256="K1", declared_name="prism", declared_version="1.0")
        seen = obs(tls_spki_sha256="K1", declared_name="prism", declared_version=None)
        assert fp.compare(stored, seen) == fp.VERDICT_UNCHANGED

    def test_plain_http_device_never_alarms_on_the_tls_dimension(self):
        """An http:// upstream has no certificate. That is a property of the device, not a
        failed check, and it must not be reported as a key that disappeared."""
        stored = obs(declared_name="sensor")
        seen = obs(declared_name="sensor")
        assert fp.compare(stored, seen) == fp.VERDICT_UNCHANGED


class TestObservation:
    def test_has_tls_and_is_empty(self):
        assert obs(tls_spki_sha256="K1").has_tls()
        assert not obs(declared_name="x").has_tls()
        assert obs().is_empty()
        assert not obs(declared_name="x").is_empty()


class TestPolicy:
    def test_device_override_wins(self):
        assert fp.resolve_policy("enforce", "warn") == fp.POLICY_ENFORCE
        assert fp.resolve_policy("warn", "enforce") == fp.POLICY_WARN

    def test_falls_back_to_deployment_default(self):
        assert fp.resolve_policy(None, "enforce") == fp.POLICY_ENFORCE

    def test_defaults_to_warn(self):
        """Not enforce. A fleet that stops on certificate rotation is a fleet whose
        operators disable the check, and a disabled control detects nothing."""
        assert fp.resolve_policy(None, None) == fp.POLICY_WARN

    @pytest.mark.parametrize("junk", ["", "  ", "ENFORCEISH", "yes", "true"])
    def test_unrecognised_policy_falls_through_to_warn(self, junk):
        assert fp.resolve_policy(junk, None) == fp.POLICY_WARN

    def test_policy_is_case_insensitive(self):
        assert fp.resolve_policy("ENFORCE", None) == fp.POLICY_ENFORCE


class TestQuarantine:
    def test_quarantined_only_when_pending_and_enforcing(self):
        assert fp.is_quarantined(fp.STATE_PENDING, fp.POLICY_ENFORCE)

    def test_warn_never_quarantines(self):
        """The default policy keeps the device working — it warns, it does not stop."""
        assert not fp.is_quarantined(fp.STATE_PENDING, fp.POLICY_WARN)

    def test_pinned_device_is_never_quarantined(self):
        assert not fp.is_quarantined(fp.STATE_PINNED, fp.POLICY_ENFORCE)
        assert not fp.is_quarantined(fp.STATE_UNPINNED, fp.POLICY_ENFORCE)


class TestObserveTls:
    def test_never_raises_on_a_broken_ssl_object(self):
        """A fingerprint is diagnostic. Failing to read one must not fail the request it
        rode in on, so every error path yields an empty observation instead."""

        class Exploding:
            def getpeercert(self, binary_form):
                raise RuntimeError("boom")

        assert fp.observe_tls(Exploding()).is_empty()

    def test_empty_cert_yields_empty_observation(self):
        class NoCert:
            def getpeercert(self, binary_form):
                return b""

        assert fp.observe_tls(NoCert()).is_empty()

    def test_reads_a_real_certificate(self):
        """Pins the positional-argument gotcha: the object httpcore hands back is a raw
        _SSLSocket, so `getpeercert(binary_form=True)` raises TypeError. A regression here
        would silently disable fingerprinting rather than fail loudly."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        import datetime

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        der = cert.public_bytes(serialization.Encoding.DER)

        class RealCert:
            def getpeercert(self, binary_form):
                assert binary_form is True, "must be called positionally with True"
                return der

        seen = fp.observe_tls(RealCert())
        assert seen.has_tls()
        assert seen.tls_spki_sha256 == fp.spki_sha256(der)
        assert "device.test" in (seen.tls_issuer or "")
        assert seen.tls_not_after

    def test_spki_is_stable_across_a_reissued_certificate(self):
        """Two certificates over the same key must produce the same SPKI digest — the
        property the renewal case depends on."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        import datetime

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device.test")])
        now = datetime.datetime.now(datetime.timezone.utc)

        def issue(days: int) -> bytes:
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=days))
                .sign(key, hashes.SHA256())
            )
            return cert.public_bytes(serialization.Encoding.DER)

        first, second = issue(30), issue(90)
        assert first != second, "different certificates"
        assert fp.spki_sha256(first) == fp.spki_sha256(second), "same key => same SPKI"
