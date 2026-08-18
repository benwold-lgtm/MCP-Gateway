# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §7 — an operator's identity must survive the whole chain into the audit.

    No component between the operator's authenticated session and the record written in
    the tenant's stack may substitute an identity of its own.

**Why this file exists separately from the per-hop tests.** ``tests/test_oidc.py`` proves the
validator derives ``oidc:<iss>#<sub>``; ``tests/test_audit.py`` proves ``audit_request`` copies
whatever subject it is handed; the BFF's ``test_act_on_tenant.py`` proves ``upstream_bearer``
picks the operator's token rather than the stack's admin key. Every hop is covered, and *each
hop being individually correct is not the property.* The property is that two distinct humans
arrive as two distinct entries, which no single-hop test can state — a relay that memoised a
credential, or a cache keyed too coarsely, passes all three and fails this.

So these tests drive the **real** authenticator and assert against **emitted** audit records.
Nothing here constructs a ``Principal`` by hand: a synthesised principal would agree with the
code because both were written from the same belief, which is the failure ADR-0013 §11c
records against its own test double.

**Adjacent coverage.** ``tests/test_identity_propagation.py`` pins the *next* hop — that the
subject rides the Redis stream into the worker's execution audit (F-30). This file pins the
hop before it: that the subject arriving at the gateway names the human who authenticated.
Together they span credential → audit record → worker; neither states the other's half.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.security import HTTPAuthorizationCredentials
from loguru import logger

from device_mcp_gateway.audit import audit_request
from device_mcp_gateway.oidc import MultiIssuerValidator, OIDCConfig
from device_mcp_gateway.rbac import CompositeAuthenticator, build_static_authenticator

ISSUER = "https://provider-idp.example.com"
AUDIENCE = "device-mcp-gateway"
KID = "test-key-1"

#: Two operators, because one cannot demonstrate distinguishability.
ALICE = "alice@provider.example"
BRIAN = "brian@provider.example"


@pytest.fixture
def audit_log():
    """Emitted audit records, as ``extra`` dicts. Assertions read these rather than return
    values, because the audit chain is the artefact a tenant actually inspects."""
    captured = []

    def _sink(message):
        rec = message.record
        if rec["extra"].get("event") == "audit":
            captured.append(rec["extra"])

    sink_id = logger.add(_sink, level="INFO")
    yield captured
    logger.remove(sink_id)


@pytest.fixture(scope="module")
def priv() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(priv: rsa.RSAPrivateKey) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk.update(kid=KID, alg="RS256")
    return jwk


def _token(priv: rsa.RSAPrivateKey, sub: str) -> str:
    """A token for one named operator. Only ``sub`` varies between the two — if anything
    downstream collapses them, it is collapsing on the one field that identifies a human."""
    now = int(time.time())
    claims = {
        "sub": sub,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
        "groups": ["mcp-admins"],
    }
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": KID})


def _authenticator(priv: rsa.RSAPrivateKey, *, admin_key: str = "shared-admin-key"):
    """The real composite: OIDC first, static key as break-glass — the production shape.

    The static key is configured deliberately. It is the collapse this file exists to detect,
    so a test bed without one could not catch it arriving.
    """
    validator = MultiIssuerValidator(
        [
            OIDCConfig(
                issuer=ISSUER,
                audience=AUDIENCE,
                group_roles={"mcp-admins": "admin"},
                jwks_uri=f"{ISSUER}/jwks",
                allow_private_targets=True,  # no DNS: the suite stays offline
            )
        ]
    )
    validator.seed(ISSUER, {"keys": [_jwk(priv)]})
    # Built through the production path rather than by hand, so the subject format the
    # assertions read (``key:<name>``) is the one a deployment actually produces.
    static = build_static_authenticator({"gateway": {"rbac": [{"name": "admin", "key": admin_key, "role": "admin"}]}})
    return CompositeAuthenticator(oidc=validator, static=static)


async def _act_as(auth, token: str, audit_log, *, action="device.read") -> str:
    """Authenticate as the holder of ``token`` and emit one audit record. Returns its subject.

    This is the whole chain in miniature: credential in, principal resolved by the real
    authenticator, record emitted by the real auditor. No step is stubbed.
    """
    principal = await auth.authenticate_async(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
    request = SimpleNamespace(state=SimpleNamespace(principal=principal, request_id="rid-test"))
    before = len(audit_log)
    audit_request(request, action, outcome="success", target="dev-1")
    assert len(audit_log) == before + 1, "expected exactly one audit record per act"
    return audit_log[-1]["subject"]


# --- The property ------------------------------------------------------------


@pytest.mark.asyncio
async def test_two_operators_reach_the_audit_as_two_identities(priv, audit_log):
    """Two humans, two credentials, two distinguishable entries in the chain.

    The assertion is inequality of what a tenant can *read*, not equality against a format
    this test also computes. Asserting ``== f"oidc:{ISSUER}#{ALICE}"`` would restate the
    implementation and would still pass if both operators produced that same string for the
    wrong reason.
    """
    auth = _authenticator(priv)

    alice = await _act_as(auth, _token(priv, ALICE), audit_log)
    brian = await _act_as(auth, _token(priv, BRIAN), audit_log)

    assert alice != brian, "two operators collapsed to a single audit identity"
    assert ALICE in alice and BRIAN in brian, "the audit subject does not name the operator"


@pytest.mark.asyncio
async def test_neither_operator_arrives_as_the_shared_key(priv, audit_log):
    """One shape of collapse: a human recorded as the stack's shared *static* key.

    The BFF's gateway client carries the stack's admin token as a *client-level default*, so
    a relay that omits the per-request bearer does not fail — it succeeds, as the key. That
    is invisible from inside the BFF; here it is a subject that names no person.

    **This test covers that shape and not the general case**, which mutation testing is how I
    found out. Collapsing every operator onto a shared *federated* identity — a service
    account used for the relay, the form ADR-0012 rejected — produces a subject beginning
    ``oidc:``, and passes here. ``test_two_operators_reach_the_audit_as_two_identities`` is
    what catches that, and is the test carrying the property; this one names the specific
    regression the current code is one omitted argument away from.
    """
    auth = _authenticator(priv)

    for sub in (ALICE, BRIAN):
        subject = await _act_as(auth, _token(priv, sub), audit_log)
        assert subject.startswith("oidc:"), f"{sub} was not recorded as a federated identity"
        assert not subject.startswith("key:"), f"{sub} arrived as a shared static key"


@pytest.mark.asyncio
async def test_the_subject_is_qualified_by_issuer(priv, audit_log):
    """Two issuers may each have a ``sub`` of ``admin``; the audit must not merge them.

    Covered at the validator in ``test_multi_issuer_isolation.py``. Repeated here against an
    *emitted record* because the qualification is only useful if it survives to the artefact —
    a formatter that trimmed the subject for readability would pass that test and fail this.
    """
    auth = _authenticator(priv)
    subject = await _act_as(auth, _token(priv, ALICE), audit_log)
    assert ISSUER in subject, "the audit subject is not qualified by its issuer"


# --- Proof the assertions can fail -------------------------------------------


@pytest.mark.asyncio
async def test_the_shared_key_really_does_collapse_two_operators(priv, audit_log):
    """The negative control, and the reason to trust the three tests above.

    Two *different* people using the break-glass key produce the *same* audit subject. That
    is correct behaviour for a shared credential — a key names a key — and it is exactly the
    outcome the tests above must reject when it happens to a federated operator.

    Without this, ``test_two_operators_reach_the_audit_as_two_identities`` might be passing
    because nothing in the bed can produce a collision, which is a check that cannot fail.
    """
    auth = _authenticator(priv, admin_key="shared-admin-key")

    first = await _act_as(auth, "shared-admin-key", audit_log)
    second = await _act_as(auth, "shared-admin-key", audit_log)

    assert first == second, "the bed cannot produce a collapse, so the tests above prove nothing"
    assert first.startswith("key:"), "a static key should be recorded as a key, not a person"
    assert ALICE not in first and BRIAN not in first, "a shared key must not name any operator"
