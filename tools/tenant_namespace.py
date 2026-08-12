#!/usr/bin/env python3
"""Compute a tenant's Kubernetes namespace pseudonym (ADR-0014 §1).

    $ export MCP_TENANT_NAMESPACE_KEY="$(openssl rand -hex 32)"
    $ python3 tools/tenant_namespace.py acme-corp
    mcp-t-3f9a1c2b7d4e8065

The namespace name is a *pseudonym*, never the customer's name. A namespace name is not
encrypted, so a customer name written here survives the crypto-shred that ADR-0013 §10
exists to provide, and it leaks into every ``kubectl`` output, Prometheus label, alert and
dashboard derived from them. This is the same reasoning that gave hostnames a tombstone
rather than a delete.

**Keyed, not a bare hash.** A bare hash of a tenant identifier is reversible by dictionary
attack over a plausible customer list, which would make the pseudonym decorative — the
argument ADR-0013 §9 already made for actor handles.

**The key is domain-separated from the BFF's audit pseudonym key, and must not be the same
key.** The two handles have different exposure: an audit handle is read by that tenant, a
namespace name is visible to anyone with cluster read across the whole estate. Sharing key
material would let one be used to probe the other.

**Deterministic on purpose.** GitOps, a rebuild and an ADR-0011 restore all recompute the
same namespace from the tenant identifier, with no stateful allocation record to lose. The
cost is that the key is now load-bearing: lose it and you cannot derive the namespace of an
existing tenant, though the cluster still knows it. Back it up with ``MCP_SECRET_KEY``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import sys

PREFIX = "mcp-t-"
DIGEST_BYTES = 8  # 16 hex chars; 22 total with the prefix, inside the 63-char DNS-1123 limit
DOMAIN = "namespace:v1:"
KEY_ENV = "MCP_TENANT_NAMESPACE_KEY"

# RFC 1123 label: lowercase alphanumeric or '-', starting and ending alphanumeric, <= 63.
_DNS1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def namespace_for(tenant_id: str, key: bytes) -> str:
    """Return the namespace name for ``tenant_id``.

    Domain-separated so this HMAC cannot collide with, or be used to probe, any other
    keyed handle derived from related material.
    """
    if not tenant_id:
        raise ValueError("tenant_id must not be empty")
    if not key:
        raise ValueError(f"a key is required; set {KEY_ENV}")
    msg = (DOMAIN + tenant_id).encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).digest()[:DIGEST_BYTES]
    name = PREFIX + digest.hex()
    # Belt and braces: the construction cannot produce an invalid label, but a future
    # edit to PREFIX or DIGEST_BYTES could, and the failure would surface as a confusing
    # API rejection at apply time rather than here.
    if len(name) > 63 or not _DNS1123.match(name):
        raise ValueError(f"computed namespace {name!r} is not a valid DNS-1123 label")
    return name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute a tenant's Kubernetes namespace pseudonym (ADR-0014 §1).",
        epilog=(
            f"The key is read from ${KEY_ENV}. It must be the same key for the life of "
            "the estate — changing it renames every tenant's namespace."
        ),
    )
    parser.add_argument("tenant_id", help="stable internal tenant identifier (never displayed to tenants)")
    parser.add_argument(
        "--label",
        action="store_true",
        help="print the kustomize/namespace label lines as well as the name",
    )
    args = parser.parse_args(argv)

    key = os.getenv(KEY_ENV, "").encode("utf-8")
    if not key:
        # Fail rather than defaulting to an unkeyed hash. An unkeyed pseudonym is
        # reversible by dictionary attack, and it would be indistinguishable from a
        # keyed one by inspection — so the insecure result must never be reachable
        # by omission.
        print(
            f"error: {KEY_ENV} is not set. Generate one once for the estate and keep it "
            f'with MCP_SECRET_KEY:\n    export {KEY_ENV}="$(openssl rand -hex 32)"',
            file=sys.stderr,
        )
        return 2

    try:
        name = namespace_for(args.tenant_id, key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.label:
        print(f"namespace: {name}")
        print("labels:")
        print("  mcp.gateway/plane: tenant")
        print(f"  mcp.gateway/tenant: {name[len(PREFIX):]}")
    else:
        print(name)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
