#!/usr/bin/env python3
"""Mint and validate a tenant's opaque identifier (ADR-0019).

    $ python3 tools/tenant_id.py new
    t-3f9a1c2b7d4e8065

    $ python3 tools/tenant_id.py namespace t-3f9a1c2b7d4e8065 --label
    namespace: mcp-t-3f9a1c2b7d4e8065
    labels:
      mcp.gateway/plane: tenant
      mcp.gateway/tenant: 3f9a1c2b7d4e8065

**Random, not derived** — this is the whole of [ADR-0019](../docs/adr/0019-opaque-tenant-identity.md),
and it replaces ``tools/tenant_namespace.py``, which computed a keyed HMAC over the customer's
identifier. That construction was sound and expensive: a key to generate, distribute, rotate and
protect; a domain-separation rule that had to be *remembered* rather than enforced; a standing
warning never to reuse the material for the audit pseudonym; and a collision assertion because
truncating a MAC makes collision improbable rather than impossible.

All of it existed to conceal a value we had chosen to make revealing. A random identifier
carries no customer information, so there is nothing to conceal, and nothing to reverse — a
dictionary attack over a plausible customer list has no target here. See ADR-0019 §3 for the
full list of what that removes.

**Determinism is not lost, because nothing is computed.** GitOps, a rebuild and an ADR-0011
restore used to recompute the namespace from the tenant identifier plus the key. They now read
the identifier from the same declarative source they already read everything else from: *the
identifier is itself the durable record*.

**The identifier is never reissued** (ADR-0019 §4). Randomness makes accidental reuse
vanishingly unlikely; only a tombstone makes deliberate reuse impossible, and those are
different guarantees. Stale DNS, cached tokens and a bookmarked console from a departed tenant
must never resolve onto a new one.
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys

PREFIX = "t-"
NAMESPACE_PREFIX = "mcp-"

#: 64 bits. The collision argument alone would permit 32 — at any plausible estate size an
#: accidental collision is remote — but 32 bits is uncomfortable for a value that appears in a
#: *hostname* under ADR-0021 §5, where it is enumerable by anyone who can resolve names. At
#: 10,000 tenants the birthday probability is already about 1% at 32 bits and around 3e-15 at
#: 64, which settles ADR-0019's open question on width in the direction that costs eight
#: characters.
#:
#: It also happens to preserve the ``mcp-t-<16 hex>`` shape the deploy manifests already use, so
#: this change rewrites how the suffix is produced and nothing about how it is consumed.
ID_BYTES = 8

# RFC 1123 label: lowercase alphanumeric or '-', starting and ending alphanumeric, <= 63.
# The identifier must satisfy this in its own right: it is a namespace name and a hostname
# label, and an underscore — the natural way to write `t_7f3a91c4` — is valid in neither.
_DNS1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_TENANT_ID = re.compile(rf"^{re.escape(PREFIX)}[0-9a-f]{{{ID_BYTES * 2}}}$")


def new_tenant_id() -> str:
    """Mint a fresh opaque tenant identifier.

    ``secrets`` rather than ``random``: this is an identifier that appears in hostnames and
    must not be predictable from another one, which a seeded PRNG would make it.
    """
    return PREFIX + secrets.token_hex(ID_BYTES)


def is_valid_tenant_id(tenant_id: str) -> bool:
    """Whether ``tenant_id`` has the minted shape *and* is usable everywhere ADR-0019 §1 puts it.

    Both checks, not either. The pattern alone would accept a value that is well-formed but too
    long to be a DNS label if ``ID_BYTES`` were ever raised; the label check alone would accept
    any hostname-safe string, including a customer's name, which is the one thing this design
    exists to keep out of namespaces and dashboards.
    """
    return bool(_TENANT_ID.match(tenant_id)) and bool(_DNS1123.match(tenant_id)) and len(tenant_id) <= 63


def namespace_for(tenant_id: str) -> str:
    """The Kubernetes namespace for ``tenant_id`` — a prefix, not a derivation.

    There is no key and no computation to get wrong. The old implementation needed a
    ``ValueError`` guard here because an HMAC truncation could in principle produce an invalid
    label; concatenating two validated constants cannot.
    """
    if not is_valid_tenant_id(tenant_id):
        raise ValueError(
            f"{tenant_id!r} is not a tenant identifier (expected {PREFIX}<{ID_BYTES * 2} hex>); "
            f"mint one with `tenant_id.py new`"
        )
    name = NAMESPACE_PREFIX + tenant_id
    if len(name) > 63 or not _DNS1123.match(name):  # pragma: no cover - unreachable by construction
        raise ValueError(f"computed namespace {name!r} is not a valid DNS-1123 label")
    return name


def _cmd_new(_args: argparse.Namespace) -> int:
    print(new_tenant_id())
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    if not is_valid_tenant_id(args.tenant_id):
        print(
            f"error: {args.tenant_id!r} is not a valid tenant identifier — expected "
            f"{PREFIX}<{ID_BYTES * 2} hex>, lowercase.",
            file=sys.stderr,
        )
        return 2
    print(f"{args.tenant_id} ok")
    return 0


def _cmd_namespace(args: argparse.Namespace) -> int:
    try:
        name = namespace_for(args.tenant_id)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.label:
        print(f"namespace: {name}")
        print("labels:")
        print("  mcp.gateway/plane: tenant")
        print(f"  mcp.gateway/tenant: {args.tenant_id[len(PREFIX):]}")
    else:
        print(name)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mint and validate opaque tenant identifiers (ADR-0019).",
        epilog=(
            "There is no key to keep. Record the identifier against the customer in the "
            "provider-side mapping (ADR-0019 §2) — that record is the only place the two "
            "appear together, and it is not deployed to any cluster."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("new", help="mint a fresh tenant identifier").set_defaults(func=_cmd_new)

    p_check = sub.add_parser("check", help="validate an existing identifier")
    p_check.add_argument("tenant_id")
    p_check.set_defaults(func=_cmd_check)

    p_ns = sub.add_parser("namespace", help="print the Kubernetes namespace for an identifier")
    p_ns.add_argument("tenant_id")
    p_ns.add_argument("--label", action="store_true", help="print the kustomize label lines as well")
    p_ns.set_defaults(func=_cmd_namespace)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
