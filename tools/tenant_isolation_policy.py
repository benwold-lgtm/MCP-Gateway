#!/usr/bin/env python3
"""Generate the Tier-2 cross-tenant deny policies (ADR-0014 §5).

    # From the cluster's own labelled namespaces — the form provisioning should use
    $ python3 tools/tenant_isolation_policy.py generate --from-cluster | kubectl apply -f -

    # From an explicit list (GitOps: commit the output, apply from the repo)
    $ python3 tools/tenant_isolation_policy.py generate mcp-t-3f9a1c2b7d4e8065 mcp-t-c8dfe247

    # Coverage check — exits non-zero if a tenant namespace has no policy
    $ python3 tools/tenant_isolation_policy.py check

Why this is generated rather than written once
----------------------------------------------
A ``CiliumClusterwideNetworkPolicy`` is a single cluster-scoped object, and the selector
language has **no self-reference** — it cannot say "any tenant namespace other than the
pod's own". So one object cannot express the rule for every tenant at once. What works is
**one policy per tenant**, each naming its own namespace in the ``NotIn`` list, which is
exactly what has to be regenerated whenever a tenant is added or removed.

Three facts that were established by measurement, each of which produced a policy that
applied cleanly and did the wrong thing (see ADR-0014 § Implementation notes):

1. **One object with ``NotIn [every tenant namespace]`` is a no-op.** ``matchExpressions``
   are ANDed, so "source is in a tenant-plane namespace" AND "source is not any tenant
   namespace" matches the empty set. It produces no error and enforces nothing — it fails
   **open**.

2. **A deny-only policy flips the endpoint into default-deny** unless
   ``enableDefaultDeny`` is explicitly false for both directions. Without it the policy
   does block cross-tenant traffic — and also every other thing the pod talks to,
   including its own namespace, because deny rules alone allow nothing.

3. **The namespace-label selector key is ``io.cilium.k8s.namespace.labels.<label>``**, not
   ``io.kubernetes.pod.namespace.labels.<label>``. The wrong key matches nothing, silently.
   (The *namespace name* key, ``io.kubernetes.pod.namespace``, is a separate thing and is
   spelled as it looks.)

Coverage, and what a gap actually costs
---------------------------------------
Each tenant's policy carries **both** an ``ingressDeny`` and an ``egressDeny``, so it
protects that tenant in both directions on its own: a covered tenant is isolated even from
tenants that have no policy. A missing policy therefore exposes only the **uncovered**
tenant, and only to other uncovered tenants — verified on a live cluster. That bounds the
damage, but it does not remove it, which is why ``check`` exists and why provisioning must
regenerate rather than hand-edit.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any

import yaml

PLANE_LABEL = "mcp.gateway/plane"
TENANT_PLANE = "tenant"

# Cilium's selector key for a *namespace label*. Not io.kubernetes.pod.namespace.labels.*,
# which is a plausible-looking key that matches nothing.
NS_LABEL_KEY = f"io.cilium.k8s.namespace.labels.{PLANE_LABEL}"
# Cilium's selector key for the *namespace name*.
NS_NAME_KEY = "io.kubernetes.pod.namespace"

POLICY_PREFIX = "mcp-tenant-deny-"


def policy_for(namespace: str) -> dict[str, Any]:
    """Build the deny policy isolating ``namespace`` from every other tenant namespace."""
    if not namespace:
        raise ValueError("namespace must not be empty")

    # "Any endpoint in a tenant-plane namespace that is not THIS namespace." The second
    # expression is what makes the policy per-tenant, and what a single cluster-wide
    # object cannot express.
    def other_tenants() -> list[dict[str, Any]]:
        # Built fresh for each direction rather than shared. A shared object makes
        # PyYAML emit an anchor/alias pair (&id001 / *id001) — valid YAML that the API
        # server accepts, but which several manifest tools and diff viewers mishandle,
        # and which makes the generated file harder to read than it needs to be.
        return [
            {
                "matchExpressions": [
                    {"key": NS_LABEL_KEY, "operator": "In", "values": [TENANT_PLANE]},
                    {"key": NS_NAME_KEY, "operator": "NotIn", "values": [namespace]},
                ]
            }
        ]

    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumClusterwideNetworkPolicy",
        "metadata": {
            "name": f"{POLICY_PREFIX}{namespace}",
            "labels": {
                "app.kubernetes.io/managed-by": "tenant_isolation_policy.py",
                PLANE_LABEL: TENANT_PLANE,
            },
        },
        "spec": {
            "description": (
                f"Deny traffic between {namespace} and every other MCP tenant namespace, "
                "both directions. Deny takes precedence over any allow, including one "
                "created inside a tenant's own namespace. ADR-0014 §5 (Tier 2)."
            ),
            # Contribute ONLY deny rules. Without this the policy puts the endpoint into
            # default-deny for both directions, and since deny rules allow nothing, the
            # tenant loses its own intra-namespace traffic as well as its egress.
            "enableDefaultDeny": {"ingress": False, "egress": False},
            "endpointSelector": {"matchLabels": {NS_NAME_KEY: namespace}},
            "ingressDeny": [{"fromEndpoints": other_tenants()}],
            "egressDeny": [{"toEndpoints": other_tenants()}],
        },
    }


def generate(namespaces: list[str]) -> list[dict[str, Any]]:
    """One policy per namespace, in a stable order so the output diffs cleanly."""
    unique = sorted(set(namespaces))
    if not unique:
        # Emitting nothing would apply nothing and read as success — the fail-open shape
        # this whole file exists to avoid.
        raise ValueError("no tenant namespaces given; refusing to emit an empty policy set")
    return [policy_for(ns) for ns in unique]


def _kubectl(args: list[str]) -> str:
    proc = subprocess.run(["kubectl", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def tenant_namespaces_from_cluster() -> list[str]:
    """Namespaces labelled as tenant-plane. This is the authority for coverage.

    Reading the cluster rather than a list in a file is deliberate: a namespace created
    outside the provisioning path is exactly the one a hand-maintained list would miss.
    """
    out = _kubectl(["get", "namespaces", "-l", f"{PLANE_LABEL}={TENANT_PLANE}", "-o", "json"])
    return sorted(item["metadata"]["name"] for item in json.loads(out).get("items", []))


def applied_policy_namespaces() -> list[str]:
    """Namespaces that currently have a generated deny policy applied."""
    try:
        out = _kubectl(["get", "ciliumclusterwidenetworkpolicies", "-o", "json"])
    except RuntimeError as exc:
        if "server doesn't have a resource type" in str(exc) or "NotFound" in str(exc):
            return []
        raise
    names = [item["metadata"]["name"] for item in json.loads(out).get("items", [])]
    return sorted(n[len(POLICY_PREFIX) :] for n in names if n.startswith(POLICY_PREFIX))


def coverage(tenants: list[str], covered: list[str]) -> tuple[list[str], list[str]]:
    """Return (uncovered tenants, orphaned policies)."""
    return (
        sorted(set(tenants) - set(covered)),
        sorted(set(covered) - set(tenants)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Tier-2 cross-tenant deny policies (ADR-0014 §5).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="emit one CiliumClusterwideNetworkPolicy per tenant namespace")
    gen.add_argument("namespaces", nargs="*", help="tenant namespaces; omit with --from-cluster")
    gen.add_argument(
        "--from-cluster",
        action="store_true",
        help="read namespaces labelled mcp.gateway/plane=tenant from the cluster",
    )

    chk = sub.add_parser("check", help="report tenant namespaces with no deny policy")
    chk.add_argument(
        "--quiet",
        action="store_true",
        help="print nothing on success (for CI / provisioning hooks)",
    )

    args = parser.parse_args(argv)

    try:
        if args.cmd == "generate":
            namespaces = tenant_namespaces_from_cluster() if args.from_cluster else args.namespaces
            if args.from_cluster and args.namespaces:
                print("error: pass namespaces or --from-cluster, not both", file=sys.stderr)
                return 2
            policies = generate(namespaces)
            print(
                yaml.dump_all(
                    policies,
                    sort_keys=False,
                    default_flow_style=False,
                    allow_unicode=True,
                    width=100,
                ),
                end="",
            )
            return 0

        tenants = tenant_namespaces_from_cluster()
        uncovered, orphaned = coverage(tenants, applied_policy_namespaces())
        for ns in uncovered:
            # Loud, because this is the fail-open direction: the namespace exists, is
            # labelled a tenant, and nothing is isolating it from other uncovered tenants.
            print(f"UNCOVERED: {ns} has no {POLICY_PREFIX}* policy", file=sys.stderr)
        for ns in orphaned:
            print(f"orphaned:  {POLICY_PREFIX}{ns} has no matching namespace", file=sys.stderr)
        if uncovered:
            return 1
        if not args.quiet:
            print(f"all {len(tenants)} tenant namespace(s) covered")
        return 0

    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
