"""Tests for the Tier-2 cross-tenant deny generator (ADR-0014 §5).

Most of these pin behaviour that, when wrong, produced a policy the API server accepted
without complaint and that enforced the wrong thing — or nothing. A unit test cannot prove
Cilium enforces the output (see testing-gaps.md TG-10); what it *can* do is stop the three
measured mistakes from being reintroduced by an edit, since none of them raises.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

_SPEC = importlib.util.spec_from_file_location(
    "tenant_isolation_policy",
    Path(__file__).resolve().parent.parent / "tools" / "tenant_isolation_policy.py",
)
assert _SPEC and _SPEC.loader
tip = importlib.util.module_from_spec(_SPEC)
sys.modules["tenant_isolation_policy"] = tip
_SPEC.loader.exec_module(tip)


def _selectors(policy: dict) -> list[dict]:
    """Both directions' peer selectors, which must be identical in content."""
    return [
        policy["spec"]["ingressDeny"][0]["fromEndpoints"][0],
        policy["spec"]["egressDeny"][0]["toEndpoints"][0],
    ]


class TestPolicyShape:
    def test_names_only_its_own_namespace_in_notin(self):
        """The per-tenant NotIn is the whole point.

        A single policy listing every tenant namespace here matches the empty set —
        "in a tenant namespace" AND "not in any tenant namespace" — so it enforces
        nothing and fails open. Measured on a live cluster before this was fixed.
        """
        policy = tip.policy_for("mcp-t-aaaa")
        for sel in _selectors(policy):
            notin = [e for e in sel["matchExpressions"] if e["operator"] == "NotIn"]
            assert len(notin) == 1
            assert notin[0]["values"] == ["mcp-t-aaaa"], "NotIn must name only this tenant"

    def test_default_deny_is_disabled_in_both_directions(self):
        """Without this, a deny-only policy puts the endpoint into default-deny and the
        tenant loses its own intra-namespace traffic as well as its egress."""
        spec = tip.policy_for("mcp-t-aaaa")["spec"]
        assert spec["enableDefaultDeny"] == {"ingress": False, "egress": False}

    def test_uses_cilium_namespace_label_key(self):
        """`io.kubernetes.pod.namespace.labels.*` is the plausible-looking key that
        matches nothing. Cilium's namespace-label key is `io.cilium.k8s.namespace.labels.*`."""
        for sel in _selectors(tip.policy_for("mcp-t-aaaa")):
            keys = [e["key"] for e in sel["matchExpressions"]]
            assert "io.cilium.k8s.namespace.labels.mcp.gateway/plane" in keys
            assert not any(k.startswith("io.kubernetes.pod.namespace.labels") for k in keys)

    def test_denies_both_directions(self):
        """Each policy isolates its tenant on its own, so a covered tenant stays isolated
        from an uncovered one. Dropping either half silently halves the guarantee."""
        spec = tip.policy_for("mcp-t-aaaa")["spec"]
        assert spec["ingressDeny"] and spec["egressDeny"]

    def test_endpoint_selector_targets_the_namespace_by_name(self):
        spec = tip.policy_for("mcp-t-aaaa")["spec"]
        assert spec["endpointSelector"]["matchLabels"] == {"io.kubernetes.pod.namespace": "mcp-t-aaaa"}

    def test_is_cluster_scoped(self):
        """A namespaced CiliumNetworkPolicy would live in the tenant's own namespace and
        so be deletable by the tenant — which defeats the reason Tier 2 exists."""
        assert tip.policy_for("mcp-t-aaaa")["kind"] == "CiliumClusterwideNetworkPolicy"

    def test_rejects_empty_namespace(self):
        with pytest.raises(ValueError):
            tip.policy_for("")


class TestGenerate:
    def test_one_policy_per_namespace_with_distinct_names(self):
        policies = tip.generate(["mcp-t-bbbb", "mcp-t-aaaa"])
        assert len(policies) == 2
        assert [p["metadata"]["name"] for p in policies] == [
            "mcp-tenant-deny-mcp-t-aaaa",
            "mcp-tenant-deny-mcp-t-bbbb",
        ], "sorted, so regenerating produces a clean diff"

    def test_deduplicates(self):
        assert len(tip.generate(["mcp-t-aaaa", "mcp-t-aaaa"])) == 1

    def test_empty_input_raises_rather_than_emitting_nothing(self):
        """Emitting an empty document would apply nothing and exit 0 — success-shaped
        output for a total absence of isolation."""
        with pytest.raises(ValueError):
            tip.generate([])

    def test_output_has_no_yaml_anchors(self):
        """Sharing the selector object between directions makes PyYAML emit &id/*id.
        The API server copes; several manifest tools and diff viewers do not."""
        out = yaml.dump_all(tip.generate(["mcp-t-aaaa"]), sort_keys=False)
        assert "&id" not in out and "*id" not in out

    def test_round_trips_through_yaml(self):
        policies = tip.generate(["mcp-t-aaaa", "mcp-t-bbbb"])
        assert list(yaml.safe_load_all(yaml.dump_all(policies))) == policies


class TestCoverage:
    def test_reports_uncovered_tenant(self):
        uncovered, orphaned = tip.coverage(["a", "b"], ["a"])
        assert uncovered == ["b"] and orphaned == []

    def test_reports_orphaned_policy(self):
        uncovered, orphaned = tip.coverage(["a"], ["a", "gone"])
        assert uncovered == [] and orphaned == ["gone"]

    def test_clean_when_matched(self):
        assert tip.coverage(["a", "b"], ["b", "a"]) == ([], [])
