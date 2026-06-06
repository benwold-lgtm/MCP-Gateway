# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Sanity checks for the Kubernetes manifests (S2 finding F9).

The distributed architecture is built for independent horizontal scaling but
shipped without HorizontalPodAutoscalers. These tests verify the new HPA
manifest is valid, targets both deployments, and is wired into the kustomization.
"""

from pathlib import Path

import yaml

_K8S = Path(__file__).resolve().parent.parent / "deploy" / "kubernetes"


def _load_all(path: Path) -> list:
    return [doc for doc in yaml.safe_load_all(path.read_text()) if doc]


def test_all_manifests_are_valid_yaml():
    files = list(_K8S.glob("*.yaml"))
    assert files, "no kubernetes manifests found"
    for f in files:
        docs = _load_all(f)
        assert docs, f"{f.name} produced no documents"
        for doc in docs:
            assert "kind" in doc, f"{f.name} has a document without a kind"


def test_hpa_targets_both_deployments():
    docs = _load_all(_K8S / "hpa.yaml")
    hpas = [d for d in docs if d["kind"] == "HorizontalPodAutoscaler"]
    targets = {h["spec"]["scaleTargetRef"]["name"] for h in hpas}
    assert targets == {"device-mcp-gateway", "device-mcp-worker"}
    for h in hpas:
        assert h["spec"]["minReplicas"] >= 1
        assert h["spec"]["maxReplicas"] >= h["spec"]["minReplicas"]


def test_hpa_is_registered_in_kustomization():
    kustomization = yaml.safe_load((_K8S / "kustomization.yaml").read_text())
    assert "hpa.yaml" in kustomization["resources"]
