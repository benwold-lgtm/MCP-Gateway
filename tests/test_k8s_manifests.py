# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
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


# --- F10 slice 2: metrics scrape config --------------------------------------


def _deployment(path: Path) -> dict:
    return next(d for d in _load_all(path) if d["kind"] == "Deployment")


def _pod_template(dep: dict) -> dict:
    return dep["spec"]["template"]


def _container(dep: dict) -> dict:
    return _pod_template(dep)["spec"]["containers"][0]


def test_deployments_have_prometheus_scrape_annotations():
    for fname in ("deployment.yaml", "worker-deployment.yaml"):
        tmpl = _pod_template(_deployment(_K8S / fname))
        annotations = tmpl["metadata"].get("annotations", {})
        assert annotations.get("prometheus.io/scrape") == "true", fname
        assert annotations.get("prometheus.io/port") == "9100", fname


def test_containers_expose_named_metrics_port():
    for fname in ("deployment.yaml", "worker-deployment.yaml"):
        ports = _container(_deployment(_K8S / fname)).get("ports", [])
        metrics_ports = [p for p in ports if p.get("name") == "metrics"]
        assert metrics_ports and metrics_ports[0]["containerPort"] == 9100, fname


def test_worker_metrics_service_exists():
    services = [d for d in _load_all(_K8S / "service.yaml") if d["kind"] == "Service"]
    by_name = {s["metadata"]["name"]: s for s in services}
    worker_svc = by_name.get("device-mcp-worker-metrics")
    assert worker_svc is not None, "worker metrics Service missing"
    assert worker_svc["spec"]["selector"] == {"app": "device-mcp-worker"}
    assert any(p["name"] == "metrics" and p["port"] == 9100 for p in worker_svc["spec"]["ports"])
    # Gateway Service also exposes the metrics port.
    gw_ports = by_name["device-mcp-gateway"]["spec"]["ports"]
    assert any(p["name"] == "metrics" and p["port"] == 9100 for p in gw_ports)
