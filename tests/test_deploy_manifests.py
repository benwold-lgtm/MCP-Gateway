# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Shipped Kubernetes manifests — image pinning invariants (third-party review item 7).

The manifests used to ship ``image: device-mcp-gateway:latest`` with
``imagePullPolicy: IfNotPresent``. Three separate problems:

  - the reference had no registry, so it resolved to Docker Hub and a user following the
    k8s docs got ``ImagePullBackOff``;
  - a mutable tag with ``IfNotPresent`` lets a node keep running a stale image forever;
  - the gateway set ``IfNotPresent`` while the worker set nothing (defaulting to ``Always``
    under ``:latest``), so the two could end up on different builds of the same tag — a
    split-brain risk, since they share the Redis data model.

These are cheap invariants to assert and expensive to notice by hand at review time.
"""

from pathlib import Path

import pytest
import yaml

_DEPLOY = Path(__file__).resolve().parent.parent / "deploy" / "kubernetes"
_WORKLOADS = ["deployment.yaml", "worker-deployment.yaml"]


def _containers(filename):
    doc = yaml.safe_load((_DEPLOY / filename).read_text())
    return doc["spec"]["template"]["spec"]["containers"]


def _app_images():
    """Image reference for the gateway and worker containers, by manifest filename."""
    return {f: _containers(f)[0]["image"] for f in _WORKLOADS}


@pytest.mark.parametrize("filename", _WORKLOADS)
def test_manifest_does_not_ship_a_mutable_latest_tag(filename):
    image = _app_images()[filename]
    assert not image.endswith(":latest"), f"{filename} ships a mutable :latest tag"


@pytest.mark.parametrize("filename", _WORKLOADS)
def test_manifest_image_is_digest_pinned(filename):
    """A digest is what makes the deployment reproducible — a re-pushed tag can't move it."""
    image = _app_images()[filename]
    assert "@sha256:" in image, f"{filename} is not digest-pinned: {image}"


@pytest.mark.parametrize("filename", _WORKLOADS)
def test_manifest_image_names_a_registry(filename):
    """Without a registry host the reference resolves to Docker Hub → ImagePullBackOff."""
    image = _app_images()[filename]
    repo = image.split("@")[0].rsplit(":", 1)[0]
    assert "/" in repo, f"{filename} image has no registry/namespace: {image}"
    registry = repo.split("/")[0]
    assert "." in registry or ":" in registry, f"{filename} image has no registry host: {image}"


def test_gateway_and_worker_run_the_same_image():
    """They share the Redis data model; a version skew across a schema change is a
    split-brain risk, so the two references must be identical — digest included."""
    images = _app_images()
    assert images["deployment.yaml"] == images["worker-deployment.yaml"], (
        "gateway and worker images differ — they must stay in lockstep:\n"
        f"  gateway: {images['deployment.yaml']}\n"
        f"  worker:  {images['worker-deployment.yaml']}"
    )


@pytest.mark.parametrize("filename", _WORKLOADS)
def test_pull_policy_is_explicit_and_consistent(filename):
    """Previously the gateway said IfNotPresent and the worker said nothing (defaulting to
    Always under :latest). Both must state it, and agree."""
    policy = _containers(filename)[0].get("imagePullPolicy")
    assert policy is not None, f"{filename} leaves imagePullPolicy to the Kubernetes default"
    assert policy == "IfNotPresent", f"{filename} uses {policy!r}; IfNotPresent is correct for a digest pin"


def test_pull_policy_matches_the_tagging_strategy():
    """IfNotPresent is only safe because the image is immutable. If someone swaps in a
    moving tag without a digest, this fails and points at the required policy change."""
    for filename, image in _app_images().items():
        policy = _containers(filename)[0].get("imagePullPolicy")
        if "@sha256:" not in image:
            assert policy == "Always", (
                f"{filename} uses the mutable reference {image!r} with {policy!r} — "
                "a moving tag requires imagePullPolicy: Always, or a node runs stale bits forever"
            )
