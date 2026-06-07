# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Guards for the CI workflow hardening (S2 finding F13).

CI now runs against a real Redis service, enforces a coverage gate, and runs
advisory dependency/static security scans. These checks fail if any of that is
removed from the workflow.
"""

from pathlib import Path

import yaml

_CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def _workflow() -> dict:
    return yaml.safe_load(_CI.read_text())


def test_test_job_has_redis_service_and_coverage_gate():
    wf = _workflow()
    test_job = wf["jobs"]["test"]
    assert "redis" in test_job["services"]
    steps = " ".join(s.get("run", "") for s in test_job["steps"])
    assert "--cov-fail-under" in steps


def test_security_job_runs_scanners():
    wf = _workflow()
    assert "security" in wf["jobs"], "security job missing"
    steps = " ".join(s.get("run", "") for s in wf["jobs"]["security"]["steps"])
    assert "pip-audit" in steps
    assert "bandit" in steps
