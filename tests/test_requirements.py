# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Guard against requirements.txt drifting from pyproject.toml (S2 finding F2).

requirements.txt is the pip-compiled lockfile used by the Docker image. It had
silently gone stale — missing redis/slowapi/pybreaker — so a clean install from
it produced an environment that couldn't import the app. This test fails if any
declared runtime dependency is absent from the lockfile.
"""

import re
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _canonical(name: str) -> str:
    # PEP 503 canonicalisation: lowercase, runs of -/_/. collapse to a single -.
    return re.sub(r"[-_.]+", "-", name).lower()


def _dep_name(spec: str) -> str:
    # "redis[asyncio]>=5.0" -> "redis"
    return _canonical(re.split(r"[<>=!~\[ ]", spec.strip(), maxsplit=1)[0])


def _pyproject_runtime_deps() -> set[str]:
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text())
    return {_dep_name(d) for d in data["project"]["dependencies"]}


def _locked_names() -> set[str]:
    names = set()
    for line in (_ROOT / "requirements.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.add(_dep_name(line))
    return names


def test_every_runtime_dependency_is_locked():
    missing = _pyproject_runtime_deps() - _locked_names()
    assert not missing, f"requirements.txt is missing pyproject deps: {sorted(missing)} — re-run pip-compile"


def test_runtime_critical_packages_present():
    locked = _locked_names()
    for pkg in ("redis", "pybreaker", "fastapi", "cryptography"):
        assert pkg in locked, f"{pkg} missing from requirements.txt"
