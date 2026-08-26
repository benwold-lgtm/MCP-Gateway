# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""A deliberate, small duplicate of `device_mcp_gateway.core.manifest_diff`'s pure
classifier (`diff_tools`/`ToolSetDiff`/`_index_tools`/`_schema_break`), for ADR-0020 §4's
upgrade-offer diff (slice 5).

This is NOT imported from the gateway package, even though both live in this repo. The
gateway module sits next to `record_tool_change`, which pulls in `device_mcp_gateway.metrics`
and `device_mcp_gateway.audit` — importing the module at all would make this service depend
on the whole gateway package's dependency tree (prometheus_client, redis, the audit log
writer, ...) just to reuse an ~80-line pure function, which is exactly the coupling
ADR-0020 §7 calls for this service NOT to have ("a separate component with its own failure
domain"). The classifier itself is pure (dataclasses + stdlib only) and has had zero reason
to change since F-41 shipped it, so a small, clearly-flagged duplicate costs less than
either building shared-package plumbing for one function or accepting the dependency.

If `diff_tools` in the gateway ever changes behavior, this copy must be updated to match —
there is no test that can catch drift across the repo boundary automatically; that risk is
the price of this call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolSetDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    breaking: bool = False
    breaking_reasons: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.changed)


def _index_tools(tools: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        name = t.get("name")
        method = (t.get("method") or "").upper()
        schema = t.get("schema") or t.get("inputSchema") or {}
        if name:
            out[str(name)] = {"method": method, "schema": schema if isinstance(schema, dict) else {}}
    return out


def _schema_break(old_schema: dict[str, Any], new_schema: dict[str, Any]) -> str | None:
    old_props = set((old_schema.get("properties") or {}).keys())
    new_props = set((new_schema.get("properties") or {}).keys())
    removed_props = old_props - new_props
    if removed_props:
        return f"parameter(s) removed: {sorted(removed_props)}"
    old_req = set(old_schema.get("required") or [])
    new_req = set(new_schema.get("required") or [])
    newly_required = new_req - old_req
    if newly_required:
        return f"parameter(s) newly required: {sorted(newly_required)}"
    return None


def diff_tools(old_tools: Any, new_tools: Any) -> ToolSetDiff:
    """Classify the change between two declared tool sets (pure — no side effects, never
    called with anything but curator-declared data in this service)."""
    old_idx = _index_tools(old_tools)
    new_idx = _index_tools(new_tools)

    added = sorted(set(new_idx) - set(old_idx))
    removed = sorted(set(old_idx) - set(new_idx))
    changed: list[str] = []
    reasons: list[str] = []

    for name in sorted(set(old_idx) & set(new_idx)):
        o, n = old_idx[name], new_idx[name]
        if o["method"] != n["method"]:
            changed.append(name)
            reasons.append(f"{name}: method {o['method'] or '?'}→{n['method'] or '?'}")
            continue
        if o["schema"] != n["schema"]:
            changed.append(name)
            reason = _schema_break(o["schema"], n["schema"])
            if reason:
                reasons.append(f"{name}: {reason}")

    if removed:
        reasons.insert(0, f"tool(s) removed: {removed}")

    return ToolSetDiff(added=added, removed=removed, changed=changed, breaking=bool(reasons), breaking_reasons=reasons)
