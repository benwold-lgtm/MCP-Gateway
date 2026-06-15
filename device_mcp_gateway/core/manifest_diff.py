# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tool-set change governance (F-41).

A device's MCP tool set is generated from its upstream OpenAPI spec. When the
spec changes the gateway re-pods and the tool set mutates — previously with no
record of *what* changed or whether it was backwards-breaking, so a live MCP
client could silently start failing calls.

This module turns that silent swap into a governed signal:

  * :func:`diff_tools` is a pure classifier — it compares the old and new tool
    sets and labels the change *breaking* (a tool or parameter removed, a
    parameter newly required, or the HTTP method changed — clients calling the
    old shape now fail) versus *compatible* (a tool or optional parameter added).
  * :func:`record_tool_change` records the diff as an audit event + Prometheus
    counter + log line, so a breaking mutation is visible, alertable, and
    attributable instead of invisible.

The caller bumps a monotonic ``tools_revision`` on the device record so a client
can detect "the tool set moved under me" by polling — see ``DeviceDetail`` /
``DeviceDiagnostics``. There is no real-time server→client push (the MCP layer
declares ``tools.listChanged: false`` honestly — the SSE connection is
replica-pinned, F-20); the governance signal is the recorded change + revision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.audit import audit_event

# Cap how many names ride into a single audit/log record so a wholesale spec
# rewrite (hundreds of tools) can't emit an unbounded line.
_MAX_NAMES = 50


@dataclass
class ToolSetDiff:
    """The classified difference between two tool sets."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    breaking: bool = False
    # Human-readable reasons the change was classified breaking (empty when not).
    breaking_reasons: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        """True when nothing changed (no add/remove/change) — a no-op spec edit."""
        return not (self.added or self.removed or self.changed)


def _index_tools(tools: Any) -> dict[str, dict[str, Any]]:
    """Index a tool list by name → {method, schema}.

    Accepts either ``McpTool`` dataclasses (``.name``/``.method``/``.schema``) or
    plain dicts (manifest-from-Redis: ``name``/``method``/``schema`` or the MCP
    wire ``inputSchema``), so both the embedded and distributed call sites can
    feed it whatever they hold.
    """
    out: dict[str, dict[str, Any]] = {}
    for t in tools or []:
        if isinstance(t, dict):
            name = t.get("name")
            method = (t.get("method") or "").upper()
            schema = t.get("schema") or t.get("inputSchema") or {}
        else:
            name = getattr(t, "name", None)
            method = (getattr(t, "method", "") or "").upper()
            schema = getattr(t, "schema", None) or {}
        if name:
            out[str(name)] = {"method": method, "schema": schema if isinstance(schema, dict) else {}}
    return out


def _schema_break(old_schema: dict[str, Any], new_schema: dict[str, Any]) -> str | None:
    """Return a reason string if the schema change is backwards-breaking, else None.

    Breaking = a previously-accepted call could now be rejected: a parameter was
    removed (an arg the client sends is no longer known) or a parameter became
    required (a client that omitted it now fails validation). Adding an optional
    parameter or loosening ``required`` is compatible.
    """
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
    """Classify the change between two tool sets (pure — no side effects).

    ``changed`` lists tools present in both whose signature differs at all;
    ``breaking`` / ``breaking_reasons`` flag the subset of removals + signature
    changes that break a client calling the old shape.
    """
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

    return ToolSetDiff(
        added=added,
        removed=removed,
        changed=changed,
        breaking=bool(reasons),
        breaking_reasons=reasons,
    )


def record_tool_change(hostname: str, old_tools: Any, new_tools: Any) -> ToolSetDiff:
    """Diff the tool sets and record the change (audit + metric + log).

    Returns the :class:`ToolSetDiff`. When nothing changed (``diff.empty``) this
    is a no-op beyond the diff — the caller should not bump the revision.
    """
    diff = diff_tools(old_tools, new_tools)
    if diff.empty:
        return diff

    metrics.device_tools_changed_total.labels(hostname=hostname, breaking=str(diff.breaking).lower()).inc()
    audit_event(
        "device.tools_changed",
        subject="system",
        target=hostname,
        outcome="breaking" if diff.breaking else "compatible",
        added=diff.added[:_MAX_NAMES],
        removed=diff.removed[:_MAX_NAMES],
        changed=diff.changed[:_MAX_NAMES],
        breaking=diff.breaking,
        reasons=diff.breaking_reasons[:_MAX_NAMES],
    )
    summary = f"Tool set changed for {hostname}: +{len(diff.added)} -{len(diff.removed)} ~{len(diff.changed)}"
    if diff.breaking:
        logger.warning(f"{summary} — BREAKING ({'; '.join(diff.breaking_reasons[:5])})")
    else:
        logger.info(f"{summary} — compatible")
    return diff
