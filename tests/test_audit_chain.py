# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for the tamper-evident audit hash chain (F-57).

Each audit record links to the previous via its hash, so the verifier detects any
edit, deletion, or reorder. The chain continues across a process restart (seeded
from the existing file) and across a rotation boundary (via an anchor).
"""

import json

from loguru import logger

from device_mcp_gateway.audit import (
    audit_event,
    audit_log,
    init_audit_chain,
    reset_audit_chain,
    verify_audit_chain,
)


def _emit(path, n, *, reset=True):
    """Emit ``n`` audit records to ``path`` through a real (serialised) loguru sink."""
    if reset:
        reset_audit_chain()
    sink_id = logger.add(
        str(path),
        level="INFO",
        serialize=True,
        filter=lambda rec: rec["extra"].get("event") == "audit",
    )
    try:
        for i in range(n):
            audit_event("device.create", subject="key:admin", outcome="success", rid=f"r{i}", target=f"dev{i}")
    finally:
        logger.remove(sink_id)  # flush + close the sink


def _lines(path):
    # Explicit UTF-8: the serialized audit records are UTF-8, and read_text() defaults to
    # the locale encoding (cp1252 on Windows), which mis-decodes them and fails the chain
    # tests on a non-UTF-8 box. Production audit.py already reads with encoding="utf-8".
    return path.read_text(encoding="utf-8").splitlines()


# --- happy path --------------------------------------------------------------


def test_valid_chain_verifies(tmp_path):
    p = tmp_path / "audit.log"
    _emit(p, 3)
    ok, detail = verify_audit_chain(str(p))
    assert ok, detail
    assert "verified 3" in detail


def test_mixed_emitters_share_one_chain(tmp_path):
    """audit_event (who/what/outcome) and audit_log (e.g. 'tool dispatch') write to
    the same chain — a real audit file interleaves both and must still verify."""
    p = tmp_path / "audit.log"
    reset_audit_chain()
    sink_id = logger.add(str(p), level="INFO", serialize=True, filter=lambda rec: rec["extra"].get("event") == "audit")
    try:
        audit_event("device.create", subject="key:admin", outcome="success", rid="r0", target="dev1")
        audit_log("tool dispatch", hostname="dev1", method="get_x", status="ok", rid="r1", duration_ms=12.3)
        audit_event("authz.check", subject="key:ops", outcome="denied", rid="r2", reason="missing_scope")
        audit_log("tool dispatch", hostname="dev1", method="make_x", status="dead_letter", rid="r3")
    finally:
        logger.remove(sink_id)

    ok, detail = verify_audit_chain(str(p))
    assert ok, detail
    assert "verified 4" in detail


def test_empty_file_verifies_zero(tmp_path):
    p = tmp_path / "empty.log"
    p.write_text("")
    ok, detail = verify_audit_chain(str(p))
    assert ok and "verified 0" in detail


def test_missing_file_reports_error(tmp_path):
    ok, detail = verify_audit_chain(str(tmp_path / "nope.log"))
    assert not ok
    assert "cannot read" in detail


# --- tamper detection --------------------------------------------------------


def test_altered_record_is_detected(tmp_path):
    p = tmp_path / "audit.log"
    _emit(p, 3)
    lines = _lines(p)
    rec = json.loads(lines[1])
    rec["record"]["extra"]["subject"] = "key:attacker"  # edit payload, leave hash stale
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")

    ok, detail = verify_audit_chain(str(p))
    assert not ok
    assert "altered" in detail


def test_deleted_record_is_detected(tmp_path):
    p = tmp_path / "audit.log"
    _emit(p, 4)
    lines = _lines(p)
    del lines[1]  # drop the second record
    p.write_text("\n".join(lines) + "\n")

    ok, detail = verify_audit_chain(str(p))
    assert not ok
    assert "deleted or reordered" in detail or "sequence gap" in detail


def test_reordered_records_are_detected(tmp_path):
    p = tmp_path / "audit.log"
    _emit(p, 4)
    lines = _lines(p)
    lines[1], lines[2] = lines[2], lines[1]  # swap two records
    p.write_text("\n".join(lines) + "\n")

    ok, _ = verify_audit_chain(str(p))
    assert not ok


# --- continuity --------------------------------------------------------------


def test_chain_continues_after_restart(tmp_path):
    p = tmp_path / "audit.log"
    _emit(p, 2)  # seq 0, 1

    # Simulate a fresh process: the in-memory chain would restart at genesis unless
    # it is re-seeded from the existing file.
    reset_audit_chain()
    init_audit_chain(str(p))
    _emit(p, 1, reset=False)  # appends seq 2, linked to the prior tail

    ok, detail = verify_audit_chain(str(p))
    assert ok, detail
    assert "verified 3" in detail


def test_restart_without_reseed_breaks_chain(tmp_path):
    """Guard: a restart that resets the chain (no init) is itself detectable."""
    p = tmp_path / "audit.log"
    _emit(p, 2)
    reset_audit_chain()  # fresh process, NO init_audit_chain
    _emit(p, 1, reset=False)  # appends a seq-0/genesis-prev record mid-file

    ok, _ = verify_audit_chain(str(p))
    assert not ok


# --- rotation boundary -------------------------------------------------------


def test_rotation_boundary_anchor(tmp_path):
    p = tmp_path / "audit.log"
    _emit(p, 4)
    lines = _lines(p)
    rotated = tmp_path / "audit.log.2"
    rotated.write_text("\n".join(lines[2:]) + "\n")  # second file starts mid-chain (seq 2,3)

    # Verifies internally with no anchor...
    ok, _ = verify_audit_chain(str(rotated))
    assert ok
    # ...but a wrong anchor flags the boundary.
    ok2, detail2 = verify_audit_chain(str(rotated), start_prev="0" * 64, start_seq=2)
    assert not ok2


# --- multi-replica (one shared sink, independent per-replica sub-chains) ------


def _emit_as(path, instance, specs, monkeypatch):
    """Emit ``specs`` as audit records tagged with replica ``instance`` (its own chain
    seeded at genesis), returning the serialised lines."""
    import device_mcp_gateway.audit as audit

    monkeypatch.setattr(audit, "_INSTANCE_ID", instance)  # restored after the test
    reset_audit_chain()  # a fresh replica starts its own sub-chain at genesis
    sink_id = logger.add(
        str(path), level="INFO", serialize=True, filter=lambda rec: rec["extra"].get("event") == "audit"
    )
    try:
        for s in specs:
            audit_event(**s)
    finally:
        logger.remove(sink_id)
    return _lines(path)


_A_SPECS = [
    dict(action="device.create", subject="key:admin", outcome="success", rid="a0", target="d0"),
    dict(action="device.update", subject="key:admin", outcome="success", rid="a1", target="d0"),
]
_B_SPECS = [
    dict(action="device.create", subject="key:ops", outcome="success", rid="b0", target="d1"),
    dict(action="authz.check", subject="key:ops", outcome="denied", rid="b1", reason="missing_scope"),
]


def _interleaved_shared_log(tmp_path, monkeypatch):
    """Two replicas (A, B) each with their own genesis-seeded chain, interleaved
    line-by-line into one shared sink — A0, B0, A1, B1."""
    a = _emit_as(tmp_path / "a.log", "replica-A", _A_SPECS, monkeypatch)
    b = _emit_as(tmp_path / "b.log", "replica-B", _B_SPECS, monkeypatch)
    p = tmp_path / "shared.log"
    p.write_text("\n".join([a[0], b[0], a[1], b[1]]) + "\n")
    return p


def test_multi_replica_interleaved_chains_verify(tmp_path, monkeypatch):
    # Pre-fix this was a false positive: replica B's seq-0/genesis record landing mid
    # file (after A's seq-1) tripped the single global chain as a "chain break".
    p = _interleaved_shared_log(tmp_path, monkeypatch)
    ok, detail = verify_audit_chain(str(p))
    assert ok, detail
    assert "verified 4" in detail


def test_multi_replica_tamper_in_one_subchain_is_detected(tmp_path, monkeypatch):
    # Per-replica verification must not weaken tamper detection: editing one replica's
    # record still fails the chain.
    p = _interleaved_shared_log(tmp_path, monkeypatch)
    lines = _lines(p)
    rec = json.loads(lines[2])  # A's second record (seq 1)
    rec["record"]["extra"]["target"] = "evil"
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")

    ok, detail = verify_audit_chain(str(p))
    assert not ok
    assert "altered" in detail
