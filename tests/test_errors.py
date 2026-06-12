# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tier-1 tests for the central error catalog (F-51)."""

from pathlib import Path

from device_mcp_gateway.core import adapter
from device_mcp_gateway.core.errors import (
    ENVELOPE_CATALOG,
    RPC_CATALOG,
    RPC_INVALID_PARAMS,
    RPC_NO_WORKER,
    rpc_error,
)

_CATALOG_DOC = Path(__file__).resolve().parents[1] / "docs" / "error-catalog.md"


# --- rpc_error builder -------------------------------------------------------


def test_rpc_error_structure_and_reason():
    err = rpc_error(RPC_NO_WORKER, 7, rid="abc", request_id="req-1", message="custom")
    assert err == {
        "jsonrpc": "2.0",
        "id": 7,
        "error": {
            "code": -32001,
            "message": "custom",
            "data": {"reason": "no_worker", "rid": "abc", "request_id": "req-1"},
        },
    }


def test_rpc_error_default_message_from_catalog():
    err = rpc_error(RPC_INVALID_PARAMS, 1)
    assert err["error"]["code"] == -32602
    assert err["error"]["message"] == RPC_CATALOG[RPC_INVALID_PARAMS][1]
    assert err["error"]["data"] == {"reason": "invalid_params"}  # no rid/request_id when unknown


def test_rpc_error_omits_placeholder_rid():
    # The access-log default "-" is not a real correlation id and must be dropped.
    err = rpc_error(RPC_NO_WORKER, 1, rid="-")
    assert "rid" not in err["error"]["data"]


def test_rpc_error_includes_detail_when_given():
    err = rpc_error(RPC_INVALID_PARAMS, 1, detail="speed must be <= 100")
    assert err["error"]["data"]["detail"] == "speed must be <= 100"


# --- catalog integrity -------------------------------------------------------


def test_envelope_catalog_covers_all_adapter_error_types():
    adapter_types = {
        adapter.ERR_HTTP,
        adapter.ERR_TOO_LARGE,
        adapter.ERR_CIRCUIT_OPEN,
        adapter.ERR_TIMEOUT,
        adapter.ERR_CONNECTION,
        adapter.ERR_INTERNAL,
    }
    assert adapter_types == set(ENVELOPE_CATALOG)


def test_every_catalog_entry_is_documented():
    # Doc-sync guard: every reason slug and JSON-RPC code must appear in the catalog doc.
    doc = _CATALOG_DOC.read_text()
    for code, (slug, _meaning, _cause) in RPC_CATALOG.items():
        assert slug in doc, f"reason '{slug}' missing from error-catalog.md"
        assert str(code) in doc, f"code {code} missing from error-catalog.md"
    for slug in ENVELOPE_CATALOG:
        assert slug in doc, f"envelope type '{slug}' missing from error-catalog.md"
