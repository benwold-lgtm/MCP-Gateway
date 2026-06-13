# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Offline verifier for the tamper-evident audit log (F-57).

Usage:
    python -m device_mcp_gateway.audit_verify logs/audit.log
    python -m device_mcp_gateway.audit_verify logs/audit.log --start-prev <hash> --start-seq <n>

Exit code 0 = chain intact, 1 = tampering detected / unreadable. Pass the prior
rotated file's last hash + seq+1 via --start-prev/--start-seq to verify across a
rotation boundary.
"""

from __future__ import annotations

import argparse
import sys

from device_mcp_gateway.audit import verify_audit_chain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="audit_verify", description="Verify the audit log hash chain.")
    parser.add_argument("audit_file", help="Path to the serialised audit log (e.g. logs/audit.log)")
    parser.add_argument("--start-prev", default=None, help="Previous file's last audit_hash (rotation anchor)")
    parser.add_argument("--start-seq", type=int, default=None, help="Expected first seq (prior last seq + 1)")
    args = parser.parse_args(argv)

    ok, detail = verify_audit_chain(args.audit_file, start_prev=args.start_prev, start_seq=args.start_seq)
    print(("OK: " if ok else "FAIL: ") + detail)
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
