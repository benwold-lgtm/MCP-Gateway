# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Canonical JSON serialization and digesting (ADR-0018 §6).

A general-purpose utility, not restore-specific — ADR-0022 reuses this exact
canonicalization for device-write plans ("no new digest mechanism, no new
canonicalization rules"), so nothing here may assume the shape of a restore
request.

The scheme is RFC 8785 (JSON Canonicalization Scheme), which settles object-key
ordering (sorted by UTF-16 code unit) and numeric form (ECMAScript
``Number::toString``). JCS leaves two axes open; ADR-0018 §6 settles both:

  * **Absent vs. null.** A field with no value is omitted; an explicit ``null``
    is never emitted. A ``None`` dict value is dropped rather than serialized,
    so a client that spells a default as ``null`` and one that omits the field
    entirely produce the same digest.
  * **Order of set-valued fields.** A field whose *order* is semantically
    insignificant (e.g. a device-selector list) must be declared via
    ``set_fields`` and is sorted before hashing. Anything not declared keeps
    its given order — most fields (an archive blob, a flag) are ordered by
    construction and sorting them would be silently wrong.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import AbstractSet, Any, Mapping, Sequence

__all__ = ["canonicalize", "compute_digest"]


def _utf16_sort_key(s: str) -> bytes:
    """RFC 8785 §3.2.3: object keys sorted by UTF-16 code unit.

    Encoding to UTF-16BE and comparing the raw bytes reproduces that ordering
    (including surrogate-pair handling for characters outside the BMP), so no
    separate code-unit-by-code-unit comparator is needed.
    """
    return s.encode("utf-16-be")


def _canonical_number(n: float) -> str:
    """ECMAScript ``Number::toString`` form, for the finite floats JSON allows."""
    if math.isnan(n) or math.isinf(n):
        raise ValueError("NaN and Infinity have no JSON representation")
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    return repr(n)


def _dumps(value: Any, set_fields: AbstractSet[str], *, _top: bool = False) -> str:
    if isinstance(value, bool):  # must precede the int check — bool is an int subclass
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonical_number(value)
    if isinstance(value, str):
        # ensure_ascii=False: RFC 8785 emits raw UTF-8, not \uXXXX escapes.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, Mapping):
        items = []
        for key in sorted(value.keys(), key=_utf16_sort_key):
            if not isinstance(key, str):
                raise TypeError(f"canonical JSON object keys must be strings, got {type(key).__name__}")
            v = value[key]
            if v is None:
                continue  # absent-vs-null: a None field is omitted, never emitted
            items.append(f"{json.dumps(key, ensure_ascii=False)}:{_dumps(v, set_fields)}")
        return "{" + ",".join(items) + "}"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items_list = list(value)
        # set_fields only meaningfully applies to a named object field, not to an
        # anonymous top-level array — canonicalize() enforces that at the call site.
        return "[" + ",".join(_dumps(v, set_fields) for v in items_list) + "]"
    if value is None:
        if _top:
            return "null"
        raise TypeError("null may only appear as an omitted object field, never inside a list")
    raise TypeError(f"cannot canonicalize value of type {type(value).__name__}")


def canonicalize(payload: Mapping[str, Any], *, set_fields: AbstractSet[str] = frozenset()) -> bytes:
    """Serialize ``payload`` to canonical JSON bytes (RFC 8785 + ADR-0018 §6 axes).

    ``payload`` must be a JSON object (a mapping) — the digest commits to the
    *whole request*, by construction, so there is no meaningful top-level
    array or scalar case here.

    ``set_fields`` names top-level keys whose *list* value has no significant
    order and must therefore be sorted (as canonical-JSON strings, so the sort
    itself is stable and encoding-independent) before hashing. A field not
    named here keeps whatever order its value was given in.
    """
    if not isinstance(payload, Mapping):
        raise TypeError(f"canonicalize() requires a JSON object (mapping), got {type(payload).__name__}")

    def _prepare(value: Any, key: str | None) -> Any:
        if isinstance(value, Mapping):
            return {k: _prepare(v, k) for k, v in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            items = [_prepare(v, None) for v in value]
            if key is not None and key in set_fields:
                items = sorted(items, key=lambda v: _dumps(v, set_fields))
            return items
        return value

    prepared = {k: _prepare(v, k) for k, v in payload.items()}
    return _dumps(prepared, set_fields, _top=True).encode("utf-8")


def compute_digest(payload: Mapping[str, Any], *, set_fields: AbstractSet[str] = frozenset()) -> str:
    """SHA-256 of the canonical form, hex-encoded lowercase (ADR-0018 §6)."""
    return hashlib.sha256(canonicalize(payload, set_fields=set_fields)).hexdigest()
