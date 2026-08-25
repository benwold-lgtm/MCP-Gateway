# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0018 §6 — canonical JSON digesting.

The two axes RFC 8785 leaves open are the load-bearing tests here: absent-vs-null
normalization and declared set-valued field sorting. Both exist because a digest whose
inputs re-serialize differently is a spurious refusal under real client variation, not a
theoretical concern — a browser form and a CLI script disagree on whether to send an
unset field as ``null`` or omit it, and neither is wrong.
"""

from __future__ import annotations

import hashlib

import pytest

from device_mcp_gateway.shared.canonical_json import canonicalize, compute_digest


def test_object_keys_are_sorted():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_absent_and_explicit_null_produce_the_same_digest():
    with_null = canonicalize({"archive": "x", "passphrase": None})
    omitted = canonicalize({"archive": "x"})
    assert with_null == omitted == b'{"archive":"x"}'


def test_null_is_never_emitted():
    out = canonicalize({"a": 1, "b": None, "c": 2})
    assert b"null" not in out


def test_declared_set_field_is_sorted_before_hashing():
    forward = canonicalize({"tags": ["c", "a", "b"]}, set_fields={"tags"})
    reverse = canonicalize({"tags": ["b", "c", "a"]}, set_fields={"tags"})
    assert forward == reverse == b'{"tags":["a","b","c"]}'


def test_undeclared_list_field_keeps_its_order():
    forward = canonicalize({"items": ["a", "b"]})
    reverse = canonicalize({"items": ["b", "a"]})
    assert forward != reverse


def test_a_field_not_declared_set_valued_is_not_silently_sorted_even_if_named_similarly():
    # Declaring "tags" must not accidentally catch an unrelated list-valued field.
    out = canonicalize({"tags": ["b", "a"], "other": ["z", "y"]}, set_fields={"tags"})
    assert out == b'{"other":["z","y"],"tags":["a","b"]}'


def test_integers_and_integral_floats_canonicalize_identically():
    assert canonicalize({"n": 3}) == canonicalize({"n": 3.0}) == b'{"n":3}'


def test_bool_is_not_confused_with_int():
    # bool is an int subclass in Python; True must not canonicalize as "1".
    assert canonicalize({"flag": True}) == b'{"flag":true}'
    assert canonicalize({"flag": False}) == b'{"flag":false}'


def test_non_ascii_is_emitted_as_raw_utf8_not_escaped():
    out = canonicalize({"name": "café"})
    assert out == '{"name":"café"}'.encode("utf-8")
    assert b"\\u" not in out


def test_nested_structures_canonicalize_recursively():
    a = canonicalize({"outer": {"z": 1, "a": [3, 1, 2]}})
    b = canonicalize({"outer": {"a": [3, 1, 2], "z": 1}})
    assert a == b == b'{"outer":{"a":[3,1,2],"z":1}}'


def test_digest_is_stable_under_key_reorder_and_null_omission():
    digest1 = compute_digest({"archive": "abc", "dry_run": True, "on_conflict": "skip", "passphrase": None})
    digest2 = compute_digest({"dry_run": True, "passphrase": None, "on_conflict": "skip", "archive": "abc"})
    digest3 = compute_digest({"on_conflict": "skip", "archive": "abc", "dry_run": True})
    assert digest1 == digest2 == digest3


def test_digest_changes_when_a_value_actually_changes():
    base = compute_digest({"archive": "abc", "on_conflict": "skip"})
    changed = compute_digest({"archive": "abc", "on_conflict": "overwrite"})
    assert base != changed


def test_digest_is_a_lowercase_hex_sha256():
    digest = compute_digest({"archive": "abc"})
    assert len(digest) == 64
    assert digest == digest.lower()
    int(digest, 16)  # raises if not valid hex


def test_digest_matches_a_manual_sha256_of_the_canonical_bytes():
    payload = {"archive": "abc", "on_conflict": "skip", "dry_run": False}
    expected = hashlib.sha256(canonicalize(payload)).hexdigest()
    assert compute_digest(payload) == expected


def test_top_level_must_be_a_mapping():
    with pytest.raises(TypeError):
        canonicalize(["not", "an", "object"])  # type: ignore[arg-type]


def test_null_inside_a_list_is_rejected_rather_than_silently_kept():
    # The absent-vs-null rule is about optional object *fields*; a list has no such
    # concept, so a None element is a caller bug, not something to paper over.
    with pytest.raises(TypeError):
        canonicalize({"items": ["a", None, "b"]})
