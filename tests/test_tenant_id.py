# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0019 — opaque tenant identifiers, minted rather than derived.

The tool this replaces (``tools/tenant_namespace.py``) had no tests, which is part of why
its cost was easy to underestimate. These pin the properties that make the replacement safe:
the identifier is random, it is valid in every place ADR-0019 §1 puts it, and the namespace is
a prefix rather than a computation.
"""

from __future__ import annotations

import re

import pytest

from tools.tenant_id import (
    ID_BYTES,
    PREFIX,
    is_valid_tenant_id,
    main,
    namespace_for,
    new_tenant_id,
)

# Independent of the module's own pattern. Asserting against `tools.tenant_id._TENANT_ID`
# would restate the implementation and agree with it however it changed.
_SHAPE = re.compile(r"^t-[0-9a-f]{16}$")
_DNS1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


# --- Minting -----------------------------------------------------------------


def test_a_minted_id_has_the_expected_shape():
    assert _SHAPE.match(new_tenant_id())


def test_minted_ids_do_not_repeat():
    """Randomness, stated as the observable property rather than by inspecting the source.

    Not a statistical test — 500 draws from 64 bits collide with probability ~7e-15, so a
    duplicate here means the identifier is derived, seeded or counted, which is exactly the
    regression ADR-0019 §1 exists to prevent.
    """
    minted = {new_tenant_id() for _ in range(500)}
    assert len(minted) == 500


def test_a_minted_id_is_valid_in_every_place_it_appears():
    """§1 puts the identifier in namespace names and hostnames; both are DNS-1123 labels.

    This is the check that would have caught the ADR's first draft, which specified
    ``t_7f3a91c4``. An underscore is valid in neither, and the failure would have surfaced as
    a rejected namespace at apply time and a certificate no CA would issue.
    """
    tid = new_tenant_id()
    assert _DNS1123.match(tid), f"{tid} is not a valid DNS-1123 label"
    assert _DNS1123.match(namespace_for(tid))
    assert len(namespace_for(tid)) <= 63


# --- Validation --------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "t_3f9a1c2b7d4e8065",  # underscore: the format the ADR originally specified
        "T-3f9a1c2b7d4e8065",  # uppercase is not a DNS-1123 label
        "t-3F9A1C2B7D4E8065",  # uppercase hex, same reason
        "t-3f9a1c2b",  # too short
        "t-3f9a1c2b7d4e8065aa",  # too long
        "t-3f9a1c2b7d4e806g",  # 'g' is not hex
        "3f9a1c2b7d4e8065",  # unprefixed
        "mcp-t-3f9a1c2b7d4e8065",  # the namespace, not the identifier
        "acme-corp",  # a customer name — the thing this design keeps out of clusters
    ],
)
def test_invalid_identifiers_are_refused(bad):
    assert not is_valid_tenant_id(bad)


def test_a_minted_id_validates():
    """The pair that matters: the thing we mint is the thing we accept.

    Kept separate from the shape test because a generator and a validator drifting apart is
    the failure that shows up only when a second tool is written against one of them.
    """
    assert is_valid_tenant_id(new_tenant_id())


# --- Namespace ---------------------------------------------------------------


def test_namespace_is_a_prefix_not_a_derivation():
    """No key, no HMAC, no truncation — the namespace is readable off the identifier.

    Asserted as string containment rather than equality against a recomputed value, because
    recomputing it here is what the old design forced every consumer to do.
    """
    tid = "t-3f9a1c2b7d4e8065"
    assert namespace_for(tid) == "mcp-" + tid
    assert tid in namespace_for(tid)


def test_namespace_refuses_anything_that_is_not_an_identifier():
    """Fails closed on a customer name, which the old tool would happily have hashed.

    The old tool accepted *any* string, because its whole job was to obscure whatever it was
    given. This one has no obscuring to do, so an unrecognised value is a mistake rather than
    an input.
    """
    for bad in ("acme-corp", "t_3f9a1c2b7d4e8065", ""):
        with pytest.raises(ValueError):
            namespace_for(bad)


# --- CLI ---------------------------------------------------------------------


def test_cli_new_prints_a_usable_identifier(capsys):
    assert main(["new"]) == 0
    assert is_valid_tenant_id(capsys.readouterr().out.strip())


def test_cli_check_accepts_and_rejects(capsys):
    assert main(["check", "t-3f9a1c2b7d4e8065"]) == 0
    assert main(["check", "acme-corp"]) == 2
    assert "not a valid tenant identifier" in capsys.readouterr().err


def test_cli_namespace_with_labels(capsys):
    assert main(["namespace", "t-3f9a1c2b7d4e8065", "--label"]) == 0
    out = capsys.readouterr().out
    assert "namespace: mcp-t-3f9a1c2b7d4e8065" in out
    assert "mcp.gateway/plane: tenant" in out
    # The label value is the suffix without the prefix — what the Cilium selectors match on.
    assert "mcp.gateway/tenant: 3f9a1c2b7d4e8065" in out


def test_cli_namespace_refuses_a_bad_identifier(capsys):
    assert main(["namespace", "acme-corp"]) == 2
    assert "not a tenant identifier" in capsys.readouterr().err


def test_the_id_bytes_constant_and_the_pattern_agree():
    """A width change must move both, or validation silently rejects everything minted.

    They are defined in the same module and read as obviously linked, which is exactly when
    an edit updates one of them.
    """
    assert len(new_tenant_id()) == len(PREFIX) + ID_BYTES * 2
