"""GP-02 — canonicalization.

Design basis: design/GP-SPK-001-governance-kernel.md §5, §13.1 requirement 2.

Two layers, tested in two separated sections because the separation is the point:

* **Section A — `canonical.canonical_bytes`** is genuine RFC 8785 / JCS and contains
  **no governed-planner policy**. It accepts every valid JSON value, finite floats and
  `null` included, and refuses only things that are not JSON.
* **Section B — `profile.refuse_outside_profile`** is the named, versioned application
  policy `gplanner.payload-profile/1`. It refuses two values JCS accepts perfectly
  well: floats and `null`.

The load-bearing proof is that a float and a `null` pass Section A and fail Section B.
If those ever collapsed into one layer, "RFC 8785" would silently come to mean "our
subset of it", and an external verifier reading `preimage_version` would compute a
different digest than we do.

Every expected byte string below was measured against the installed rfc8785 0.1.4
before being asserted; none is predicted from the specification text.
"""

from __future__ import annotations

import inspect
import os
import subprocess
import sys

import pytest

from gplanner.canonical import canonical_bytes
from gplanner.errors import (
    CanonicalizationError,
    GovernedPlannerError,
    PayloadProfileViolation,
)
from gplanner.profile import PAYLOAD_PROFILE, refuse_outside_profile

# --- Section A: RFC 8785 / JCS, policy-free --------------------------------------


def test_utf16_code_unit_key_ordering_including_the_non_bmp_case() -> None:
    """JCS sorts keys by UTF-16 code unit, not by scalar value.

    A non-BMP key begins with a surrogate (U+D800..U+DBFF), so it sorts *before*
    U+FFF0 -- the opposite of scalar-value order. This is the exact case where the
    sibling governed-runtime's hand-rolled serializer disagrees with JCS, which is
    why governed-planner uses one implementation and pins its behaviour here.
    """
    out = canonical_bytes({"\U0001f600": 1, "￰": 2})
    assert out == b'{"\xf0\x9f\x98\x80":1,"\xef\xbf\xb0":2}'
    assert out.index("\U0001f600".encode()) < out.index("￰".encode())


def test_keys_are_sorted_not_left_in_insertion_order() -> None:
    assert canonical_bytes({"b": 1, "a": 2, "A": 3, "0": 4}) == b'{"0":4,"A":3,"a":2,"b":1}'


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1.0, b"1"),
        (100.0, b"100"),
        (1e-7, b"1e-7"),
        (1e21, b"1e+21"),
        (1, b"1"),
        (-0.5, b"-0.5"),
    ],
    ids=["1.0", "100.0", "1e-7", "1e+21", "int", "negative"],
)
def test_numeric_normalization(value: float | int, expected: bytes) -> None:
    """`1.0` serializes as `1`: JCS has one number space, not two.

    This collapse is exactly why `gplanner.payload-profile/1` forbids floats in a
    content-addressed payload (Section B) -- two distinct Python values would
    otherwise share one identity.
    """
    assert canonical_bytes(value) == expected


def test_finite_floats_are_accepted_by_the_canonicalizer() -> None:
    """Policy-free: the JCS layer has no opinion about floats."""
    assert canonical_bytes({"ratio": 0.25}) == b'{"ratio":0.25}'


def test_null_is_accepted_by_the_canonicalizer() -> None:
    """Policy-free: `null` is a valid JSON value."""
    assert canonical_bytes(None) == b"null"
    assert canonical_bytes({"a": None}) == b'{"a":null}'


def test_booleans() -> None:
    assert canonical_bytes([True, False]) == b"[true,false]"


def test_nested_objects_and_arrays() -> None:
    value = {"b": [1, {"a": None}], "a": {"z": [], "y": {}}}
    assert canonical_bytes(value) == b'{"a":{"y":{},"z":[]},"b":[1,{"a":null}]}'


def test_minimal_escaping() -> None:
    """Only what JSON requires, with control characters as \\uXXXX."""
    out = canonical_bytes("quote\" back\\ nl\n tab\t ctrl\x01")
    assert out == b'"quote\\" back\\\\ nl\\n tab\\t ctrl\\u0001"'


def test_non_ascii_is_emitted_as_utf8_not_escaped() -> None:
    out = canonical_bytes({"café": "naïve — 日本"})
    assert out == '{"café":"naïve — 日本"}'.encode()
    assert b"\\u" not in out


def test_repeated_serialization_is_byte_identical() -> None:
    value = {"z": [1, 2, 3], "a": {"k": "v"}, "m": True}
    first = canonical_bytes(value)
    assert all(canonical_bytes(value) == first for _ in range(20))


def test_serialization_is_byte_identical_across_a_different_hash_seed() -> None:
    """The check that actually catches dict-ordering leaks.

    Within one process, insertion order is stable and can mask a serializer that
    never sorted at all. A fresh interpreter with a different `PYTHONHASHSEED` is
    what makes the ordering claim testable.
    """
    program = (
        "from gplanner.canonical import canonical_bytes\n"
        "v = {'zz': 1, 'aa': 2, 'mm': 3, 'b': [1, {'q': None}], 'caf\\u00e9': True}\n"
        "print(canonical_bytes(v).hex())\n"
    )

    def run(seed: str) -> str:
        env = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=True,
        )
        return result.stdout.strip()

    assert run("0") == run("12345") == canonical_bytes(
        {"zz": 1, "aa": 2, "mm": 3, "b": [1, {"q": None}], "café": True}
    ).hex()


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        b"bytes",
        {1, 2},
        object(),
        1 + 2j,
        2**64,
    ],
    ids=["nan", "inf", "-inf", "bytes", "set", "object", "complex", "huge-int"],
)
def test_non_json_values_are_refused_not_coerced(value: object) -> None:
    """Refusal, never silent coercion.

    A coercion would make identity depend on the coercion rule rather than on the
    content. `2**64` is included because JCS bounds integers to the range JSON
    numbers represent exactly; a silently rounded integer is a changed identity.
    """
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


@pytest.mark.parametrize("key", [1, None, (1, 2)], ids=["int", "none", "tuple"])
def test_non_string_object_keys_are_refused(key: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_bytes({key: "value"})


def test_the_refusal_is_a_governed_planner_error_not_a_library_error() -> None:
    """Adapters translate their failures into this package's vocabulary.

    `rfc8785` raises its own `CanonicalizationError`, a `ValueError`, whose name
    collides with ours. A caller must be able to catch `gplanner.errors`
    consistently without importing the serializer or knowing it exists.
    """
    import rfc8785

    with pytest.raises(CanonicalizationError) as excinfo:
        canonical_bytes(object())
    assert not isinstance(excinfo.value, rfc8785.CanonicalizationError)
    assert isinstance(excinfo.value.__cause__, rfc8785.CanonicalizationError)


def test_a_lone_surrogate_object_key_is_refused_through_the_public_contract() -> None:
    """ST3-R01: an encoding failure must not escape as a raw library exception.

    JCS orders keys by UTF-16 code unit, so `rfc8785` encodes each key to `utf-16-be`
    to sort it. A lone surrogate is unencodable there, and that encode happens outside
    the library's own error handling -- so it raised `UnicodeEncodeError` straight
    through `canonical_bytes`, past the translation that every other refusal goes
    through.

    A lone surrogate reaches this layer easily: it survives `str` construction, JSON
    parsing with `surrogatepass`, and any round trip that never re-encodes to UTF-8.
    A caller catching `gplanner.errors` would have missed it entirely.

    Note the asymmetry the fix has to cover -- a lone surrogate in a *value* was
    already translated correctly, because values take a different code path inside the
    library. Only the key path leaked.
    """
    with pytest.raises(CanonicalizationError) as excinfo:
        canonical_bytes({"\ud800": 1})

    assert not isinstance(excinfo.value, UnicodeEncodeError), (
        "the encoding failure escaped as the public exception"
    )
    assert isinstance(excinfo.value.__cause__, UnicodeEncodeError), (
        "the underlying cause must stay reachable for diagnosis"
    )


def test_a_lone_surrogate_value_is_refused_the_same_way() -> None:
    """The value path already translated; asserted so the fix cannot regress it."""
    with pytest.raises(CanonicalizationError) as excinfo:
        canonical_bytes({"key": "\udfff"})
    assert excinfo.value.__cause__ is not None



# --- Section B: gplanner.payload-profile/1, application policy -------------------


def test_the_profile_is_named_and_versioned() -> None:
    """Recorded inside every hashed preimage, so a verifier knows which subset ran."""
    assert PAYLOAD_PROFILE == "gplanner.payload-profile/1"


@pytest.mark.parametrize(
    "value",
    [
        {"key": "string"},
        ["array", "of", "strings"],
        "bare string",
        True,
        False,
        42,
        -7,
        0,
        {"nested": {"deep": [1, {"ok": "yes"}]}},
        {},
        [],
    ],
    ids=[
        "object", "array", "string", "true", "false", "int", "negative-int",
        "zero", "nested", "empty-object", "empty-array",
    ],
)
def test_the_profile_permits_the_declared_value_space(value: object) -> None:
    refuse_outside_profile(value)  # must not raise


# The two refusals. Each is a value JCS accepts perfectly well.


def test_a_float_passes_jcs_but_fails_the_profile() -> None:
    """The load-bearing separation, stated as one test.

    JCS serializes `1.0` as `1`, so two distinct Python values would map to a single
    identity. governed-planner rejects rather than accept that collapse -- but the
    rejection is *ours*, not the specification's, which is why it lives in a
    different module and is named and versioned separately.
    """
    assert canonical_bytes(1.0) == b"1"  # JCS: accepted, and normalized
    assert canonical_bytes(1) == b"1"  # ...to the same bytes as this
    with pytest.raises(PayloadProfileViolation):
        refuse_outside_profile(1.0)


def test_null_passes_jcs_but_fails_the_profile() -> None:
    """An absent key and a `null` key hash differently.

    Permitting `null` would make identity depend on whether a serializer emitted or
    omitted an empty field, which is a configuration detail rather than content.
    """
    assert canonical_bytes(None) == b"null"  # JCS: accepted
    with pytest.raises(PayloadProfileViolation):
        refuse_outside_profile(None)


@pytest.mark.parametrize(
    "value",
    [0.0, 1.0, -2.5, 1e-7],
    ids=["zero-float", "integral-float", "negative-float", "small-float"],
)
def test_every_float_is_refused_including_integral_ones(value: float) -> None:
    """`1.0` is the dangerous case precisely because it looks harmless."""
    with pytest.raises(PayloadProfileViolation):
        refuse_outside_profile(value)


@pytest.mark.parametrize(
    "value",
    [
        {"a": 1.0},
        {"a": None},
        [1.0],
        [None],
        {"deep": {"deeper": [1, 2.5]}},
        {"deep": {"deeper": [1, None]}},
        [[[None]]],
    ],
    ids=[
        "float-in-object", "null-in-object", "float-in-array", "null-in-array",
        "float-nested", "null-nested", "null-deeply-nested",
    ],
)
def test_the_profile_walks_the_whole_value_not_just_its_surface(value: object) -> None:
    with pytest.raises(PayloadProfileViolation):
        refuse_outside_profile(value)


def test_a_non_string_object_key_is_refused() -> None:
    with pytest.raises(PayloadProfileViolation):
        refuse_outside_profile({1: "int key"})


def test_a_bool_is_not_treated_as_an_integer() -> None:
    """`bool` subclasses `int` in Python; both are permitted, so this is a guard
    against the profile accepting a float by the same loose reasoning."""
    refuse_outside_profile(True)
    refuse_outside_profile(1)
    with pytest.raises(PayloadProfileViolation):
        refuse_outside_profile(1.0)


def test_a_profile_violation_is_a_governed_planner_error() -> None:
    assert issubclass(PayloadProfileViolation, GovernedPlannerError)
    assert not issubclass(PayloadProfileViolation, CanonicalizationError), (
        "a profile refusal is not a canonicalization failure; the value is valid JSON"
    )


def test_the_profile_does_not_serialize() -> None:
    """`profile.py` must not grow a second path to canonical bytes (§5)."""
    import gplanner.profile as profile_module

    source = inspect.getsource(profile_module)
    assert "rfc8785" not in source
    assert "canonical_bytes" not in source
