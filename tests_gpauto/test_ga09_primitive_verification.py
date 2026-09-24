"""`SD11-15`: the two reused primitives are verified against their obligations.

Design basis: AP-11 §14 (`SD11-1`, `SD11-2`, `SD11-15`, `SD11-16a`), §16
(`GP-AUTO-ST-02` discovery-review scope); AP-07 §5.2 (`ID-9`, `ID-11`, `ID-12`,
`ID-13`); RFC 8785 §3.2.2 and §3.2.3; FIPS 180-4.

*"Reuse as-is means after verification against the frozen obligation it is reused
for, never because it exists and looks right."* Each primitive is reused for one
obligation, and is checked against that obligation here using an **independent
oracle** — the published RFC 8785 examples and the FIPS 180 SHA-256 known answers,
written out as expected bytes — rather than against the library it wraps, which would
verify the implementation against itself.

* **`canonical.canonical_bytes`** (`SD11-1`) is reused for `ID-11` — RFC 8785 /
  JCS, produced in one place — and for `EQ-0`'s normal-form serialization. Checked
  here: the RFC 8785 key-sorting and serialization examples; independence from
  insertion order; refusal of what JSON cannot carry; `ID-12`'s pinned version and
  cross-process byte-stability.
* **`digest.digest_of_preimage_bytes`** (`SD11-2`) is reused for `ID-9` — content
  identity is `sha256(canonical_preimage)` — and `ID-10` — bytes hashed as stored.
  Checked here: the FIPS 180 known answers; bytes in, digest out, with no parse; the
  one lowercase wire format.

A primitive that failed here would be replaced by a GP-AUTO module, never modified in
place (`SD11-15`). Neither is modified: GP-AUTO imports them and nothing else.
"""

from __future__ import annotations

import importlib.metadata
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from gplanner.canonical import canonical_bytes
from gplanner.digest import digest_of_preimage_bytes

GPAUTO_STAGE = "GP-AUTO-ST-02"

BS = chr(92)
"""A backslash, built rather than escaped (see `st02_support`)."""

TEST_TREE = Path(__file__).resolve().parent


def _refusal(value: object) -> str | None:
    """The class name of the canonicalizer's refusal, or `None` if it produced bytes.

    Read by name because the class lives in the spike's error module, which `SD11-16`
    keeps inert with respect to GP-AUTO — so it is observed here, never imported.
    """
    try:
        canonical_bytes(value)
    except Exception as exc:
        return type(exc).__name__
    return None


# --- SD11-1: canonical.canonical_bytes ------------------------------------------


@pytest.mark.traces("SD11-1", "SD11-15", "ID-11")
def test_canonical_bytes_reproduces_the_rfc8785_key_sorting_example() -> None:
    """RFC 8785 §3.2.3: properties sort by UTF-16 code unit, not by code point.

    The emoji key is a surrogate pair in UTF-16 and so sorts *before* U+FB33, although
    its code point is larger — the case a hand-rolled canonicalizer usually gets wrong.
    """
    value = {
        chr(0x20AC): "Euro Sign",
        chr(0x0D): "Carriage Return",
        chr(0xFB33): "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        chr(0x1F600): "Emoji: Grinning Face",
        chr(0x80): "Control",
        chr(0xF6): "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"' + BS + 'r":"Carriage Return",'
        '"1":"One",'
        '"' + chr(0x80) + '":"Control",'
        '"' + chr(0xF6) + '":"Latin Small Letter O With Diaeresis",'
        '"' + chr(0x20AC) + '":"Euro Sign",'
        '"' + chr(0x1F600) + '":"Emoji: Grinning Face",'
        '"' + chr(0xFB33) + '":"Hebrew Letter Dalet With Dagesh"}'
    ).encode("utf-8")
    assert canonical_bytes(value) == expected


@pytest.mark.traces("SD11-1", "SD11-15", "ID-11")
def test_canonical_bytes_reproduces_the_rfc8785_serialization_example() -> None:
    """RFC 8785 §3.2.2: ES6 number form, minimal string escaping, literals verbatim."""
    string = (
        chr(0x20AC) + "$" + chr(0x0F) + chr(0x0A) + "A'" + "B" + '"' + BS + BS + '"' + "/"
    )
    value = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": string,
        "literals": [None, True, False],
    }
    expected = (
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"' + chr(0x20AC) + "$" + BS + "u000f" + BS + "nA'B"
        + BS + '"' + BS + BS + BS + BS + BS + '"/"}'
    ).encode("utf-8")
    assert canonical_bytes(value) == expected


@pytest.mark.traces("SD11-1", "SD11-15", "ID-11")
def test_canonical_bytes_does_not_depend_on_insertion_order() -> None:
    """The property content identity rests on: one value, one byte string."""
    forward = {"a": 1, "b": {"x": True, "y": [1, 2]}, "c": "text"}
    backward = {"c": "text", "b": {"y": [1, 2], "x": True}, "a": 1}
    assert canonical_bytes(forward) == canonical_bytes(backward)
    assert canonical_bytes(forward) == b'{"a":1,"b":{"x":true,"y":[1,2]},"c":"text"}'


@pytest.mark.traces("SD11-1", "SD11-15")
@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), {"key": chr(0xD800)}, {chr(0xD800): "value"}, {1: "int key"}],
    ids=["nan", "infinity", "lone-surrogate-value", "lone-surrogate-key", "non-string-key"],
)
def test_canonical_bytes_refuses_what_json_cannot_carry(value: object) -> None:
    """Fail-closed: a value JCS cannot represent is refused, never approximated.

    A lone-surrogate *key* is the case the spike recorded fixing (`canonical.py`): the
    library encodes keys to UTF-16 to sort them outside its own error handling. Both
    placements are checked, because the reuse is only as good as the worst one.
    """
    assert _refusal(value) == "CanonicalizationError"


@pytest.mark.traces("SD11-1", "SD11-15", "ID-12")
def test_the_canonicalizer_is_the_version_byte_stability_is_claimed_for() -> None:
    """`ID-12`: byte-stability is claimed **only** for `rfc8785 0.1.4`.

    The claim is version-specific and does not transfer (limitation 10). If the
    environment carried another version the claim would not hold here, and this test
    says so rather than letting the rest of the suite imply it.
    """
    assert importlib.metadata.version("rfc8785") == "0.1.4"


_STABILITY_PROBE = """
import sys
sys.path.insert(0, {tree!r})
import st02_support
from gpauto import content_identity, equivalence
from gplanner.canonical import canonical_bytes
preimage = content_identity.stage_contract_preimage(st02_support.stage_contract_content())
normal = canonical_bytes(equivalence._normal_form(st02_support.permuted().content))
print(preimage.hex())
print(normal.hex())
"""


@pytest.mark.supports("ID-7")
@pytest.mark.traces("SD11-1", "SD11-15", "ID-12")
def test_canonical_bytes_are_byte_identical_across_processes_and_hash_seeds() -> None:
    """The pre-named failure *"JCS output is not byte-stable across processes"*, re-run.

    GP-SPK-001 recorded that it did not occur for `rfc8785 0.1.4`; here it is checked
    again over **GP-AUTO's own** outputs — a content preimage and an equivalence normal
    form built from reversed, repeated set members — in processes launched with
    different `PYTHONHASHSEED`s, so set and dict iteration order genuinely differ.
    """
    probe = _STABILITY_PROBE.format(tree=str(TEST_TREE))
    outputs = []
    for seed in ("0", "1", "4242"):
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=True,
        )
        outputs.append(completed.stdout)
    assert outputs[0].strip()
    assert outputs[0] == outputs[1] == outputs[2]


# --- SD11-2: digest.digest_of_preimage_bytes --------------------------------------


@pytest.mark.traces("SD11-2", "SD11-15", "ID-9")
def test_digest_of_preimage_bytes_matches_the_fips_180_known_answers() -> None:
    """SHA-256 of `"abc"` and of the empty string, as FIPS 180 publishes them."""
    assert digest_of_preimage_bytes(b"abc") == (
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert digest_of_preimage_bytes(b"") == (
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


@pytest.mark.traces("SD11-2", "SD11-15", "ID-10", "ID-13")
def test_digest_of_preimage_bytes_hashes_the_bytes_exactly_as_given() -> None:
    """`ID-10`: bytes in, digest out — no parse, no normalization, no re-encode.

    It accepts bytes that are not JSON at all, and two JSON texts that decode to the
    same value but differ in insignificant whitespace hash differently. That second
    fact is limitation 9, and it is why a stored-bytes digest is never a test of
    semantic sameness (`ID-13`).
    """
    assert digest_of_preimage_bytes(b"\xff\xfe not json")
    assert digest_of_preimage_bytes(b'{"a":1}') != digest_of_preimage_bytes(b'{"a": 1}')


@pytest.mark.traces("SD11-2", "SD11-15", "ID-9")
def test_digest_of_preimage_bytes_uses_one_lowercase_wire_format() -> None:
    """`sha256:` + 64 lowercase hex: one spelling per identity, never two."""
    value = digest_of_preimage_bytes(b"content")
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
