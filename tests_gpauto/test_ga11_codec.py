"""The codec: one JSON → domain boundary, one parse of the stored bytes, no round trip.

Design basis: AP-07 §23.1 (`DC-1`…`DC-4`), §5.2 (`ID-10`, `ID-13`), §23 (`VM-3`,
`VM-11`); AP-03 §4.3 rule 1; AP-11 §8 (`MU11-5`), §14 (`SD11-4`), §16
(`GP-AUTO-ST-02` negative tests).

Two of the contract's negative tests are here — *a re-serialization round trip is not
treated as identity* (`DC-4`) and *a format version is never read as recency or
precedence* (`VM-11`) — together with the refusals that make the decode path's guard
**model-enforced** (`MU11-5`). Each refusal the decode-path guard's schema mutants are
killed by is its own test, so the mutation evidence can name exactly one killing test
per mutant (`MU11-7`, `test_ga13`).

The malformed inputs are written as bytes by hand. This test tree imports no `json`
module — the GP-AUTO decode/import gate covers it too — and a hand-written byte string
also says exactly which bytes are under test.
"""

from __future__ import annotations

import ast

import pytest
from pydantic import ValidationError

import decode_gate
import st02_support
from gate_scope import REPOSITORY_ROOT, configured_package_path
from gpauto import codec
from gpauto.content_identity import (
    identify_artifact_content,
    identify_stage_contract,
    stage_contract_preimage,
)
from gpauto.identity import StageContractId
from gpauto.preimage import StageContractContent
from gplanner.digest import digest_of_preimage_bytes

GPAUTO_STAGE = "GP-AUTO-ST-02"

VERSION = b"gpauto.content-preimage/1+jcs-rfc8785"


def _stage_envelope(
    *,
    version: bytes = VERSION,
    content_class: bytes = b"STAGE_CONTRACT",
    content_encoding: bytes = b"TEXT",
    content: bytes | None = None,
    extra: bytes = b"",
) -> bytes:
    """A stage-contract preimage written by hand — valid unless an argument says not.

    Member order and separators deliberately differ from RFC 8785's, so a decode of
    this is a decode of **non-canonical** bytes.
    """
    body = (
        st02_support.stage_contract_content().model_dump_json().encode("utf-8")
        if content is None
        else content
    )
    return (
        b'{"preimage_version": "' + version + b'", "content_class": "' + content_class
        + b'", "content_encoding": "' + content_encoding
        + b'", "content": ' + body + extra + b"}"
    )


def _record_json() -> str:
    return st02_support.record().model_dump_json()


# --- The one path ----------------------------------------------------------------


@pytest.mark.traces("ST02-D3", "DC-1", "SD11-4")
def test_decode_is_one_json_aware_parse_of_the_stored_bytes() -> None:
    """Arrays arrive as tuples with strict member checking kept, through one parse."""
    identified = identify_stage_contract(st02_support.stage_contract_content())
    decoded = codec.decode_stage_contract(identified.canonical_preimage)
    assert decoded.identity == identified.identity
    assert isinstance(decoded.deliverable_boundary, tuple)
    assert decoded.deliverable_boundary == ("deliverable-a", "deliverable-b")

    artifact = identify_artifact_content(b"captured text")
    content, recovered = codec.decode_artifact_content(artifact.canonical_preimage)
    assert content.identity == artifact.identity
    assert recovered == b"captured text"


@pytest.mark.traces("DC-1")
def test_an_authorization_record_decodes_identically_from_str_and_bytes() -> None:
    """Pydantic accepts both; neither is decoded differently."""
    text = _record_json()
    assert codec.decode_authorization_record(text) == codec.decode_authorization_record(
        text.encode("utf-8")
    )
    assert codec.decode_authorization_record(text) == st02_support.record()


# --- DC-4: a re-serialization round trip is not identity -------------------------


@pytest.mark.traces("ST02-N2", "DC-4", "ID-10", "ID-13")
def test_a_re_serialization_round_trip_is_not_treated_as_identity() -> None:
    """Decode is not injective, so identity comes from the bytes and never the object.

    A valid but non-canonical preimage decodes to exactly the content the canonical one
    does. Its identity is the digest of **its own** bytes. Re-serializing what was
    decoded would reproduce the canonical bytes — and therefore the canonical identity
    — silently repairing the drift; the codec does not do that, so the two identities
    stay different and the drift stays visible (`ID-10`).
    """
    content = st02_support.stage_contract_content()
    canonical = identify_stage_contract(content)
    variant = _stage_envelope()
    assert variant != canonical.canonical_preimage

    from_canonical = codec.decode_stage_contract(canonical.canonical_preimage)
    from_variant = codec.decode_stage_contract(variant)

    parts = tuple(StageContractContent.model_fields)
    assert [getattr(from_variant, p) for p in parts] == [getattr(from_canonical, p) for p in parts]
    assert from_variant.identity == StageContractId(value=digest_of_preimage_bytes(variant))
    assert from_variant.identity != from_canonical.identity

    round_tripped = stage_contract_preimage(
        StageContractContent(**{p: getattr(from_variant, p) for p in parts})
    )
    assert round_tripped == canonical.canonical_preimage
    assert round_tripped != variant


@pytest.mark.traces("ST02-N2", "DC-4", "ID-10", "SD11-4")
def test_the_codec_holds_no_serializer_and_no_hash() -> None:
    """Read from the syntax tree: nothing on the read path can re-derive bytes.

    No `json`, no `rfc8785`, no `hashlib`; no `model_dump*`, `dumps` or `loads`; no
    `canonical_bytes`, no digest function; and no `model_validate`. Identity is taken
    from `content_identity`, which hashes the bytes it is handed and nothing else.
    """
    tree = ast.parse((configured_package_path() / "codec.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, ast.Name):
            names.append(node.id)

    assert imported == {
        "__future__",
        "gpauto.authorization",
        "gpauto.content_identity",
        "gpauto.evidence",
        "gpauto.preimage",
        "gpauto.scope_frame",
    }
    assert names.count("model_validate_json") == 3, "one parse per decoder"
    forbidden = {"model_validate", "dumps", "loads", "canonical_bytes", "sha256", "hashlib"}
    assert not forbidden & set(names)
    assert not [name for name in names if name.startswith("model_dump")]
    assert not [name for name in names if name.startswith("digest")]


# --- The decode-path guard's refusals (model-enforced, MU11-5) -------------------


@pytest.mark.traces("DC-3", "EQ-2")
def test_an_undeclared_envelope_field_is_refused_never_dropped() -> None:
    """`extra="forbid"` on the envelope: refused outright, not accepted and discarded."""
    with pytest.raises(ValidationError) as caught:
        codec.decode_stage_contract(_stage_envelope(extra=b', "issued_at": "2026-09-23"'))
    assert [error["type"] for error in caught.value.errors()] == ["extra_forbidden"]


@pytest.mark.traces("DC-3", "EQ-2")
def test_an_undeclared_content_field_is_refused_never_dropped() -> None:
    """Closure holds inside the content too — configuration is per class (`codec.py`)."""
    body = st02_support.stage_contract_content().model_dump_json().encode("utf-8")
    widened = body[:-1] + b', "rationale": "prose"}'
    with pytest.raises(ValidationError) as caught:
        codec.decode_stage_contract(_stage_envelope(content=widened))
    assert [error["type"] for error in caught.value.errors()] == ["extra_forbidden"]


@pytest.mark.traces("DC-3", "EQ-2")
def test_an_undeclared_authorization_record_field_is_refused_never_dropped() -> None:
    """AP-03 §4.3 rule 1: unenumerated content is authority-bearing, so it is refused.

    A record that silently dropped a field it did not recognize would decide an
    authority question by discarding it.
    """
    widened = '{"expires_at":"2026-09-23T00:00:00Z",' + _record_json()[1:]
    with pytest.raises(ValidationError) as caught:
        codec.decode_authorization_record(widened)
    assert [error["type"] for error in caught.value.errors()] == ["extra_forbidden"]


@pytest.mark.traces("ST02-N4", "VM-11")
@pytest.mark.parametrize(
    "version",
    [b"gpauto.content-preimage/2+jcs-rfc8785", b"gpauto.content-preimage/0+jcs-rfc8785"],
    ids=["higher", "lower"],
)
def test_a_preimage_under_another_format_version_is_refused_either_way(version: bytes) -> None:
    """`VM-11`, observed from both sides: a higher version is not newer, a lower one is
    not older. Each is simply a scheme the running definition does not cover."""
    with pytest.raises(ValidationError) as caught:
        codec.decode_stage_contract(_stage_envelope(version=version))
    assert [error["loc"] for error in caught.value.errors()] == [("preimage_version",)]


@pytest.mark.traces("ST02-N4", "VM-11")
def test_a_higher_format_version_is_refused_not_preferred() -> None:
    """`VM-11`: a higher-versioned preimage is not newer, not preferred, not superseding.

    Offered alongside a valid one, it is not taken in its place: it is refused, and the
    valid one decodes exactly as it would have alone. The version is a format tag and
    nothing reads it as an order.
    """
    current = identify_stage_contract(st02_support.stage_contract_content())
    newer = current.canonical_preimage.replace(b"content-preimage/1+", b"content-preimage/2+")
    assert newer != current.canonical_preimage
    with pytest.raises(ValidationError):
        codec.decode_stage_contract(newer)
    assert codec.decode_stage_contract(current.canonical_preimage).identity == current.identity


@pytest.mark.traces("ID-2", "DC-3")
def test_a_stage_contract_preimage_labelled_as_another_class_is_refused() -> None:
    """Well-formed stage-contract content under the wrong class tag is not decoded.

    The content alone would validate, so only the class tag refuses it — which is the
    domain separation `ID-2`'s two classes need on the read side.
    """
    with pytest.raises(ValidationError) as caught:
        codec.decode_stage_contract(_stage_envelope(content_class=b"ARTIFACT_CONTENT"))
    assert [error["loc"] for error in caught.value.errors()] == [("content_class",)]


@pytest.mark.traces("ID-2", "DC-3")
def test_an_artifact_preimage_labelled_as_another_class_is_refused() -> None:
    """Artifact text under the stage-contract tag is not decoded as artifact content."""
    mislabelled = (
        b'{"content":"74657874","content_class":"STAGE_CONTRACT",'
        b'"content_encoding":"BASE16_LOWER","preimage_version":"' + VERSION + b'"}'
    )
    with pytest.raises(ValidationError) as caught:
        codec.decode_artifact_content(mislabelled)
    assert [error["loc"] for error in caught.value.errors()] == [("content_class",)]


@pytest.mark.traces("DC-1", "DC-3")
def test_a_scalar_is_not_coerced_on_the_json_path() -> None:
    """Strict on the JSON path: the string `"true"` is not the boolean `true`."""
    loosened = _record_json().replace(
        '"owner_human_label_present":true', '"owner_human_label_present":"true"'
    )
    assert loosened != _record_json()
    with pytest.raises(ValidationError) as caught:
        codec.decode_authorization_record(loosened)
    assert [error["type"] for error in caught.value.errors()] == ["bool_type"]


@pytest.mark.traces("DC-1")
def test_bytes_that_are_not_json_are_refused() -> None:
    """Invalid UTF-8 and truncated JSON are refused by the parse itself."""
    for payload in (b"\xff\xfe", b'{"preimage_version": '):
        with pytest.raises(ValidationError):
            codec.decode_stage_contract(payload)


# --- The boundary is the only one ------------------------------------------------


@pytest.mark.traces("ST02-A3", "ST02-N1", "DC-1", "DC-2")
def test_the_codec_is_the_only_json_to_domain_boundary_in_the_package() -> None:
    """`DC-1`: every JSON → domain conversion in GP-AUTO lives in the codec.

    The GP-AUTO decode/import gate — the existing gate, with the codec-boundary rule
    this stage makes load-bearing — reports no finding over the configured scope: no
    `json` importer anywhere, no `model_validate` anywhere, and no JSON decode in any
    production module other than the codec.
    """
    inspected, findings = decode_gate.offenders()
    assert findings == ()
    codec_path = (configured_package_path() / "codec.py").relative_to(REPOSITORY_ROOT)
    assert codec_path in inspected

    decoders = {
        relative
        for relative in inspected
        if relative.parts[:2] == ("src", "gpauto")
        and "model_validate_json"
        in {
            node.attr
            for node in ast.walk(ast.parse((REPOSITORY_ROOT / relative).read_text("utf-8")))
            if isinstance(node, ast.Attribute)
        }
    }
    assert decoders == {codec_path}


@pytest.mark.supports("RC-21")
@pytest.mark.traces("VM-11", "DC-3", "ST02-N4")
def test_an_artifact_preimage_under_another_content_encoding_is_refused() -> None:
    """The encoding tag is format information, and a foreign one is not decoded.

    `content_encoding` says how to recover the bytes the envelope names. A payload
    labelled with an encoding this scheme does not define is refused outright: decoding
    it under base-16 anyway would recover bytes nobody wrote, and preferring or ranking
    the tag would read format information as recency (`VM-11`).
    """
    for foreign in (b"BASE64", b"TEXT", b"base16_lower", b""):
        mislabelled = (
            b'{"content":"74657874","content_class":"ARTIFACT_CONTENT",'
            b'"content_encoding":"' + foreign + b'","preimage_version":"' + VERSION + b'"}'
        )
        with pytest.raises(ValidationError) as caught:
            codec.decode_artifact_content(mislabelled)
        assert [error["loc"] for error in caught.value.errors()] == [("content_encoding",)], foreign


@pytest.mark.supports("RC-21")
@pytest.mark.traces("DC-3", "ST02-D3")
def test_the_artifact_payload_is_validated_before_any_byte_recovery() -> None:
    """Recovery happens behind the schema, so `bytes.fromhex` never sees a loose payload.

    `bytes.fromhex` accepts whitespace and mixed case and would therefore admit several
    spellings of one byte string. The model refuses those first, which is what makes the
    mapping single-valued in both directions rather than merely usually so.
    """
    for loose in (b"AABB", b"aa bb", b"abc", b"gg"):
        payload = (
            b'{"content":"' + loose + b'","content_class":"ARTIFACT_CONTENT",'
            b'"content_encoding":"BASE16_LOWER","preimage_version":"' + VERSION + b'"}'
        )
        with pytest.raises(ValidationError) as caught:
            codec.decode_artifact_content(payload)
        assert [error["loc"] for error in caught.value.errors()] == [("content",)], loose
