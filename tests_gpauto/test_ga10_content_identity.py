"""Content identity: derived over the canonical preimage, which is kept and used.

Design basis: AP-07 §5.1 (`ID-1`, `ID-2`), §5.2 (`ID-9`…`ID-14`), §23.1 (`DC-4`);
AP-03 §3, §3.1 rows 4 and 7, §8.1; AP-11 §16 (`GP-AUTO-ST-02` tests).

The contract's first two tests are here: *the canonical preimage is stored and used as
the authoritative representation*, and *identical content ⇒ identical identity*. The
converse — different content is necessarily a different identity (AP-03 §3) — is
checked part by part, and the structural half of `ID-1`/`ID-2` is checked over the
package rather than over one instance.
"""

from __future__ import annotations

import ast
import inspect
import typing

import pytest
from pydantic import ValidationError

import st02_support
from gpauto import codec, content_identity
from gpauto.content_identity import (
    IdentifiedArtifactContent,
    IdentifiedStageContract,
    artifact_content_identity,
    identify_artifact_content,
    identify_stage_contract,
    stage_contract_identity,
    stage_contract_preimage,
)
from gpauto.identity import (
    ArtifactContentId,
    ArtifactProductionId,
    DomainIdentity,
    StageContractId,
)
from gpauto.preimage import (
    PREIMAGE_VERSION,
    ArtifactContentPreimage,
    ContentClass,
    StageContractContent,
)
from gpauto.scope_frame import StageContract
from gpauto.vocabulary import StageContractPart
from gplanner.digest import digest_of_preimage_bytes
from introspect import source_files

GPAUTO_STAGE = "GP-AUTO-ST-02"


@pytest.mark.traces("ST02-T1", "ST02-D1", "ID-9", "DC-4")
def test_the_canonical_preimage_is_kept_and_is_what_identity_is_computed_over() -> None:
    """`ID-9`: identity is `sha256(canonical_preimage)` over the bytes that are kept.

    The preimage is checked byte for byte against the envelope written out by hand —
    RFC 8785 member order, no insignificant whitespace, the scheme named inside it —
    and the identity is checked against the digest of exactly those bytes.
    """
    content = st02_support.stage_contract_content(
        objective="o",
        deliverable_boundary=("d",),
        explicit_out_of_stage=(),
        implementation_instructions=("i",),
        review_instructions=("r",),
        acceptance_criteria=("a",),
    )
    identified = identify_stage_contract(content)
    expected = (
        b'{"content":{"acceptance_criteria":["a"],"deliverable_boundary":["d"],'
        b'"explicit_out_of_stage":[],"implementation_instructions":["i"],'
        b'"objective":"o","review_instructions":["r"]},'
        b'"content_class":"STAGE_CONTRACT","content_encoding":"TEXT",'
        b'"preimage_version":"gpauto.content-preimage/1+jcs-rfc8785"}'
    )
    assert identified.canonical_preimage == expected
    assert identified.identity == StageContractId(value=digest_of_preimage_bytes(expected))


@pytest.mark.traces("ST02-T1", "ID-9", "ID-10", "DC-4")
def test_the_kept_preimage_is_the_representation_read_back() -> None:
    """Reading back goes through the kept bytes, and yields the identity of those bytes.

    Content and identity both come from the one stored byte string: the decoded
    contract carries the identity the derivation produced, and its parts are the parts
    that were identified.
    """
    content = st02_support.stage_contract_content()
    identified = identify_stage_contract(content)
    decoded = codec.decode_stage_contract(identified.canonical_preimage)
    assert decoded.identity == identified.identity
    assert {name: getattr(decoded, name) for name in StageContractContent.model_fields} == {
        name: getattr(content, name) for name in StageContractContent.model_fields
    }


@pytest.mark.traces("ID-10")
def test_identity_from_stored_bytes_neither_parses_nor_re_encodes() -> None:
    """`ID-10`: a stored preimage is read as bytes and rehashes to its digest.

    Bytes that are not a preimage at all still hash — nothing is parsed on this path —
    so this path cannot come to disagree with the derivation about what was hashed.
    """
    arbitrary = b"\x00 not a preimage \xff"
    assert stage_contract_identity(arbitrary).value == digest_of_preimage_bytes(arbitrary)
    assert artifact_content_identity(arbitrary).value == digest_of_preimage_bytes(arbitrary)


@pytest.mark.traces("ST02-T2", "ID-9")
def test_identical_content_yields_identical_identity() -> None:
    """Separately built, equal content: one preimage and one identity, for both classes."""
    first = identify_stage_contract(st02_support.stage_contract_content())
    second = identify_stage_contract(st02_support.stage_contract_content())
    assert first.canonical_preimage == second.canonical_preimage
    assert first.identity == second.identity

    first_bytes = st02_support.ORDINARY_UTF8_BYTES
    second_bytes = ("line one" + chr(10) + "line two " + chr(0xE9)).encode("utf-8")
    assert first_bytes is not second_bytes
    assert identify_artifact_content(first_bytes) == identify_artifact_content(second_bytes)


@pytest.mark.traces("ST02-T2", "ID-9")
@pytest.mark.parametrize("part", list(StageContractPart), ids=str)
def test_changing_any_one_part_changes_the_identity(part: StageContractPart) -> None:
    """AP-03 §3.1 row 4: changed content **is** a different identity, for every part."""
    field = part.value.lower()
    current = getattr(st02_support.stage_contract_content(), field)
    changed = current + "-changed" if isinstance(current, str) else (*current, "extra")
    base = identify_stage_contract(st02_support.stage_contract_content())
    other = identify_stage_contract(st02_support.stage_contract_content(**{field: changed}))
    assert base.identity != other.identity


@pytest.mark.traces("ID-13")
def test_identity_names_bytes_not_denotation() -> None:
    """`ID-13`: a content identity is never a test of denotation beyond its bytes.

    Reordering the parts listed under one heading, or composing a character
    differently, is different content here — whether or not a reader would call the
    two contracts "the same" is not a question content identity answers.
    """
    base = identify_stage_contract(st02_support.stage_contract_content())
    reordered = identify_stage_contract(
        st02_support.stage_contract_content(
            deliverable_boundary=("deliverable-b", "deliverable-a")
        )
    )
    assert base.identity != reordered.identity
    assert (
        identify_artifact_content(st02_support.E_ACUTE_COMPOSED.encode("utf-8")).identity
        != identify_artifact_content(st02_support.E_ACUTE_DECOMPOSED.encode("utf-8")).identity
    )


@pytest.mark.traces("ID-2")
def test_the_two_content_classes_are_domain_separated() -> None:
    """`ID-2`: exactly two content classes, and neither can pass for the other.

    The class is a term of the hashed preimage, so equal payloads under the two classes
    are different bytes and different identities, and a preimage of one class is refused
    by the other's decoder.
    """
    assert set(ContentClass) == {ContentClass.STAGE_CONTRACT, ContentClass.ARTIFACT_CONTENT}

    artifact = identify_artifact_content(b"objective")
    assert b'"content_class":"ARTIFACT_CONTENT"' in artifact.canonical_preimage
    stage = identify_stage_contract(st02_support.stage_contract_content())
    assert b'"content_class":"STAGE_CONTRACT"' in stage.canonical_preimage

    with pytest.raises(ValidationError):
        codec.decode_stage_contract(artifact.canonical_preimage)
    with pytest.raises(ValidationError):
        codec.decode_artifact_content(stage.canonical_preimage)


@pytest.mark.supports("ID-3", "ID-5")
@pytest.mark.traces("ID-1", "ID-2", "ID-6")
def test_only_the_two_content_identities_are_ever_derived() -> None:
    """`ID-1`, `ID-2`: content derives content identities, and nothing else.

    Structural, over the package (`VP11-4`): no production module constructs any
    identity type other than `StageContractId` and `ArtifactContentId`, so no record,
    minted or supplied identity is computed from content anywhere, and no content
    identity can be produced for an occurrence. The derivation functions' own return
    types say the same.
    """
    identity_names = {
        cls.__name__
        for cls in _identity_classes()
        if cls.__module__ == "gpauto.identity"
    }
    constructed: set[str] = set()
    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in identity_names:
                    constructed.add(node.func.id)
    assert constructed == {"StageContractId", "ArtifactContentId"}

    hints = {
        name: typing.get_type_hints(function).get("return")
        for name, function in inspect.getmembers(content_identity, inspect.isfunction)
        if function.__module__ == content_identity.__name__
    }
    assert hints == {
        "stage_contract_preimage": bytes,
        "artifact_content_preimage": bytes,
        "stage_contract_identity": StageContractId,
        "artifact_content_identity": ArtifactContentId,
        "identify_stage_contract": IdentifiedStageContract,
        "identify_artifact_content": IdentifiedArtifactContent,
    }


def _identity_classes() -> list[type[DomainIdentity]]:
    import gpauto.identity as identity_module

    return [
        value
        for value in vars(identity_module).values()
        if isinstance(value, type) and issubclass(value, DomainIdentity)
    ]


@pytest.mark.traces("ID-9")
def test_a_preimage_that_does_not_rehash_to_its_identity_cannot_be_held() -> None:
    """`GK-INV-1`: the stored preimage always rehashes to its identity.

    The pairing is a property of the value, so a preimage cannot be held under an
    identity it does not produce — whether that identity is another content's or a
    token that was never a digest.
    """
    stage = identify_stage_contract(st02_support.stage_contract_content())
    other = identify_stage_contract(st02_support.stage_contract_content(objective="other"))
    with pytest.raises(ValidationError):
        IdentifiedStageContract(
            identity=other.identity, canonical_preimage=stage.canonical_preimage
        )

    artifact = identify_artifact_content(b"text")
    with pytest.raises(ValidationError):
        IdentifiedArtifactContent(
            identity=ArtifactContentId(value="content-token"),
            canonical_preimage=artifact.canonical_preimage,
        )


@pytest.mark.traces("ST02-D1")
def test_the_content_model_is_exactly_the_contracts_six_named_parts() -> None:
    """`StageContractContent` is `StageContract` minus its identity, and nothing else.

    Pinned structurally so the two definitions cannot drift apart: the identity is
    derived *from* the parts and so cannot be one of them, and AP-03 §2.1's six parts
    are the whole of the content.
    """
    parts = set(StageContractContent.model_fields)
    assert parts == set(StageContract.model_fields) - {"identity"}
    assert parts == {part.value.lower() for part in StageContractPart}
    for name in parts:
        assert (
            StageContractContent.model_fields[name].annotation
            == StageContract.model_fields[name].annotation
        ), name


@pytest.mark.supports("ID-14")
@pytest.mark.traces("ST02-T2")
def test_identical_artifact_text_is_one_content_identity_and_carries_no_provenance() -> None:
    """Two productions of identical bytes share a content identity and nothing else.

    The content preimage carries the content and its scheme, never a producer,
    provenance or standing (AP-03 §8.1, `AP03-I19`), and production identities are a
    separate kind that content cannot produce. That store-level sharing never merges
    two productions is `ID-14`'s store clause, owed where the store exists.
    """
    first = identify_artifact_content(b"identical captured output")
    second = identify_artifact_content(b"identical captured output")
    assert first.identity == second.identity
    assert set(ArtifactContentPreimage.model_fields) == {
        "preimage_version",
        "content_class",
        "content_encoding",
        "content",
    }
    assert not issubclass(ArtifactContentId, ArtifactProductionId)


@pytest.mark.supports("RC-21")
@pytest.mark.traces("ID-9", "ST02-D1")
def test_an_ambiguous_artifact_payload_is_refused_rather_than_half_recovered() -> None:
    """The base-16 payload is single-valued in both directions, enforced on the model.

    `bytes.fromhex` alone would accept whitespace, mixed case and grouping — several
    spellings of one byte string, which is the ambiguity that would make recovery a
    guess. The pattern refuses each of them at the decode boundary instead, so a payload
    either is the one accepted spelling of some bytes or is not decoded at all.
    """
    honest = identify_artifact_content(st02_support.INVALID_UTF8_BYTES).canonical_preimage
    spelling = st02_support.INVALID_UTF8_BYTES.hex()
    assert ('"content":"' + spelling + '"').encode("utf-8") in honest

    for ambiguous in (spelling.upper(), "ff fe 80", "f", "zz", spelling + " "):
        payload = honest.replace(
            ('"content":"' + spelling + '"').encode("utf-8"),
            ('"content":"' + ambiguous + '"').encode("utf-8"),
        )
        with pytest.raises(ValidationError) as caught:
            codec.decode_artifact_content(payload)
        assert [error["loc"] for error in caught.value.errors()] == [("content",)], ambiguous


@pytest.mark.traces("ID-12", "ST02-D1")
def test_the_preimage_names_its_scheme_and_its_canonicalizer() -> None:
    """The scheme tag names JCS / RFC 8785, the only canonicalizer claims are scoped to."""
    assert PREIMAGE_VERSION == "gpauto.content-preimage/1+jcs-rfc8785"
    preimage = stage_contract_preimage(st02_support.stage_contract_content())
    assert b'"preimage_version":"gpauto.content-preimage/1+jcs-rfc8785"' in preimage


# --- Artifact content is the bytes as produced (RC-21) ----------------------------


@pytest.mark.supports("RC-21")
@pytest.mark.traces("ST02-T2", "ST02-D1")
@pytest.mark.parametrize(
    ("label", "produced"), st02_support.ARBITRARY_BYTE_CASES, ids=lambda case: str(case)[:24]
)
def test_arbitrary_produced_bytes_round_trip_exactly(label: str, produced: bytes) -> None:
    """`RC-21`: artifact content is *"the bytes as produced"*, and all of them are.

    The JSON codec boundary is what GP-AUTO decodes *through*; it does not narrow what
    artifact content may be. Text, invalid UTF-8, an embedded zero byte and the top of
    the byte range all enter the one JCS preimage and all come back byte-identical.
    """
    identified = identify_artifact_content(produced)
    content, recovered = codec.decode_artifact_content(identified.canonical_preimage)
    assert recovered == produced, label
    assert content.identity == identified.identity, label


@pytest.mark.supports("RC-21")
@pytest.mark.traces("ST02-D1")
def test_bytes_with_no_text_reading_are_representable() -> None:
    """The case a text-shaped scheme cannot hold at all.

    `INVALID_UTF8_BYTES` has no decoding as text, so under the previous text payload it
    had no identity. It has one now, and recovery is exact.
    """
    produced = st02_support.INVALID_UTF8_BYTES
    with pytest.raises(UnicodeDecodeError):
        produced.decode("utf-8")
    _, recovered = codec.decode_artifact_content(
        identify_artifact_content(produced).canonical_preimage
    )
    assert recovered == produced


@pytest.mark.traces("ST02-T2", "ID-9")
def test_identical_bytes_are_one_identity_and_different_bytes_are_two() -> None:
    """Identity is a function of the exact bytes, in both directions."""
    produced = st02_support.EMBEDDED_ZERO_BYTES
    assert identify_artifact_content(produced) == identify_artifact_content(bytes(produced))

    identities = {
        identify_artifact_content(case).identity for _, case in st02_support.ARBITRARY_BYTE_CASES
    }
    assert len(identities) == len(st02_support.ARBITRARY_BYTE_CASES)

    assert (
        identify_artifact_content(bytes([0x00])).identity
        != identify_artifact_content(bytes([0x00, 0x00])).identity
    )


@pytest.mark.supports("RC-21")
@pytest.mark.traces("ST02-D1")
def test_the_byte_spelling_is_deterministic_and_carries_no_alternatives() -> None:
    """One byte string, one accepted payload: lowercase, two characters per byte, no padding."""
    produced = st02_support.HIGH_VALUE_BYTES
    first = identify_artifact_content(produced).canonical_preimage
    second = identify_artifact_content(produced).canonical_preimage
    assert first == second

    spelling = produced.hex()
    assert spelling == spelling.lower()
    assert len(spelling) == 2 * len(produced)
    assert (b'"content_encoding":"BASE16_LOWER"') in first
    assert bytes.fromhex(spelling) == produced


@pytest.mark.supports("ID-14", "RC-21")
@pytest.mark.traces("ST02-D1")
def test_byte_content_identity_is_still_not_an_occurrence_identity() -> None:
    """Carrying bytes changes nothing about what a content identity is (`ID-14`).

    The preimage gains an encoding tag, not a producer: two productions of identical
    bytes still share a content identity and nothing else, and no production identity is
    derivable from content.
    """
    produced = st02_support.ALL_BYTE_VALUES
    first = identify_artifact_content(produced)
    second = identify_artifact_content(produced)
    assert first.identity == second.identity
    assert set(ArtifactContentPreimage.model_fields) == {
        "preimage_version",
        "content_class",
        "content_encoding",
        "content",
    }
    assert not issubclass(ArtifactContentId, ArtifactProductionId)
