"""Content identity: `sha256(canonical_preimage)`, derived once, from stored bytes.

Design basis: AP-07 §5.1 (`ID-1`, `ID-2`), §5.2 (`ID-9`…`ID-13`), §23.1 (`DC-4`);
AP-03 §3 (content identity), §3.1 rows 4 and 7; AP-11 §14 (`SD11-1`, `SD11-2`,
`SD11-15`, `SD11-16`, `SD11-16a`), §16 (`GP-AUTO-ST-02`).

**Two primitives, imported unmodified, and nothing else from the spike.** `SD11-1`
and `SD11-2` authorize reuse of `canonical` (RFC 8785 / JCS) and `digest` (the sole
SHA-256 site) *after verification against the obligation each is reused for*
(`SD11-15`); `tests_gpauto` carries that verification. From `digest` only
`digest_of_preimage_bytes` is used — bytes in, digest out, no parsing, no
normalization — because the spike's model-level helpers embed GP-SPK-001's payload
profile, which `SD11-16` forbids GP-AUTO behaviour from depending on. Nothing is
modified, extended, subclassed or re-exported (`EB-14`(iii)); the coupling the two
imports create is the one `SD11-16a` names, and there is no other.

**One canonicalization, one SHA-256 site.** This module forms no canonical bytes of
its own and hashes nothing itself: JCS is `canonical.canonical_bytes`, SHA-256 is
`digest.digest_of_preimage_bytes`, and each appears exactly once in the repository's
production source (`ID-11`, `F3`). There is no second canonicalizer here, no
per-class variant, and no port of `governed-runtime`'s `canonical_json`.

**The canonical preimage is the authoritative representation** (`ID-9`, `DC-4`). The
derivation order is fixed and is the only one: validated envelope → `model_dump(mode=
"json")` → JCS → UTF-8 bytes → SHA-256 of **those bytes**. Identity is then always a
function of stored bytes — `stage_contract_identity(preimage)` — and never of an
object: nothing here reconstructs canonical bytes from a decoded object in order to
compare or verify, which is what keeps drift loud rather than silent (`ID-10`).

**Identity is not denotation** (`ID-13`). A content identity names exactly the bytes
it was computed over. Two byte strings decoding to equal objects are two identities,
and that is correct: sameness of *meaning* is `equivalence.py`'s question and is
never answered with a content identity.

**Only content identities are derived here** (`ID-1`, `ID-2`). The two derivations
return `StageContractId` and `ArtifactContentId` and nothing else. No record, minted
or supplied identity is computed from content anywhere in GP-AUTO, and no content
identity names an occurrence.
"""

from __future__ import annotations

from typing import Self

from pydantic import model_validator

from gpauto.identity import ArtifactContentId, StageContractId
from gpauto.preimage import (
    PREIMAGE_VERSION,
    ArtifactContentPreimage,
    ContentClass,
    ContentEncoding,
    StageContractContent,
    StageContractPreimage,
)
from gpauto.schema import DomainValue
from gplanner.canonical import canonical_bytes
from gplanner.digest import digest_of_preimage_bytes


def stage_contract_preimage(content: StageContractContent) -> bytes:
    """THE canonical preimage of a stage contract's content: stored verbatim, hashed verbatim."""
    envelope = StageContractPreimage(
        preimage_version=PREIMAGE_VERSION,
        content_class=ContentClass.STAGE_CONTRACT,
        content_encoding=ContentEncoding.TEXT,
        content=content,
    )
    return canonical_bytes(envelope.model_dump(mode="json"))


def artifact_content_preimage(content: bytes) -> bytes:
    """THE canonical preimage of artifact content: stored verbatim, hashed verbatim.

    `content` is *the bytes as produced* (`RC-21`) — any byte string, text or not. They
    enter the one JCS envelope as lowercase base-16, which is deterministic and
    reversible, so invalid UTF-8, an embedded zero byte and high-byte values are all
    representable and all recover exactly (`preimage.py`).
    """
    envelope = ArtifactContentPreimage(
        preimage_version=PREIMAGE_VERSION,
        content_class=ContentClass.ARTIFACT_CONTENT,
        content_encoding=ContentEncoding.BASE16_LOWER,
        content=content.hex(),
    )
    return canonical_bytes(envelope.model_dump(mode="json"))


def stage_contract_identity(preimage: bytes) -> StageContractId:
    """The identity **of these stored bytes** — no parse, no re-encode (`ID-10`)."""
    return StageContractId(value=digest_of_preimage_bytes(preimage))


def artifact_content_identity(preimage: bytes) -> ArtifactContentId:
    """The identity **of these stored bytes** — no parse, no re-encode (`ID-10`)."""
    return ArtifactContentId(value=digest_of_preimage_bytes(preimage))


class IdentifiedStageContract(DomainValue):
    """A stage contract's canonical preimage, held together with its identity.

    The preimage is the authoritative representation and the identity is derived from
    it; the validator below makes *"the stored preimage always rehashes to its
    identity"* (`GK-INV-1`, `ID-9`) a property of the value rather than of whoever
    built it. What the bytes *denote* is checked where they are decoded (`codec.py`).
    """

    identity: StageContractId
    canonical_preimage: bytes

    @model_validator(mode="after")
    def _preimage_rehashes_to_identity(self) -> Self:
        if stage_contract_identity(self.canonical_preimage) != self.identity:
            raise ValueError("canonical preimage does not rehash to the stated identity")
        return self


class IdentifiedArtifactContent(DomainValue):
    """An artifact's canonical preimage, held together with its identity.

    As `IdentifiedStageContract`. It carries no provenance and no standing: two
    productions of identical content share this value and nothing else (`ID-14`,
    `AP03-I19`).
    """

    identity: ArtifactContentId
    canonical_preimage: bytes

    @model_validator(mode="after")
    def _preimage_rehashes_to_identity(self) -> Self:
        if artifact_content_identity(self.canonical_preimage) != self.identity:
            raise ValueError("canonical preimage does not rehash to the stated identity")
        return self


def identify_stage_contract(content: StageContractContent) -> IdentifiedStageContract:
    """Derive a stage contract's content identity over its canonical preimage."""
    preimage = stage_contract_preimage(content)
    return IdentifiedStageContract(
        identity=stage_contract_identity(preimage), canonical_preimage=preimage
    )


def identify_artifact_content(content: bytes) -> IdentifiedArtifactContent:
    """Derive an artifact's content identity over its canonical preimage.

    Identity is a function of **the exact bytes**: the base-16 spelling is injective, so
    different bytes are a different preimage and therefore a different identity, and
    identical bytes are the same identity however they were captured.
    """
    preimage = artifact_content_preimage(content)
    return IdentifiedArtifactContent(
        identity=artifact_content_identity(preimage), canonical_preimage=preimage
    )
