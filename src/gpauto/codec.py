"""The single JSON → domain boundary for GP-AUTO.

Design basis: AP-07 §23.1 (`DC-1`…`DC-4`), §5.2 (`ID-9`, `ID-10`, `ID-13`), §23
(`VM-3`, `VM-11`); AP-03 §4.3 rule 1; AP-11 §14 (`SD11-4`, `SD11-12a`(ii),
`SD11-12b`), §8 (`MU11-3`, `MU11-5`), §16 (`GP-AUTO-ST-02`); `CLAUDE.md` "JSON
ingestion — one path, enforced".

**`model_validate_json` is the only JSON → domain path, and every such conversion in
GP-AUTO lives here** (`DC-1`). Domain models are `strict=True` with `tuple[...]`
fields; strict validation refuses a `list`, and `json.loads` produces lists, so the
two-step `json.loads(...)` + `model_validate(...)` fails at run time on a *valid*
input — and only on the decode path, which is exercised less than encode. It is
forbidden package-wide. This module imports no `json`, no serializer and no hash:
the GP-AUTO decode/import gate keys on imports, finds zero `json` importers, and
finds `model_validate_json` nowhere else in the package (`DC-2`, `SD11-12b`).

**`SD11-4`: the spike's discipline, not the spike's module.** `EB-14`(iii) forbids
extending `gplanner.codec`, so GP-AUTO has its own codec under the same rule, and
imports nothing from the spike's.

**Preimage decode is one parse of the authoritative bytes** (`DC-4`, `ID-10`). The
content comes from one JSON-aware parse of the stored bytes, and the identity comes
from **those same bytes**, never from re-serializing what was decoded. Decode is not
injective over arbitrary accepted JSON — two byte strings differing only in
insignificant whitespace decode to equal objects — so a re-serialization round trip is
not an identity operation and nothing here treats it as one. A preimage that is valid
but not canonical therefore decodes to its content under *its own* identity, and the
difference from the canonical identity is visible rather than repaired.

**The decode-path guard is model-enforced** (`MU11-5`). Every structural refusal —
an undeclared field (`extra="forbid"`, `DC-3`, `VM-3`), a `list` where a `tuple` is
required, a foreign scheme tag (`VM-11`), a mislabelled content class — lives on the
models, so each decode line performs no check of its own. Deleting a line removes
decoding altogether rather than weakening a check, which is why the guard's mutation
obligation is **schema mutation**, not line deletion. The guard identifier is fixed
here, where the guard is written (`MU11-3`).

**Canonical production and schema validation are separate contracts.** Decoding
establishes that bytes satisfy the schema; it does not establish that they are the
canonical encoding, and it does not try to — checking canonicality would mean
re-serializing a decoded object, which `ID-10` forbids.
"""

from __future__ import annotations

from gpauto.authorization import AuthorizationRecord
from gpauto.content_identity import artifact_content_identity, stage_contract_identity
from gpauto.evidence import ArtifactContent
from gpauto.preimage import ArtifactContentPreimage, StageContractPreimage
from gpauto.scope_frame import StageContract


def decode_stage_contract(preimage: bytes) -> StageContract:
    """THE ONLY way to turn stored stage-contract preimage bytes into a `StageContract`.

    Its identity is the digest of the bytes supplied, so a stored preimage re-read is
    the same identity for as long as the bytes are the same bytes (`ID-10`).
    """
    envelope = StageContractPreimage.model_validate_json(preimage)  # guard:ga_codec_decode
    content = envelope.content
    return StageContract(
        identity=stage_contract_identity(preimage),
        objective=content.objective,
        deliverable_boundary=content.deliverable_boundary,
        explicit_out_of_stage=content.explicit_out_of_stage,
        implementation_instructions=content.implementation_instructions,
        review_instructions=content.review_instructions,
        acceptance_criteria=content.acceptance_criteria,
    )


def decode_artifact_content(preimage: bytes) -> tuple[ArtifactContent, bytes]:
    """THE ONLY way to turn stored artifact preimage bytes into content and its bytes.

    `ArtifactContent` is the identity and nothing else (AP-03 §8.1), so **the bytes as
    produced** are returned beside it rather than attached to it.

    Recovery is exact and single-valued. The envelope's payload is validated against the
    base-16 pattern *before* this line unspells it, so `bytes.fromhex` is reached only
    for an even-length lowercase string — it never sees the whitespace or mixed case it
    would otherwise accept, and one byte string therefore has exactly one accepted
    spelling. The identity still comes from the stored preimage bytes, never from
    re-encoding what was recovered (`ID-10`, `DC-4`).
    """
    envelope = ArtifactContentPreimage.model_validate_json(preimage)  # guard:ga_codec_decode
    content = ArtifactContent(identity=artifact_content_identity(preimage))
    return content, bytes.fromhex(envelope.content)


def decode_authorization_record(payload: bytes | str) -> AuthorizationRecord:
    """THE ONLY way to turn a JSON authorization record into an `AuthorizationRecord`.

    `str` and `bytes` are both accepted because Pydantic accepts both; neither is
    decoded differently. An undeclared field is refused, never dropped — which is
    what makes AP-03 §4.3 rule 1's fail-closed projection real (`EQ-2`, `DC-3`).
    """
    return AuthorizationRecord.model_validate_json(payload)  # guard:ga_codec_decode
