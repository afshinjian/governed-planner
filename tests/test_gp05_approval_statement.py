"""GP-05 — the approval record binds one exact artifact, and one only.

Design basis: design/GP-SPK-001-governance-kernel.md §13.1 requirement 4, §7, §8, §11.

Requirement 4 is accepted only when **every binding field broken in isolation is
refused**. That phrasing is what this file is organized around: each structural
constraint is broken on its own, against an otherwise-valid statement, so a passing
case can never be carrying a second defect that masks the one under test.

Two things GP-05 deliberately does **not** do.

It does not consume an approval, advance a case, persist anything, or evaluate
staleness. A statement that binds `(subject digest, workflow, from → to)` is a
different question from whether that binding matches a live case, and the second is
GP-06's and the kernel's. This file therefore reads binding as a property *of the
statement*, never as a verdict about a case.

And it does not claim the approval came from a human. §11 is explicit: the `HUMAN`
authority label is enforced, human identity and authenticity are not. The label is
asserted here; the limitation is asserted here too, so the two travel together.

Transport is JSON text end to end. `codec` remains the single JSON → domain boundary,
and the decode path is `ApprovalStatement.model_validate_json` — never `json.loads`
followed by `model_validate`, which §7 forbids package-wide and which GP-03 proves
broken against strict `tuple[...]` fields.
"""

from __future__ import annotations

import ast
import copy
import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from gplanner import approvals, codec
from gplanner.approvals import (
    APPROVAL_ID_PATTERN,
    BARE_SHA256_PATTERN,
    ISSUED_AT_PATTERN,
    MAX_LABEL_LENGTH,
    PREDICATE_VERSION,
    SCOPE_APPROVAL_PREDICATE_TYPE,
    STATEMENT_TYPE,
    WORKFLOW_ID_PATTERN,
    ApprovalStatement,
    ScopeApprovalPredicate,
    Sha256DigestSet,
    Subject,
)
from gplanner.codec import decode_approval, encode_approval
from gplanner.digest import from_intoto_hex, is_digest, to_intoto_hex
from gplanner.states import ActorKind, ScopeState

SRC = Path(__file__).resolve().parents[1] / "src" / "gplanner"

# --- The one valid statement every case is a single mutation away from -----------

SUBJECT_HEX = "9f2c4e1a" + "0" * 48 + "7b3d5e6f"
SUBJECT_DIGEST = "sha256:" + SUBJECT_HEX
APPROVAL_ID = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a88"
WORKFLOW_ID = "gp-spk-001-case-0001"
APPROVER_ID = "owner@example.invalid"
ISSUED_AT = "2026-09-17T11:22:33Z"

VALID_WIRE: dict[str, Any] = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
        {
            "name": "gplanner.scope/v1",
            "digest": {"sha256": SUBJECT_HEX},
        }
    ],
    "predicateType": SCOPE_APPROVAL_PREDICATE_TYPE,
    "predicate": {
        "predicate_version": PREDICATE_VERSION,
        "approval_id": APPROVAL_ID,
        "workflow_id": WORKFLOW_ID,
        "from_state": "SCOPE_REVIEW_PENDING",
        "to_state": "SCOPE_APPROVED",
        "approver_id": APPROVER_ID,
        "approver_kind": "HUMAN",
        "decision": "APPROVE",
        "issued_at": ISSUED_AT,
    },
}


def wire(**_unused: Any) -> dict[str, Any]:
    """A deep copy of the valid statement, so a mutation cannot leak between tests."""
    return copy.deepcopy(VALID_WIRE)


def text(payload: dict[str, Any]) -> str:
    return json.dumps(payload)


def valid_statement() -> ApprovalStatement:
    return decode_approval(text(wire()))


def binding(statement: ApprovalStatement) -> tuple[str, str, ScopeState, ScopeState]:
    """The tuple `GK-INV-2` says an approval authorizes, read off the statement.

    Read here rather than provided by `approvals.py` on purpose: deciding whether this
    tuple matches a live case is the kernel's job, and a comparison helper shipped in
    the model layer would be a second opinion about binding sitting outside the layer
    that owns it.
    """
    return (
        from_intoto_hex(statement.subject[0].digest.sha256),
        statement.predicate.workflow_id,
        statement.predicate.from_state,
        statement.predicate.to_state,
    )


EXPECTED_BINDING: tuple[str, str, ScopeState, ScopeState] = (
    SUBJECT_DIGEST,
    WORKFLOW_ID,
    ScopeState.SCOPE_REVIEW_PENDING,
    ScopeState.SCOPE_APPROVED,
)


def top_level_imports(module_name: str) -> set[str]:
    """Root module names imported by a production module, read from its source."""
    tree = ast.parse((SRC / f"{module_name}.py").read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            roots.add(node.module or "")
    return roots


def attribute_names(module_name: str) -> list[str]:
    tree = ast.parse((SRC / f"{module_name}.py").read_text(encoding="utf-8"))
    return [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)]


# --- Section A: the frozen vocabulary --------------------------------------------


def test_a_the_statement_type_is_in_toto_statement_v1() -> None:
    """The one value §8 fixes by reference to an external specification."""
    assert STATEMENT_TYPE == "https://in-toto.io/Statement/v1"


def test_a_the_predicate_type_is_the_approved_uri(  # ST6-R01
) -> None:
    """Fixed by the approved plan of record (revision 5 §6), not chosen at ST-6.

    ST-6 first froze a versionless `urn:` form, reasoning from `digest.py`'s split
    between a versionless `media_type` and a versioned payload. That reasoning does not
    reach here: the plan specifies this URI separately, and a stage may not amend it.
    Written out as a literal so the constant is pinned to the contract rather than to
    whatever the module happens to declare.
    """
    assert SCOPE_APPROVAL_PREDICATE_TYPE == "https://governed-planner/ScopeApproval/v1"
    assert PREDICATE_VERSION == "gplanner.scope-approval/v1"


def test_a_the_approval_id_pattern_is_exactly_32_lowercase_hex() -> None:
    assert APPROVAL_ID_PATTERN == r"^[0-9a-f]{32}$"


def test_a_the_workflow_id_constraint_is_the_approved_pattern() -> None:  # ST6-R02
    """Letters, digits, underscore, dot, colon, hyphen; length 1-128 (plan §6).

    Pinned as a literal, for the same reason as the predicate URI above: an assertion
    derived from the module would agree with any value the module chose.
    """
    assert WORKFLOW_ID_PATTERN == r"^[A-Za-z0-9_.:-]{1,128}$"
    assert re.compile(WORKFLOW_ID_PATTERN).match(WORKFLOW_ID) is not None


def test_a_the_workflow_id_bound_is_128_accepted_and_129_refused() -> None:  # ST6-R02
    """The boundary itself, decided through the decoder rather than through the regex."""
    payload = wire()
    payload["predicate"]["workflow_id"] = "a" * 128
    assert len(decode_approval(text(payload)).predicate.workflow_id) == 128

    payload["predicate"]["workflow_id"] = "a" * 129
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize("char", ["A", "z", "0", "9", "_", ".", ":", "-"])
def test_a_every_approved_workflow_id_character_is_accepted(char: str) -> None:  # ST6-R02
    """The approved letters, digits, underscore, dot, colon and hyphen, one at a time,
    so a narrowed character class cannot pass by being merely plausible."""
    payload = wire()
    payload["predicate"]["workflow_id"] = f"gp{char}case"
    assert decode_approval(text(payload)).predicate.workflow_id == f"gp{char}case"


def test_a_the_issued_at_constraint_is_rfc3339_date_time_with_a_mandatory_offset() -> None:
    """Syntax only (§8). The offset is the one part this spike insists on, because with
    no trusted clock a local-time instant cannot be interpreted at all."""
    assert ISSUED_AT_PATTERN == (
        r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
        r"[Tt](?:[01][0-9]|2[0-3]):[0-5][0-9]:(?:[0-5][0-9]|60)"
        r"(?:\.[0-9]+)?"
        r"(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
    )
    pattern = re.compile(ISSUED_AT_PATTERN)
    assert pattern.fullmatch(ISSUED_AT) is not None
    assert pattern.fullmatch(ISSUED_AT.removesuffix("Z")) is None
    assert "\\d" not in ISSUED_AT_PATTERN, "Unicode-wide \\d accepted fullwidth digits"


def test_a_the_subject_digest_pattern_agrees_with_the_digest_module() -> None:
    """`approvals` must not import `digest`, so the bare-hex shape is stated twice.

    Exactly the arrangement `ArtifactRef` already uses (see `artifacts.py`): the
    pattern is restated, and the test asserts the two spellings accept the same set.
    """
    assert BARE_SHA256_PATTERN == r"^[0-9a-f]{64}$"
    pattern = re.compile(BARE_SHA256_PATTERN)
    assert pattern.match(SUBJECT_HEX) is not None
    assert is_digest(from_intoto_hex(SUBJECT_HEX))
    assert to_intoto_hex(SUBJECT_DIGEST) == SUBJECT_HEX


# --- Section B: Subject ----------------------------------------------------------


def test_b_subject_carries_exactly_name_and_digest() -> None:
    assert set(Subject.model_fields) == {"name", "digest"}


def test_b_subject_is_frozen_strict_and_closed() -> None:
    subject = Subject(name="gplanner.scope/v1", digest=Sha256DigestSet(sha256=SUBJECT_HEX))
    with pytest.raises(ValidationError):
        subject.name = "other"
    assert Subject.model_config["frozen"] is True
    assert Subject.model_config["strict"] is True
    assert Subject.model_config["extra"] == "forbid"


def test_b_the_digest_map_holds_exactly_the_approved_sha256_shape() -> None:
    assert set(Sha256DigestSet.model_fields) == {"sha256"}
    assert Sha256DigestSet.model_config["extra"] == "forbid"


@pytest.mark.parametrize("name", ["", "x" * 257], ids=["empty", "over-bound"])
def test_b_subject_name_is_non_empty_and_bounded(name: str) -> None:  # ST6-R03
    with pytest.raises(ValidationError):
        Subject(name=name, digest=Sha256DigestSet(sha256=SUBJECT_HEX))


def test_b_the_label_bound_is_the_approved_256() -> None:  # ST6-R03
    """`Subject.name` and `approver_id` share the plan's `ACTORID` bound of 1-256.

    The literal is written out here and the boundary is then exercised through the
    decoder, so neither the constant nor the models can drift below the contract.
    """
    assert MAX_LABEL_LENGTH == 256

    payload = wire()
    payload["subject"][0]["name"] = "n" * 256
    payload["predicate"]["approver_id"] = "a" * 256
    statement = decode_approval(text(payload))
    assert len(statement.subject[0].name) == 256
    assert len(statement.predicate.approver_id) == 256


def test_b_the_subject_digest_is_bare_hex_not_the_prefixed_wire_form() -> None:
    """in-toto's digest map omits the algorithm prefix; ours keeps it everywhere else.

    Storing `sha256:<hex>` inside the map would be a malformed in-toto statement, and
    the mismatch is a known footgun — `digest.to_intoto_hex` exists to convert in one
    place. Refusing the prefixed spelling here is what makes that conversion mandatory
    rather than merely available.
    """
    with pytest.raises(ValidationError):
        Sha256DigestSet(sha256=SUBJECT_DIGEST)
    assert Sha256DigestSet(sha256=SUBJECT_HEX).sha256 == SUBJECT_HEX


# --- Section C: ScopeApprovalPredicate -------------------------------------------


def test_c_the_predicate_carries_exactly_the_frozen_nine_fields() -> None:
    assert list(ScopeApprovalPredicate.model_fields) == [
        "predicate_version",
        "approval_id",
        "workflow_id",
        "from_state",
        "to_state",
        "approver_id",
        "approver_kind",
        "decision",
        "issued_at",
    ]


def test_c_the_predicate_is_frozen_strict_and_closed() -> None:
    assert ScopeApprovalPredicate.model_config["frozen"] is True
    assert ScopeApprovalPredicate.model_config["strict"] is True
    assert ScopeApprovalPredicate.model_config["extra"] == "forbid"


def test_c_states_decode_to_the_enum_not_to_bare_strings() -> None:
    predicate = valid_statement().predicate
    assert predicate.from_state is ScopeState.SCOPE_REVIEW_PENDING
    assert predicate.to_state is ScopeState.SCOPE_APPROVED


def test_c_the_approver_kind_label_is_human_and_only_human() -> None:
    assert valid_statement().predicate.approver_kind is ActorKind.HUMAN


@pytest.mark.parametrize("kind", ["SYSTEM", "LLM"], ids=["system", "llm"])
def test_c_a_non_human_approver_kind_fails_validation_before_the_kernel(kind: str) -> None:
    """§11's "must prove" list, in its GP-05 half: a statement carrying `LLM` or
    `SYSTEM` never becomes an `ApprovalStatement` at all, so no kernel check is what
    stands between an LLM label and an authorized transition."""
    payload = wire()
    payload["predicate"]["approver_kind"] = kind
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


def test_c_the_only_decision_is_approve() -> None:
    payload = wire()
    payload["predicate"]["decision"] = "REJECT"
    with pytest.raises(ValidationError):
        decode_approval(text(payload))
    assert valid_statement().predicate.decision == "APPROVE"


# --- Section D: ApprovalStatement ------------------------------------------------


def test_d_the_statement_carries_exactly_the_four_in_toto_members() -> None:
    assert list(ApprovalStatement.model_fields) == [
        "type_",
        "subject",
        "predicateType",
        "predicate",
    ]


def test_d_the_statement_is_frozen_strict_and_closed() -> None:
    assert ApprovalStatement.model_config["frozen"] is True
    assert ApprovalStatement.model_config["strict"] is True
    assert ApprovalStatement.model_config["extra"] == "forbid"


def test_d_only_type_needs_an_alias() -> None:  # ST6-R04
    """`_type` on the wire; `predicateType` is already a legal Python identifier.

    Pydantic reserves leading-underscore attribute names for private state, so the
    in-toto `_type` spelling cannot be a field name and must be an alias. `predicateType`
    needs none, and giving it one would be a second spelling to keep in step for nothing.
    """
    assert ApprovalStatement.model_fields["type_"].alias == "_type"
    assert ApprovalStatement.model_fields["predicateType"].alias is None
    assert [
        name for name, f in ApprovalStatement.model_fields.items() if f.alias is not None
    ] == ["type_"]


def test_d_name_population_is_enabled_as_the_plan_fixes_it() -> None:  # ST6-R04
    assert ApprovalStatement.model_config["populate_by_name"] is True


def test_d_a_valid_statement_decodes_with_every_member_intact() -> None:
    statement = valid_statement()
    assert statement.type_ == STATEMENT_TYPE
    assert statement.predicateType == SCOPE_APPROVAL_PREDICATE_TYPE
    assert statement.predicate.predicate_version == PREDICATE_VERSION
    assert statement.predicate.approval_id == APPROVAL_ID
    assert statement.predicate.workflow_id == WORKFLOW_ID
    assert statement.predicate.approver_id == APPROVER_ID
    assert statement.predicate.issued_at == ISSUED_AT
    assert statement.subject[0].name == "gplanner.scope/v1"
    assert statement.subject[0].digest.sha256 == SUBJECT_HEX


def test_d_the_statement_is_unsigned_and_carries_no_signature_envelope() -> None:
    """§8: unsigned; the statement *is* the payload a signature would later cover.

    No DSSE, no `signatures`, no `payloadType`. Asserted rather than assumed, so a
    later stage adding signing has to change this test deliberately.
    """
    members = set(ApprovalStatement.model_fields) | {
        field.alias for field in ApprovalStatement.model_fields.values() if field.alias
    }
    assert not members & {"signatures", "signature", "payload", "payloadType", "dsse"}


# --- Section E: every constraint broken in isolation -----------------------------


def test_e_zero_subjects_is_refused() -> None:
    payload = wire()
    payload["subject"] = []
    with pytest.raises(ValidationError) as excinfo:
        decode_approval(text(payload))
    assert "too_short" in {error["type"] for error in excinfo.value.errors()}


def test_e_more_than_one_subject_is_refused() -> None:
    """One statement authorizes one artifact. Two subjects would make "the digest this
    approval references" ambiguous, which is precisely what `GK-INV-2` forbids."""
    payload = wire()
    payload["subject"] = [payload["subject"][0], copy.deepcopy(payload["subject"][0])]
    with pytest.raises(ValidationError) as excinfo:
        decode_approval(text(payload))
    assert "too_long" in {error["type"] for error in excinfo.value.errors()}


@pytest.mark.parametrize(
    "digest_map",
    [
        {},
        {"sha256": SUBJECT_DIGEST},
        {"sha256": SUBJECT_HEX.upper()},
        {"sha256": SUBJECT_HEX[:-1]},
        {"sha256": SUBJECT_HEX + "0"},
        {"sha256": SUBJECT_HEX + "\n"},
        {"sha512": SUBJECT_HEX},
        {"sha256": SUBJECT_HEX, "sha512": SUBJECT_HEX},
    ],
    ids=[
        "empty-map",
        "prefixed",
        "uppercase",
        "short",
        "long",
        "trailing-newline",
        "wrong-algorithm",
        "extra-algorithm",
    ],
)
def test_e_an_invalid_digest_shape_is_refused(digest_map: dict[str, str]) -> None:
    payload = wire()
    payload["subject"][0]["digest"] = digest_map
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize(
    "workflow_id",
    ["", "x" * 129, "has space", "has/slash", "has\nnewline", "café"],
    ids=["empty", "over-bound", "space", "slash", "newline", "non-ascii"],
)
def test_e_an_invalid_workflow_id_is_refused(workflow_id: str) -> None:
    payload = wire()
    payload["predicate"]["workflow_id"] = workflow_id
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize(
    "approval_id",
    [
        "",
        APPROVAL_ID[:-1],
        APPROVAL_ID + "0",
        APPROVAL_ID.upper(),
        APPROVAL_ID[:-1] + "g",
        APPROVAL_ID + "\n",
        str(uuid.uuid4()),
    ],
    ids=["empty", "short", "long", "uppercase", "non-hex", "trailing-newline", "dashed-uuid"],
)
def test_e_an_invalid_approval_id_is_refused(approval_id: str) -> None:
    payload = wire()
    payload["predicate"]["approval_id"] = approval_id
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize("approver_id", ["", "x" * 257], ids=["empty", "over-bound"])
def test_e_an_empty_or_unbounded_approver_id_is_refused(approver_id: str) -> None:  # R03
    payload = wire()
    payload["predicate"]["approver_id"] = approver_id
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize(
    "issued_at",
    [
        "",
        "2026-09-17",
        "17/09/2026 11:22:33Z",
        "2026-09-17 11:22:33Z",
        "2026-09-17T11:22Z",
        "2026-09-17T11:22:33Z ",
        "2026-09-17T11:22:33Z\n",
        "1758108153",
    ],
    ids=[
        "empty",
        "date-only",
        "not-rfc3339",
        "space-separator",
        "no-seconds",
        "trailing-space",
        "trailing-newline",
        "epoch-seconds",
    ],
)
def test_e_a_malformed_issued_at_is_refused(issued_at: str) -> None:
    payload = wire()
    payload["predicate"]["issued_at"] = issued_at
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize(
    "issued_at",
    ["2026-09-17T11:22:33", "2026-09-17T11:22:33.125", "2026-09-17T11:22:33+0200"],
    ids=["naive", "naive-fractional", "offset-without-colon"],
)
def test_e_an_issued_at_lacking_an_explicit_offset_is_refused(issued_at: str) -> None:
    """No trusted clock is available, so a local-time instant cannot be interpreted at
    all. The offset is the one part of the timestamp this spike does insist on."""
    payload = wire()
    payload["predicate"]["issued_at"] = issued_at
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize(
    "issued_at",
    [
        "2026-09-17T24:00:00Z",
        "2026-09-17T11:60:00Z",
        "2026-09-17T11:22:61Z",
        "2026-13-17T11:22:33Z",
        "2026-00-17T11:22:33Z",
        "2026-09-32T11:22:33Z",
        "2026-09-00T11:22:33Z",
        "2026-09-17T11:22:33+24:00",
        "2026-09-17T11:22:33+00:60",
        "\uff12\uff10\uff12\uff16-\uff10\uff19-\uff11\uff17T\uff11\uff11:\uff12\uff12:\uff13\uff13Z",
        "2026-09-17T11:22:33.\uff11\uff12\uff15Z",
        "2026-09-17T11:22:33.Z",
    ],
    ids=[
        "hour-24",
        "minute-60",
        "second-61",
        "month-13",
        "month-00",
        "day-32",
        "day-00",
        "offset-hour-24",
        "offset-minute-60",
        "fullwidth-digits",
        "fullwidth-fraction",
        "empty-fraction",
    ],
)
def test_e_an_out_of_range_or_non_ascii_issued_at_component_is_refused(  # ST6-R05
    issued_at: str,
) -> None:
    """RFC 3339 §5.6 bounds each component, and RFC 5234 B.1 defines `DIGIT` as ASCII.

    Every one of these was **accepted** before ST6-R05: the pattern used `\\d`, which is
    Unicode-wide in Python, with unbounded two-digit groups. Each case here breaks one
    component in isolation against an otherwise valid statement.

    This is format validation only. It adds no freshness, TTL, trusted clock, ordering,
    calendar-consistency or leap-second-history check — see the Section H limitation.
    """
    payload = wire()
    payload["predicate"]["issued_at"] = issued_at
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


def test_e_the_issued_at_guard_is_the_frozen_single_deletable_line() -> None:  # ST6-R05
    """`guard:gp_approval_issued_at_syntax`, at the site the plan's §10 registry names.

    A line guard, not one of the two model-enforced exceptions: it must survive as a
    single deletable line so GP-SPK-002's harness can excise it and see the suite go red.
    The predicate deliberately types `issued_at` as a bare `str`, so deleting this line
    genuinely removes the check rather than leaving a `StringConstraints` pattern behind
    to keep the field validated and the mutant alive.
    """
    source = (SRC / "approvals.py").read_text(encoding="utf-8")
    lines = [ln for ln in source.splitlines() if "# guard:gp_approval_issued_at_syntax" in ln]
    assert len(lines) == 1
    assert lines[0].strip().startswith("return _parse_rfc3339_or_raise(")
    assert lines[0].rstrip().endswith("# guard:gp_approval_issued_at_syntax")
    assert len(lines[0]) <= 100

    assert ScopeApprovalPredicate.model_fields["issued_at"].metadata == []


@pytest.mark.parametrize(
    "issued_at",
    [
        "2026-09-17T11:22:33Z",
        "2026-09-17t11:22:33z",
        "2026-09-17T11:22:33.125Z",
        "2026-09-17T11:22:33+02:00",
        "2026-09-17T11:22:33-05:30",
        "2026-09-17T11:22:33-00:00",
        "2026-09-17T23:59:60Z",
        "2026-09-17T11:22:33+23:59",
        "2026-12-31T00:00:00Z",
    ],
    ids=[
        "zulu",
        "lowercase",
        "fractional",
        "plus-offset",
        "minus-offset",
        "unknown-offset",
        "leap-second",
        "max-offset",
        "boundary-components",
    ],
)
def test_e_rfc3339_date_time_syntax_is_accepted(issued_at: str) -> None:
    """RFC 3339 §5.6 `date-time`, as written — `t`/`z` are case-insensitive there."""
    payload = wire()
    payload["predicate"]["issued_at"] = issued_at
    assert decode_approval(text(payload)).predicate.issued_at == issued_at


@pytest.mark.parametrize(
    "predicate_type",
    [
        "https://slsa.dev/provenance/v1",
        "urn:gplanner:scope-approval",
        "https://governed-planner/ScopeApproval/v2",
        "https://governed-planner/ScopeApproval/v1 ",
        "",
    ],
    ids=["foreign", "retired-urn", "wrong-version", "trailing-space", "empty"],
)
def test_e_a_wrong_predicate_type_is_refused(predicate_type: str) -> None:
    """A foreign predicate is refused rather than decoded under our rules — the same
    reason `ScopePreimage` pins its three envelope members to `Literal`s (§7)."""
    payload = wire()
    payload["predicateType"] = predicate_type
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize(
    "statement_type",
    ["https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1 ", ""],
    ids=["older-version", "trailing-space", "empty"],
)
def test_e_a_wrong_statement_type_is_refused(statement_type: str) -> None:
    payload = wire()
    payload["_type"] = statement_type
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize(
    "member", ["_type", "subject", "predicateType", "predicate"]
)
def test_e_a_missing_statement_member_is_refused(member: str) -> None:
    """`_type` and `predicateType` have no defaults. A statement must *say* what it is;
    inferring either would mean accepting an untyped blob and labelling it ourselves."""
    payload = wire()
    del payload[member]
    with pytest.raises(ValidationError) as excinfo:
        decode_approval(text(payload))
    assert "missing" in {error["type"] for error in excinfo.value.errors()}


@pytest.mark.parametrize(
    "member",
    [
        "predicate_version",
        "approval_id",
        "workflow_id",
        "from_state",
        "to_state",
        "approver_id",
        "approver_kind",
        "decision",
        "issued_at",
    ],
)
def test_e_a_missing_predicate_member_is_refused(member: str) -> None:
    payload = wire()
    del payload["predicate"][member]
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


def test_e_an_extra_statement_field_is_refused() -> None:
    payload = wire()
    payload["signatures"] = []
    with pytest.raises(ValidationError) as excinfo:
        decode_approval(text(payload))
    assert "extra_forbidden" in {error["type"] for error in excinfo.value.errors()}


def test_e_an_extra_predicate_field_is_refused() -> None:
    payload = wire()
    payload["predicate"]["expires_at"] = "2026-09-18T00:00:00Z"
    with pytest.raises(ValidationError) as excinfo:
        decode_approval(text(payload))
    assert "extra_forbidden" in {error["type"] for error in excinfo.value.errors()}


def test_e_an_extra_subject_field_is_refused() -> None:
    payload = wire()
    payload["subject"][0]["annotations"] = {}
    with pytest.raises(ValidationError) as excinfo:
        decode_approval(text(payload))
    assert "extra_forbidden" in {error["type"] for error in excinfo.value.errors()}


def test_e_the_field_name_spelling_of_type_is_accepted() -> None:  # ST6-R04
    """`populate_by_name=True` (plan §6), so `type_` and `_type` both validate.

    A Python caller constructing a statement should not have to spell a member the way
    the wire does, and the plan fixes that arrangement. It costs nothing on the wire:
    `encode_approval` passes `by_alias=True`, so what leaves this package is always
    `_type`, which the next assertion checks.
    """
    payload = wire()
    payload["type_"] = payload.pop("_type")
    statement = decode_approval(text(payload))
    assert statement == valid_statement()
    assert json.loads(encode_approval(statement))["_type"] == STATEMENT_TYPE


def test_e_a_foreign_field_name_is_still_refused_as_extra() -> None:  # ST6-R04
    """Name population accepts *this model's* field names, not any name at all."""
    payload = wire()
    payload["statement_type"] = payload.pop("_type")
    with pytest.raises(ValidationError) as excinfo:
        decode_approval(text(payload))
    assert "extra_forbidden" in {error["type"] for error in excinfo.value.errors()}


@pytest.mark.parametrize(
    "value",
    [1, 1.0, True, None, [], {}],
    ids=["int", "float", "bool", "null", "array", "object"],
)
def test_e_strict_validation_refuses_a_non_string_where_a_string_belongs(value: Any) -> None:
    payload = wire()
    payload["predicate"]["approver_id"] = value
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


@pytest.mark.parametrize(
    "state", ["SCOPE_REJECTED", "scope_approved", "", "SCOPE_APPROVED "]
)
def test_e_an_unknown_state_token_is_refused(state: str) -> None:
    payload = wire()
    payload["predicate"]["to_state"] = state
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


# --- Section F: binding, one field broken at a time ------------------------------


def test_f_a_valid_statement_binds_the_expected_tuple() -> None:
    """The negative control for the three mismatch cases below: with nothing broken,
    the binding tuple is exactly the one `GK-INV-2` names."""
    assert binding(valid_statement()) == EXPECTED_BINDING


def test_f_the_subject_digest_is_the_artifact_the_approval_references() -> None:
    """Requirement 4 in one line: the approval references the exact digest."""
    other_hex = "1" * 64
    payload = wire()
    payload["subject"][0]["digest"]["sha256"] = other_hex
    bound = binding(decode_approval(text(payload)))
    assert bound[0] == from_intoto_hex(other_hex)
    assert bound[0] != SUBJECT_DIGEST
    assert bound[1:] == EXPECTED_BINDING[1:]


def test_f_a_wrong_workflow_id_breaks_only_the_workflow_binding() -> None:
    payload = wire()
    payload["predicate"]["workflow_id"] = "gp-spk-001-case-0002"
    bound = binding(decode_approval(text(payload)))
    assert bound[1] != WORKFLOW_ID
    assert (bound[0], bound[2], bound[3]) == (
        EXPECTED_BINDING[0],
        EXPECTED_BINDING[2],
        EXPECTED_BINDING[3],
    )


def test_f_a_wrong_from_state_breaks_only_the_from_state_binding() -> None:
    payload = wire()
    payload["predicate"]["from_state"] = "SCOPE_DRAFTING"
    bound = binding(decode_approval(text(payload)))
    assert bound[2] is ScopeState.SCOPE_DRAFTING
    assert bound[2] != EXPECTED_BINDING[2]
    assert (bound[0], bound[1], bound[3]) == (
        EXPECTED_BINDING[0],
        EXPECTED_BINDING[1],
        EXPECTED_BINDING[3],
    )


def test_f_a_wrong_to_state_breaks_only_the_to_state_binding() -> None:
    payload = wire()
    payload["predicate"]["to_state"] = "SCOPE_REVIEW_PENDING"
    bound = binding(decode_approval(text(payload)))
    assert bound[3] is ScopeState.SCOPE_REVIEW_PENDING
    assert bound[3] != EXPECTED_BINDING[3]
    assert (bound[0], bound[1], bound[2]) == (
        EXPECTED_BINDING[0],
        EXPECTED_BINDING[1],
        EXPECTED_BINDING[2],
    )


def test_f_each_binding_field_is_broken_in_isolation_and_nowhere_else() -> None:
    """The four binding positions, each perturbed alone, each detected alone.

    Written as a census so a fifth binding field added later has to be added here too
    — the alternative is four hand-written cases that silently stop being exhaustive.
    """
    perturbations: tuple[tuple[int, tuple[str, ...], Any], ...] = (
        (0, ("subject", "0", "digest", "sha256"), "2" * 64),
        (1, ("predicate", "workflow_id"), "gp-spk-001-case-9999"),
        (2, ("predicate", "from_state"), "SCOPE_DRAFTING"),
        (3, ("predicate", "to_state"), "SCOPE_REVIEW_PENDING"),
    )
    assert len(perturbations) == len(EXPECTED_BINDING)
    for position, path, replacement in perturbations:
        payload = wire()
        cursor: Any = payload
        for key in path[:-1]:
            cursor = cursor[int(key)] if isinstance(cursor, list) else cursor[key]
        cursor[path[-1]] = replacement
        bound = binding(decode_approval(text(payload)))
        differing = [
            index for index in range(len(bound)) if bound[index] != EXPECTED_BINDING[index]
        ]
        assert differing == [position], (path, bound)


# --- Section G: the approval transport codec -------------------------------------


def test_g_encode_produces_json_text_not_a_dict_and_not_pickle() -> None:
    """§7: approval transport is JSON *text*. A `dict` crossing the boundary would be
    a second ingestion path, and pickle would be a code-execution channel."""
    encoded = encode_approval(valid_statement())
    assert isinstance(encoded, str)
    assert encoded.startswith("{") and encoded.endswith("}")


def test_g_encode_emits_the_in_toto_wire_spellings() -> None:
    reloaded = json.loads(encode_approval(valid_statement()))
    assert set(reloaded) == {"_type", "subject", "predicateType", "predicate"}
    assert reloaded["_type"] == STATEMENT_TYPE
    assert reloaded["predicateType"] == SCOPE_APPROVAL_PREDICATE_TYPE
    assert reloaded["subject"] == VALID_WIRE["subject"]
    assert reloaded["predicate"] == VALID_WIRE["predicate"]


def test_g_the_round_trip_is_lossless() -> None:
    statement = valid_statement()
    assert decode_approval(encode_approval(statement)) == statement


def test_g_the_round_trip_is_stable_under_repetition() -> None:
    once = encode_approval(valid_statement())
    twice = encode_approval(decode_approval(once))
    assert once == twice


def test_g_subject_comes_back_as_a_tuple_not_a_list() -> None:
    """A JSON array decodes to `tuple`, through the JSON-aware path, with strict member
    validation intact. This is the property `json.loads` + `model_validate` destroys."""
    statement = decode_approval(encode_approval(valid_statement()))
    assert isinstance(statement.subject, tuple)
    assert len(statement.subject) == 1
    assert isinstance(statement.subject[0], Subject)


def test_g_decode_accepts_the_same_bytes_as_the_same_text() -> None:
    encoded = encode_approval(valid_statement())
    assert decode_approval(encoded.encode("utf-8")) == decode_approval(encoded)


def test_g_decode_refuses_text_that_is_not_json() -> None:
    with pytest.raises(ValidationError):
        decode_approval("not json at all")


def test_g_decode_refuses_a_json_value_that_is_not_an_object() -> None:
    for payload in ("[]", '"a string"', "42", "null"):
        with pytest.raises(ValidationError):
            decode_approval(payload)


@pytest.mark.parametrize(
    "member",
    [5, "gplanner.scope/v1", None, True, [], 1.5],
    ids=["int", "string", "null", "bool", "array", "float"],
)
def test_g_a_subject_array_member_of_the_wrong_type_is_rejected(  # ST6-R06
    member: Any,
) -> None:
    """The frozen GP-05 acceptance row requires this case by name.

    `subject` is a JSON **array of objects**, and strict validation has to reach inside
    it. Section E's non-string case perturbs a scalar field (`approver_id`); this one
    perturbs an array member, which is the only place the JSON-aware tuple conversion
    and strict member checking meet.
    """
    payload = wire()
    payload["subject"] = [member]
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


def test_g_a_subject_member_with_a_broken_nested_digest_is_rejected() -> None:  # ST6-R06
    """Strict validation survives two levels of nesting, not just the array boundary."""
    payload = wire()
    payload["subject"] = [{"name": "gplanner.scope/v1", "digest": {"sha256": 5}}]
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


def test_g_the_forbidden_two_step_fails_on_an_approval_statement() -> None:  # ST6-R06
    """`json.loads(...)` + `model_validate(...)` is forbidden package-wide (§7), and the
    frozen GP-05 acceptance row requires that prohibition asserted **for approvals**.

    GP-03 proves it for `ScopeSpec` and the preimage envelope. That is a different model
    with a different field set, so it does not establish anything about
    `ApprovalStatement`: `subject` is a `tuple[Subject, ...]`, and `json.loads` produces
    a `list`, which strict validation refuses with `tuple_type`.

    The control matters as much as the failure. The **same bytes** decode cleanly through
    `decode_approval`, so what is being shown is that the two-step is broken, not that
    the statement was malformed.

    This and GP-03's equivalent are the only places the forbidden pattern appears in the
    repository, and both appear in order to prove it broken. The decode AST gate scans
    production modules, where it occurs nowhere.
    """
    blob = text(wire())
    assert decode_approval(blob) == valid_statement()

    with pytest.raises(ValidationError) as excinfo:
        ApprovalStatement.model_validate(json.loads(blob))

    errors = excinfo.value.errors()
    assert ("subject",) in {error["loc"] for error in errors}
    assert "tuple_type" in {error["type"] for error in errors}


def test_g_the_decoded_statement_is_immutable() -> None:
    statement = valid_statement()
    with pytest.raises(ValidationError):
        statement.predicate.decision = "REJECT"  # type: ignore[assignment]
    with pytest.raises(ValidationError):
        statement.subject[0].digest.sha256 = "0" * 64


# --- Section H: the limitations, asserted so they cannot be quietly dropped -------


@pytest.mark.parametrize(
    "approval_id",
    [
        "0" * 32,
        "f" * 32,
        "00000000000000000000000000000001",
        "deadbeefdeadbeefdeadbeefdeadbeef",
    ],
    ids=["all-zero", "all-f", "counter-like", "word-pattern"],
)
def test_h_a_hex32_that_is_not_a_uuid_v4_is_accepted(approval_id: str) -> None:
    """**Recorded limitation, not an oversight** (§8's table).

    `HEX32` checks 32 lowercase hex characters and nothing else. None of these values
    has uuid4's version or variant bits, and every one of them is accepted.

    uuid4 is relied on for **generation** — unpredictability and uniqueness. It is not
    relied on for validation, because version bits cannot establish where a value came
    from: asserting them would be a false assurance on an authority-bearing field.
    Single-use is enforced by the `approval_id` PRIMARY KEY (§12), not by its shape.

    This must not be silently strengthened. Adding a UUID-v4 check would make this test
    fail, which is the point.
    """
    payload = wire()
    payload["predicate"]["approval_id"] = approval_id
    assert decode_approval(text(payload)).predicate.approval_id == approval_id
    assert uuid.UUID(approval_id).version != 4


def test_h_a_uuid4_hex_is_also_accepted() -> None:
    """The generated form round-trips — the limitation is a widening, not a swap."""
    payload = wire()
    generated = uuid.uuid4().hex
    payload["predicate"]["approval_id"] = generated
    assert decode_approval(text(payload)).predicate.approval_id == generated


def test_h_a_stray_field_name_key_beside_a_valid_alias_is_dropped() -> None:
    """**Recorded limitation, measured on pydantic 2.13.5.** (Reviewer follow-up F1.)

    Under the alias configuration the plan fixes, an input carrying *both* spellings
    takes the alias and silently discards the field-name value — even an invalid one. An
    unrelated unknown key still raises `extra_forbidden`, which the assertion below
    pins so this is understood as alias-resolution precedence and not a hole in
    `extra="forbid"`.

    Closing it would need a root `model_validator(mode="before")`, which hands Pydantic a
    Python object and thereby **defeats the JSON-aware array → tuple mapping**: `subject`
    then fails with `tuple_type`, because the decode has silently become the
    `json.loads` + `model_validate` two-step §7 forbids package-wide. One was written
    during ST-6 and removed for exactly that reason; the reviewer recorded the behaviour
    as nonblocking and did not require the workaround.

    Pinned here so it cannot change unobserved, and so the trade-off stays a recorded
    decision rather than an unexamined default.
    """
    payload = wire()
    payload["type_"] = "a value that is about to be thrown away"
    statement = decode_approval(text(payload))
    assert statement == valid_statement()
    assert "type_" not in json.loads(encode_approval(statement))

    payload = wire()
    payload["unrelated"] = "x"
    with pytest.raises(ValidationError):
        decode_approval(text(payload))


def test_h_issued_at_is_syntax_only_with_no_clock_and_no_freshness() -> None:
    """§8: syntax only. No trusted clock, no freshness, no TTL, no ordering.

    A timestamp far in the past and one far in the future are both accepted, and the
    impossible calendar date proves no date arithmetic happens either. Freshness is
    deferred; recorded here so the deferral is visible rather than assumed.
    """
    for issued_at in ("1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "2026-02-30T00:00:00Z"):
        payload = wire()
        payload["predicate"]["issued_at"] = issued_at
        assert decode_approval(text(payload)).predicate.issued_at == issued_at


def test_h_the_human_label_is_enforced_but_authenticity_is_not_proven() -> None:
    """§11, verbatim: **HUMAN authority label enforced; human identity/authenticity not
    proven until the signing/authentication stage.**

    The executable half: an arbitrary, unauthenticated `approver_id` is accepted beside
    the `HUMAN` label, and nothing in this package detects it. `approvals.py` imports no
    cryptography and defines no signature field, so there is nothing here that *could*
    establish authenticity.
    """
    payload = wire()
    payload["predicate"]["approver_id"] = "not-a-real-person"
    statement = decode_approval(text(payload))
    assert statement.predicate.approver_kind is ActorKind.HUMAN
    assert statement.predicate.approver_id == "not-a-real-person"

    source = (SRC / "approvals.py").read_text(encoding="utf-8")
    assert "§11" in source or "11" in source
    assert not {"cryptography", "nacl", "jwt", "hashlib", "hmac"} & top_level_imports("approvals")


def test_h_the_statement_records_no_consumption_state() -> None:
    """§8: the record is immutable; consumption is a fact recorded elsewhere. A
    `consumed` flag here would change the statement's bytes, and therefore its digest,
    at the moment it is used."""
    names = set(ApprovalStatement.model_fields) | set(ScopeApprovalPredicate.model_fields)
    assert not names & {"consumed", "consumed_at", "status", "revision", "expires_at"}


# --- Section I: architecture boundaries ------------------------------------------


def test_i_approvals_imports_nothing_it_must_not() -> None:
    """`approvals` is a model layer: Pydantic plus the state vocabulary, nothing else.

    No store, no kernel, no DBOS, no workflow, no LLM SDK — and no `digest`, so the
    module cannot acquire an opinion about identity that competes with §6's.
    """
    roots = top_level_imports("approvals")
    assert roots == {"__future__", "re", "typing", "pydantic", "gplanner.states"}


def test_i_approvals_defines_no_serializer_and_no_decoder() -> None:
    """Every JSON → domain conversion lives in `codec` (§7), this one included."""
    attributes = attribute_names("approvals")
    assert "model_validate" not in attributes
    assert "model_validate_json" not in attributes
    assert not [name for name in attributes if name.startswith("model_dump")]


def test_i_codec_decodes_approvals_through_model_validate_json_only() -> None:
    """The single frozen decode call, carrying the frozen `gp_transport_decode` guard ID.

    Model-enforced rather than a deletable line: removing the call does not weaken a
    check, it removes decoding altogether. GP-SPK-002's harness mutates the *schema*
    here, which is why the ID is frozen now (CLAUDE.md, known gaps).
    """
    source = (SRC / "codec.py").read_text(encoding="utf-8")
    lines = [line for line in source.splitlines() if "# guard:gp_transport_decode" in line]
    assert len(lines) == 1
    assert "ApprovalStatement.model_validate_json(" in lines[0]

    attributes = attribute_names("codec")
    assert "model_validate" not in attributes
    assert attributes.count("model_validate_json") == 2, "one parse per decoder, no more"


def test_i_codec_remains_the_sole_json_to_domain_boundary() -> None:
    """No `json` import anywhere in the package, `codec` included: even the transport
    boundary reaches JSON only through Pydantic (§7)."""
    for module in sorted(path.stem for path in SRC.glob("*.py")):
        roots = top_level_imports(module)
        assert "json" not in roots, module
        assert not {name for name in roots if name.startswith("json.")}, module


def test_i_the_approval_encoder_is_not_an_identity_path() -> None:
    """`encode_approval` is transport, never identity.

    It emits Pydantic's JSON, which is **not** the RFC 8785 canonical preimage: no
    `payload_profile`, no `media_type`, no key ordering guarantee. Digesting its output
    would be exactly the second serialization path §7 exists to prevent, so `codec`
    still imports no serializer, computes no digest, and hashes nothing.
    """
    roots = top_level_imports("codec")
    assert "rfc8785" not in roots
    assert "hashlib" not in roots
    assert "gplanner.digest" in roots  # the Literal aliases only

    attributes = attribute_names("codec")
    assert "sha256" not in attributes
    assert "dumps" not in attributes and "loads" not in attributes

    encoded = encode_approval(valid_statement())
    assert "payload_profile" not in encoded
    assert "preimage_version" not in encoded


def test_i_importing_approvals_pulls_in_no_engine_and_no_llm_sdk() -> None:
    import sys

    assert approvals is not None and codec is not None
    assert "dbos" not in sys.modules
    assert not {"anthropic", "openai"} & sys.modules.keys()


def test_i_no_stage_beyond_the_current_one_has_appeared() -> None:
    """The scope fence, moved forward by exactly one stage at ST-7, and again at ST-8.

    Each move is the same single edit, for the same reason: a stage authorized to
    create a module (plan §22) and a test asserting that module absent cannot both
    hold. ST-7 removed `store`; ST-8 removes `kernel` and nothing else. `app` and
    `workflow` are ST-9 work and are still asserted absent, so the fence still fails
    loudly if a later stage's file appears early.
    """
    assert (SRC / "kernel.py").exists(), "ST-8 creates the kernel; the fence moves with it"
    for absent in ("app", "workflow"):
        assert not (SRC / f"{absent}.py").exists(), absent
