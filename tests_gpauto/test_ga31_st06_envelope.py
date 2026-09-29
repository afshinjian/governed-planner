"""`GP-AUTO-ST-06`: mechanical envelope derivation, `≤ ceiling`, equivalent-or-narrower, `C1`.

Design basis: AP-11 §16 `GP-AUTO-ST-06` (Tests: *"derived bounds ≤ ceiling; equal bounds
across cycles satisfy `AP03-I14`"*; Negative tests: *"no envelope carries a Git class outside
{none, bounded read}; reviewing envelope carrying `E-12` refused as malformed, not wider;
consumed envelope identity never reactivated"*); AP-03 §5 (`EV-1`…`EV-7`), `AP03-I07`,
`AP03-I13`…`AP03-I15`, `AP03-I18`, `AP03-I30`; AP-04 `C1`, `AP04-I12`, `AP04-I49`; the
frozen ST-06 clarification S6G2-3…S6G2-11, §17.

The envelope is its role's member copied, plus `E-14` from the frozen-set input. Every
relation is exercised dimension by dimension, and `C1` is exercised as ST-05 evaluates it:
over the facts this stage supplies and the two ST-07 and ST-08 supply.
"""

from __future__ import annotations

import ast
import inspect
from typing import Any

import pytest

import st06_world as w
from gpauto import authority
from gpauto import derivations as dv
from gpauto.absence import Carried, KnownAbsent, NotApplicable, Present
from gpauto.authorization import AuthorizationRecord
from gpauto.bounds import (
    ActionClass,
    AuthoritativeInputDesignation,
    AuthorityBounds,
    AuthorityCeilingMember,
    ReadBoundary,
    ToolCategory,
    WriteBoundary,
)
from gpauto.coordination_identity import CycleOccurrenceId, M1PositionEntryId
from gpauto.coordination_records import (
    AuthorityEnvelopeRecord,
    CycleOccurrence,
    M1PositionEntry,
    M3PositionEntry,
    RootResolutionRecord,
)
from gpauto.coordination_vocabulary import M1Edge, M2Edge, M2Position, M3Edge, M3Position
from gpauto.envelope import AuthorityEnvelope
from gpauto.identity import (
    AuthorityEnvelopeId,
    BaselineIdentityId,
    EntryStateBoundaryId,
    FrozenFindingSetId,
    GovernedStageId,
    OwnerAuthorizationId,
    RootResolutionId,
)
from gpauto.minting import mint_value
from gpauto.state_machine import Refused
from gpauto.state_machine_model import (
    BINDINGS_MATCH,
    BOUNDS_WITHIN_CEILING,
    DERIVATION_TOTAL,
    E14_REFERENCES_FROZEN_SET,
    E20_DESIGNATES_INPUTS,
    ENVELOPE_VALID,
    FALSE,
    NAMES_ROOT_INSTANCE,
    PREFLIGHT_PERMITTED,
    READ_ONLY_WITHOUT_WRITE_BOUNDARY,
    REMEDIATOR_BOUNDS,
    ROLE_AUTHORIZED,
    TRUE,
    UNACCOUNTED_MUTATION,
)
from gpauto.store import CoordinationStore, UnreadableRecord, WriteRefused
from gpauto.vocabulary import GitCapabilityClass, Role, WriteMode
from st03_world import fresh_store

GPAUTO_STAGE = "GP-AUTO-ST-06"

S = w.scope()
IMPL, DR, REM, BCV = w.WORKERS
S3, S4, S6, S7 = (
    M2Position.S3_IMPLEMENTATION_ACTIVE,
    M2Position.S4_DISCOVERY_ACTIVE,
    M2Position.S6_REMEDIATION_ACTIVE,
    M2Position.S7_CLOSURE_ACTIVE,
)
STEPS = {IMPL: S3, DR: S4, REM: S6, BCV: S7}
WITHIN, WIDER, MALFORMED = authority.Order


def _bounds(member: AuthorityCeilingMember, e14: Any = None) -> AuthorityBounds:
    """An envelope bounds value equal to `member` — what a correct derivation yields."""
    return AuthorityBounds(
        **{name: getattr(member, name) for name in AuthorityCeilingMember.model_fields},
        frozen_set_reference=e14 or NotApplicable(),
    )


def _root(content_changes: dict[str, Any] | None = None) -> authority.ResolvedRoot:
    """A resolved root for the pure derivation, outside any store."""
    return authority.ResolvedRoot(
        authorization=w.root_id(),
        content=authority.canonical_content(w.content(S, **(content_changes or {}))),
        resolution=RootResolutionRecord(
            identity=RootResolutionId(value="resolution"),
            project=S.project,
            stage=S.stage,
            predecessor_terminal_entry=KnownAbsent(basis="first"),
            candidates=(),
        ),
        records=(),
    )


BOUNDARY = EntryStateBoundaryId(value="boundary")
FROZEN = FrozenFindingSetId(value="frozen")
PRESENT = Present[FrozenFindingSetId](value=FROZEN)
NO_SET = KnownAbsent(basis="no set frozen yet")


def _envelope(epoch: w.Epoch, bounds: AuthorityBounds, **changes: Any) -> AuthorityEnvelope:
    values: dict[str, Any] = {
        "identity": AuthorityEnvelopeId(value=mint_value()),
        "resolved_root": epoch.root,
        "stage": S.stage,
        "entry_boundary": epoch.boundary.boundary.identity,
        "role": bounds.role_applicability,
        "bounds": bounds,
        "declared_closed": True,
    }
    return AuthorityEnvelope(**{**values, **changes})


def _all_roles(e: w.Epoch) -> dict[Role, AuthorityEnvelopeRecord]:
    """Every worker role's envelope, each derived at its own step on the findings branch."""
    w.to_findings_branch(e)
    implementer = e.handles["implementer"]
    assert isinstance(implementer, AuthorityEnvelopeRecord)
    derived = {IMPL: implementer}
    for role in (DR, REM):
        found = e.derive(role, STEPS[role])
        assert isinstance(found, authority.EnvelopeRecorded), (role, found)
        derived[role] = found.record
    s7 = w.m2(e.root, S7, M2Edge.B7, e.entries[S6], e.handles["cycle"].identity)  # type: ignore[attr-defined]
    e.store.create(s7)
    e.entries[S7] = s7
    found = e.derive(BCV, S7)
    assert isinstance(found, authority.EnvelopeRecorded), found
    derived[BCV] = found.record
    return derived


@pytest.mark.traces(
    "ST06C-I02", "ST06-D4", "ST06-T3", "EV-2", "EV-3", "EV-7", "AP03-I13", "AP03-I14"
)
def test_each_worker_role_derives_its_member_copied_plus_e14_from_the_frozen_set() -> None:
    """S6G2-4: each role's envelope bounds are its member, field for field, plus `E-14` —
    `Carried(set)` for REMEDIATOR and BCV, `NotApplicable` for IMPLEMENTER and DR. Each is
    recorded with its `ENVELOPE_DERIVED` entry, names the resolved instance and its
    boundary, and names no other envelope: roles' envelopes are independent (`EV-7`)."""
    with fresh_store() as store:
        invalid_sibling = w.record(S, "record-z", owner_human_label_present=False)
        e = w.resolved_epoch(store, S, w.record(S, "record-a"), invalid_sibling)
        derived = _all_roles(e)
        frozen = e.handles["frozen"].identity  # type: ignore[attr-defined]
        for role, found in derived.items():
            envelope = found.envelope
            member = w.member_of(w.ceiling(S), role)
            e14 = Carried[FrozenFindingSetId](value=frozen) if role in (REM, BCV) else None
            assert envelope.bounds == _bounds(member, e14), role
            assert envelope.role == role and envelope.declared_closed
            assert envelope.resolved_root == e.root
            assert envelope.entry_boundary == e.boundary.boundary.identity
            assert found.target_state == STEPS[role]
            assert authority.within_ceiling(envelope.bounds, w.ceiling(S)) == WITHIN
        identities = {found.envelope.identity for found in derived.values()}
        assert len(identities) == 4
        entries = [m for m in store.enumerate(M3PositionEntry) if isinstance(m, M3PositionEntry)]
        assert {(m.identity.envelope, m.state, m.edge) for m in entries} == {
            (i, M3Position.ENVELOPE_DERIVED, M3Edge.C1) for i in identities
        }


@pytest.mark.supports("AP04-I49")
@pytest.mark.traces("ST06C-I03", "EV-4", "ST06-D4")
def test_derivation_is_a_total_function_of_exactly_five_inputs() -> None:
    """`EV-4`, S6G2-8: exactly five inputs — root, role, branch, frozen set, boundary —
    and no `CYCLE_BOUND`, obligation, closure record or envelope identity is read, by the
    derivation or by the reader of its inputs. Identical inputs, identical output."""
    parameters = list(inspect.signature(authority.derive_envelope).parameters)
    assert parameters == ["root", "role", "branch", "frozen_set", "boundary"]
    forbidden = {
        "CYCLE_BOUND", "derive_cycle_bound", "CycleBound", "RemediationObligation",
        "ClosureAssessmentRecord", "AuthorityEnvelopeId", "mint_value", "identity",
    }  # fmt: skip
    source = inspect.getsource(authority)
    tree = ast.parse(source)
    for name in ("derive_envelope", "envelope_inputs", "_frozen_set_reference"):
        (function,) = [
            n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name
        ]
        names = {n.id for n in ast.walk(function) if isinstance(n, ast.Name)}
        attributes = {n.attr for n in ast.walk(function) if isinstance(n, ast.Attribute)}
        assert not (names | attributes) & (forbidden - {"identity"}), name
        assert "identity" not in names, name
    root = _root()
    first = authority.derive_envelope(root, REM, S6, PRESENT, BOUNDARY)
    second = authority.derive_envelope(root, REM, S6, PRESENT, BOUNDARY)
    assert isinstance(first, authority.DerivedEnvelope) and first == second


@pytest.mark.traces("AP03-I14", "ST06-T4", "ST06C-I03", "ST06-D4")
def test_identical_inputs_in_a_later_cycle_give_equal_bounds_and_a_fresh_identity() -> None:
    """S6G2-9, `OP-5`, `OP-6`: a second cycle's REMEDIATOR envelope — its own `MC-15` key,
    after `B15` — has bounds equal to the first cycle's and a distinct, freshly minted
    identity. Equal is the *equivalent* case of equivalent-or-narrower."""
    with fresh_store() as store:
        e = w.resolved_epoch(store, S)
        derived = _all_roles(e)
        s6 = w.m2(e.root, S6, M2Edge.B15, e.entries[S7])
        cycle = CycleOccurrence(
            identity=CycleOccurrenceId(value=mint_value()),
            establishing_edge=M2Edge.B15,
            predecessor_entry=e.entries[S7].identity,
            target_state=M2Position.S6_REMEDIATION_ACTIVE,
            predecessor_closure_activation=w.ABSENT,
            envelope=w.ABSENT,
            activation=w.ABSENT,
        )
        store.create_unit((cycle, s6))
        second = authority.record_envelope(
            store,
            e.root,
            REM,
            S6,
            e.entries[S7].identity,
            Present[CycleOccurrenceId](value=cycle.identity),
            dict(w.SUPPLIED),
        )
        assert isinstance(second, authority.EnvelopeRecorded) and not second.replayed
        first = derived[REM].envelope
        assert second.record.envelope.bounds == first.bounds
        assert second.record.envelope.identity != first.identity
        assert authority.equivalent_or_narrower(second.record.envelope.bounds, first.bounds) == (
            WITHIN
        )


@pytest.mark.traces("AP03-I13", "AP03-I15", "ST06C-I04", "ST06-T3", "ST06-M3", "ST06-N5")
def test_bounds_within_the_ceiling_and_each_wider_dimension_refused() -> None:
    """S6G2-6: every one of the ten conveyed dimensions is `≤` the role's member, exact
    tokens only. Each dimension widened alone is `WIDER`; a reviewing envelope carrying
    `E-12` is `MALFORMED`, never wider (`AP03-I15`)."""
    ceiling = w.ceiling(S)
    writer, reviewer = _bounds(w.writer(S)), _bounds(w.reviewer(S))
    assert authority.within_ceiling(writer, ceiling) == WITHIN
    assert authority.within_ceiling(reviewer, ceiling) == WITHIN
    wider: tuple[tuple[str, AuthorityBounds], ...] = (
        ("scope frame", writer.model_copy(update={"scope_frame": S.frame().model_copy(
            update={"baseline": BaselineIdentityId(value="other")})})),
        ("actions", writer.model_copy(
            update={"action_classes": (*writer.action_classes, ActionClass(name="x"))})),
        ("tools", writer.model_copy(
            update={"tool_categories": (*writer.tool_categories, ToolCategory(name="x"))})),
        ("external", writer.model_copy(update={"external_action_classes": (w.SIDE_EFFECT,)})),
        ("reads", writer.model_copy(update={"read_boundary": ReadBoundary(scopes=("docs/",))})),
        ("writes", writer.model_copy(update={"write_boundary": Carried[WriteBoundary](
            value=WriteBoundary(scopes=("docs/",)))})),
        ("git", writer.model_copy(
            update={"git_capability_class": GitCapabilityClass.BOUNDED_READ})),
        ("write mode", reviewer.model_copy(update={"write_mode": WriteMode.WRITING})),
        ("designation", reviewer.model_copy(update={
            "authoritative_input_designation": Carried[AuthoritativeInputDesignation](
                value=AuthoritativeInputDesignation(designated_scopes=("docs/",)))})),
    )  # fmt: skip
    for name, bounds in wider:
        assert authority.within_ceiling(bounds, ceiling) == WIDER, name
    malformed = reviewer.model_copy(update={"write_boundary": w.writer(S).write_boundary})
    assert authority.within_ceiling(malformed, ceiling) == MALFORMED
    narrower = writer.model_copy(update={"action_classes": (ActionClass(name="edit"),)})
    assert authority.within_ceiling(narrower, ceiling) == WITHIN
    orphan = writer.model_copy(update={"role_applicability": Role.COORDINATOR})
    assert authority.within_ceiling(orphan, ceiling) == WIDER


@pytest.mark.traces("AP03-I14", "ST06C-I04", "ST06-M4")
def test_equivalent_or_narrower_ranges_over_all_eleven_dimensions() -> None:
    """S6G2-7: `later ≤ prior`, `E-14` included — equal only for the same frozen set, or
    both inapplicable; a mixed `E-14` pair is malformed. Identity is never a term."""
    remediator = _bounds(w.writer(S, REM), Carried[FrozenFindingSetId](value=FROZEN))
    other_set = remediator.model_copy(
        update={"frozen_set_reference": Carried[FrozenFindingSetId](
            value=FrozenFindingSetId(value="other"))}
    )  # fmt: skip
    no_set = remediator.model_copy(update={"frozen_set_reference": NotApplicable()})
    narrower = remediator.model_copy(update={"action_classes": ()})
    other_role = remediator.model_copy(update={"role_applicability": IMPL})
    assert authority.equivalent_or_narrower(remediator, remediator) == WITHIN
    assert authority.equivalent_or_narrower(narrower, remediator) == WITHIN
    assert authority.equivalent_or_narrower(remediator, narrower) == WIDER
    assert authority.equivalent_or_narrower(other_set, remediator) == WIDER
    assert authority.equivalent_or_narrower(remediator, no_set) == MALFORMED
    assert authority.equivalent_or_narrower(other_role, remediator) == WIDER


def _two_epochs(store: CoordinationStore) -> tuple[w.Epoch, w.Epoch]:
    """Two resolved roots, each for its own stage, in one store, both on the findings
    branch — so every per-root selection has another root's record beside it."""
    other = w.scope("-other")
    w.supply(store, other, [w.record(other, "other-a", "other-root")])
    w.resolve(store, other)
    second = w.epoch(store, other, w.root_id("other-root"))
    w.to_findings_branch(second)
    first = w.resolved_epoch(store, S)
    w.to_findings_branch(first)
    return first, second


@pytest.mark.traces("AP03-I14", "EV-3", "ST06-M4", "ST06-M3")
def test_c1_refuses_an_envelope_wider_than_a_prior_one_or_beside_one_above_the_ceiling() -> None:
    """`AP03-I14` at `C1`: a later envelope for the same root, stage, role and boundary must
    be `≤` every prior one; and *union ≤ ceiling* — every envelope of the root within its
    own member. Another root's envelopes are not this root's priors."""
    with fresh_store() as store:
        first, _ = _two_epochs(store)
        found = first.derive(DR, S4)
        assert isinstance(found, authority.EnvelopeRecorded), found
    for prior_bounds, expected in (
        (_bounds(w.writer(S)).model_copy(update={"action_classes": ()}), WIDER),
        (_bounds(w.writer(S)).model_copy(update={"external_action_classes": (w.EGRESS,)}), WIDER),
    ):
        with fresh_store() as store:
            e = w.resolved_epoch(store, S)
            prior = AuthorityEnvelopeRecord(
                envelope=_envelope(e, prior_bounds),
                cycle_occurrence=w.ABSENT,
                predecessor_entry=e.entries[M2Position.S1_EPOCH_OPENED].identity,
                target_state=S3,
            )
            store.create(prior)
            refused = e.derive(IMPL, S3)
            assert isinstance(refused, authority.NarrowingRefused), refused
            assert (refused.prior, refused.order) == (prior.envelope.identity, expected)
            envelopes = store.enumerate(AuthorityEnvelopeRecord)
            assert envelopes == (prior,)


# --- unreadable envelope-path inputs fail closed (VM-6, RC-4) -----------------------------


@pytest.mark.traces("ST06C-I05", "ST06-M2", "AP03-I14")
def test_an_unreadable_prior_envelope_fails_c1_closed_and_records_nothing() -> None:
    """`VM-6`, `AP03-I14`: a prior `RC-18` the store cannot interpret might be the narrower
    one. Readable, the narrower prior refuses the wider envelope; unreadable, `C1` is
    indeterminate — never decided over the readable remainder — and no envelope and no
    `C1` entry is written."""
    narrower = _bounds(w.writer(S)).model_copy(update={"action_classes": ()})
    for readable in (True, False):
        with fresh_store() as store:
            e = w.resolved_epoch(store, S)
            prior = AuthorityEnvelopeRecord(
                envelope=_envelope(e, narrower),
                cycle_occurrence=w.ABSENT,
                predecessor_entry=e.entries[M2Position.S1_EPOCH_OPENED].identity,
                target_state=S3,
            )
            if readable:
                store.create(prior)
            else:
                w.write_unreadable(store, prior)
            found = e.derive(IMPL, S3)
            envelopes = store.enumerate(AuthorityEnvelopeRecord)
            if readable:
                assert isinstance(found, authority.NarrowingRefused), found
                assert (found.prior, found.order) == (prior.envelope.identity, WIDER)
                assert envelopes == (prior,)
            else:
                assert isinstance(found, dv.Indeterminate), found
                assert found.cause == dv.IndeterminacyCause.UNREADABLE_INPUT
                assert len(envelopes) == 1 and isinstance(envelopes[0], UnreadableRecord)
            assert store.enumerate(M3PositionEntry) == ()


@pytest.mark.traces("ST06C-I05", "ST06-M2", "EV-4", "EV-6")
def test_an_unreadable_frozen_set_is_indeterminate_and_never_an_absence() -> None:
    """`VM-6`, `EV-4`: the frozen-set input is `KnownAbsent` only from a determinate read
    holding no unreadable `RC-26`, and `Present` only from a determinate read. An
    unreadable set makes the input indeterminate, so REMEDIATOR and BCV get no
    `NotDerivable(NO_FROZEN_SET)` from a false absence, and nothing is written."""
    with fresh_store() as store:
        e = w.resolved_epoch(store, S)
        found = authority.envelope_inputs(authority.read_authority_records(store), e.root, REM, S6)
        assert isinstance(found, authority.EnvelopeInputs), found
        assert isinstance(found.frozen_set, KnownAbsent)
    with fresh_store() as store:
        e = w.to_findings_branch(w.resolved_epoch(store, S))
        found = authority.envelope_inputs(authority.read_authority_records(store), e.root, REM, S6)
        assert isinstance(found, authority.EnvelopeInputs), found
        frozen = e.handles["frozen"].identity  # type: ignore[attr-defined]
        assert found.frozen_set == Present[FrozenFindingSetId](value=frozen)
    with fresh_store() as store:
        e = w.to_findings_branch(w.resolved_epoch(store, S), readable_set=False)
        found = authority.envelope_inputs(authority.read_authority_records(store), e.root, REM, S6)
        assert isinstance(found, dv.Indeterminate), found
        assert found.cause == dv.IndeterminacyCause.UNREADABLE_INPUT
        cycle = e.handles["cycle"]
        assert isinstance(cycle, CycleOccurrence)
        s7 = w.m2(e.root, S7, M2Edge.B7, e.entries[S6], cycle.identity)
        store.create(s7)
        e.entries[S7] = s7
        before = store.enumerate(AuthorityEnvelopeRecord)
        for role in (REM, BCV):
            derived = e.derive(role, STEPS[role])
            assert isinstance(derived, dv.Indeterminate), (role, derived)
            assert derived.cause == dv.IndeterminacyCause.UNREADABLE_INPUT, role
        assert store.enumerate(AuthorityEnvelopeRecord) == before


@pytest.mark.traces("ST06C-I05", "ST06-M2", "EV-1")
def test_an_unreadable_root_instance_input_is_indeterminate_and_records_nothing() -> None:
    """`VM-6`, `EV-1`: an `RC-14` the store cannot interpret might be the occurrence the
    root was resolved in. The root is then not read from the readable remainder: the
    envelope is indeterminate, `B2-0`'s fact is absent, and nothing is written."""
    with fresh_store() as store:
        e = w.resolved_epoch(store, S)
        (occurrence,) = [
            r for r in store.enumerate(RootResolutionRecord) if isinstance(r, RootResolutionRecord)
        ]
        (a2,) = [
            m
            for m in store.enumerate(M1PositionEntry)
            if isinstance(m, M1PositionEntry) and m.edge == M1Edge.A2
        ]
        w.write_unreadable(
            store,
            occurrence.model_copy(
                update={
                    "identity": RootResolutionId(value=mint_value()),
                    "predecessor_terminal_entry": Present[M1PositionEntryId](value=a2.identity),
                }
            ),
        )
        records = authority.read_authority_records(store)
        assert authority.root_facts(records, e.root) == {}
        found = e.derive(IMPL, S3)
        assert isinstance(found, dv.Indeterminate), found
        assert found.cause == dv.IndeterminacyCause.UNREADABLE_INPUT
        assert store.enumerate(AuthorityEnvelopeRecord) == ()
        assert store.enumerate(M3PositionEntry) == ()


@pytest.mark.traces("AP03-I15", "ST06-N5", "EV-1", "ST06-M5")
def test_an_inapplicable_dimension_present_is_malformed_not_wider() -> None:
    """§3.2, `AP03-I15`: `E-12` only for writers, `E-20` only for reviewers, `E-14` only for
    REMEDIATOR and BCV, and only worker roles. Anything else is malformed."""
    writer, reviewer = _bounds(w.writer(S)), _bounds(w.reviewer(S))
    carried_set = Carried[FrozenFindingSetId](value=FROZEN)
    assert authority.envelope_applicability(writer)
    assert authority.envelope_applicability(reviewer)
    assert authority.envelope_applicability(_bounds(w.writer(S, REM), carried_set))
    for name, bounds in (
        ("writer with E-20", writer.model_copy(
            update={"authoritative_input_designation": reviewer.authoritative_input_designation})),
        ("reviewer with E-12", reviewer.model_copy(
            update={"write_boundary": writer.write_boundary})),
        ("implementer with E-14", writer.model_copy(update={"frozen_set_reference": carried_set})),
        ("remediator without E-14", _bounds(w.writer(S, REM))),
        ("a coordinator envelope", writer.model_copy(update={
            "role_applicability": Role.COORDINATOR, "write_boundary": NotApplicable()})),
    ):  # fmt: skip
        assert not authority.envelope_applicability(bounds), name


@pytest.mark.traces("ST06-N4", "ST06-M5", "AP03-I18", "ST06C-I02")
def test_role_and_write_mode_hold_and_git_is_never_outside_none_or_bounded_read() -> None:
    """Writers `WRITING` with Git `NONE`; reviewers `READ_ONLY` with Git `BOUNDED_READ`;
    `E-16` at most the declarable side-effect class. The Git type admits nothing but
    `NONE` and `BOUNDED_READ`, so no envelope can carry staging, commit or push."""
    assert set(GitCapabilityClass) == {GitCapabilityClass.NONE, GitCapabilityClass.BOUNDED_READ}
    writer, reviewer = _bounds(w.writer(S)), _bounds(w.reviewer(S))
    assert authority.envelope_role_shape(writer) and authority.envelope_role_shape(reviewer)
    effect = writer.model_copy(update={"external_action_classes": (w.SIDE_EFFECT,)})
    assert authority.envelope_role_shape(effect)
    for name, bounds in (
        ("writer with Git read", writer.model_copy(
            update={"git_capability_class": GitCapabilityClass.BOUNDED_READ})),
        ("writer read-only", writer.model_copy(update={"write_mode": WriteMode.READ_ONLY})),
        ("reviewer writing", reviewer.model_copy(update={"write_mode": WriteMode.WRITING})),
        ("reviewer without Git read", reviewer.model_copy(
            update={"git_capability_class": GitCapabilityClass.NONE})),
        ("egress", writer.model_copy(update={"external_action_classes": (w.EGRESS,)})),
    ):  # fmt: skip
        assert not authority.envelope_role_shape(bounds), name


@pytest.mark.traces("ST06C-I02", "ST06-D4", "EV-6")
def test_the_side_effect_class_is_copied_from_the_member_and_never_added() -> None:
    """S6G2-11: carried by the member ⇒ carried by the envelope; absent ⇒ never added."""
    ceiling = w.replace_member(w.ceiling(S), IMPL, external_action_classes=(w.SIDE_EFFECT,))
    root = _root({"authority_ceiling": ceiling})
    implementer = authority.derive_envelope(root, IMPL, S3, NO_SET, BOUNDARY)
    reviewer = authority.derive_envelope(root, DR, S4, NO_SET, BOUNDARY)
    assert isinstance(implementer, authority.DerivedEnvelope)
    assert isinstance(reviewer, authority.DerivedEnvelope)
    assert implementer.bounds.external_action_classes == (w.SIDE_EFFECT,)
    assert reviewer.bounds.external_action_classes == ()


@pytest.mark.traces("AP03-I30", "AP04-I12", "EV-6", "ST06-D4")
def test_no_envelope_exists_for_a_role_not_activated_on_the_branch_taken() -> None:
    """`EV-6`, `AP03-I30`, `AP04-I12`: REMEDIATOR and BCV have no envelope off the findings
    branch's steps or without a frozen set; a role outside `RA-06`, or a non-worker role,
    has none at all. The absence is correct and is not a stripped authority."""
    root = _root()
    reason = authority.NotDerivableReason
    cases = (
        (root, REM, S3, PRESENT, reason.NOT_ACTIVATED_ON_BRANCH),
        (root, BCV, S4, PRESENT, reason.NOT_ACTIVATED_ON_BRANCH),
        (root, REM, S6, NO_SET, reason.NO_FROZEN_SET),
        (root, IMPL, S4, NO_SET, reason.NOT_ACTIVATED_ON_BRANCH),
        (
            _root({"authorized_roles": (*w.WORKERS, Role.COORDINATOR)}),
            Role.COORDINATOR,
            S3,
            NO_SET,
            reason.NOT_ACTIVATED_ON_BRANCH,
        ),
        (
            _root({"authorized_roles": (IMPL, DR, REM), "authority_ceiling": w.ceiling(S)[:3]}),
            BCV,
            S7,
            PRESENT,
            reason.ROLE_NOT_AUTHORIZED,
        ),
    )
    for resolved, role, step, frozen, why in cases:
        found = authority.derive_envelope(resolved, role, step, frozen, BOUNDARY)
        assert found == authority.NotDerivable(why), (role, step)


@pytest.mark.traces("AP03-I07", "M1-1", "EV-1", "AP03-I01")
def test_nothing_is_derived_without_a_resolved_root_and_a_fixed_boundary() -> None:
    """`AP03-I07`, `M1-1`: no envelope before `ROOT_RESOLVED`, none without the root's entry
    boundary, and none naming an instance no `A2` entry resolved (`EV-1`, `AP03-I01`)."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a")])
        s1 = w.m2(w.root_id(), M2Position.S1_EPOCH_OPENED, M2Edge.B1, None)
        store.create(s1)
        opened = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened)
        early = authority.record_envelope(
            store, w.root_id(), IMPL, S3, s1.identity, w.ABSENT, dict(w.SUPPLIED)
        )
        assert isinstance(early, dv.Indeterminate)
        authority.complete_resolution(store, opened.resolution)
        unfixed = authority.record_envelope(
            store, w.root_id(), IMPL, S3, s1.identity, w.ABSENT, dict(w.SUPPLIED)
        )
        assert isinstance(unfixed, dv.Indeterminate)
        assert unfixed.cause == dv.IndeterminacyCause.MISSING_RECORD
        assert store.enumerate(AuthorityEnvelopeRecord) == ()
        records = authority.read_authority_records(store)
        assert authority.root_facts(records, w.root_id()) == {PREFLIGHT_PERMITTED.name: TRUE}
        assert authority.root_facts(records, OwnerAuthorizationId(value="unresolved")) == {}


@pytest.mark.traces("ST06-M3", "ST06-M5", "ST06C-I02", "EV-1", "ST06-D4")
def test_the_c1_facts_of_each_envelope_and_of_each_defect() -> None:
    """Every ST-06 `C1` fact for each role's derived envelope, and each defect falsifying
    exactly the fact that reads it: a wider value, another boundary or stage, a malformed
    or mis-shaped value, an open marker, another role, and an envelope naming another
    instance than the epoch's resolved root."""
    with fresh_store() as store:
        e = w.resolved_epoch(store, S)
        derived = _all_roles(e)
        records = authority.read_authority_records(store)

        def facts(envelope: AuthorityEnvelope) -> dict[str, str]:
            return authority.envelope_facts(records, envelope, e.root, STEPS[envelope.role])

        common = {ROLE_AUTHORIZED.name: TRUE, BOUNDS_WITHIN_CEILING.name: TRUE}
        common |= {DERIVATION_TOTAL.name: TRUE, ENVELOPE_VALID.name: TRUE}
        common |= {NAMES_ROOT_INSTANCE.name: TRUE, BINDINGS_MATCH.name: TRUE}
        per_role = {
            IMPL: (FALSE, FALSE, FALSE, FALSE),
            DR: (FALSE, FALSE, TRUE, TRUE),
            REM: (TRUE, TRUE, FALSE, FALSE),
            BCV: (TRUE, FALSE, TRUE, TRUE),
        }
        for role, (e14, remediator, read_only, e20) in per_role.items():
            assert facts(derived[role].envelope) == common | {
                E14_REFERENCES_FROZEN_SET.name: e14,
                REMEDIATOR_BOUNDS.name: remediator,
                READ_ONLY_WITHOUT_WRITE_BOUNDARY.name: read_only,
                E20_DESIGNATES_INPUTS.name: e20,
            }, role
        implementer = derived[IMPL].envelope
        reviewer = derived[DR].envelope
        widened = implementer.model_copy(
            update={
                "bounds": implementer.bounds.model_copy(
                    update={"tool_categories": (ToolCategory(name="x"),)}
                )
            }
        )
        malformed = reviewer.model_copy(
            update={
                "bounds": reviewer.bounds.model_copy(
                    update={"write_boundary": implementer.bounds.write_boundary}
                )
            }
        )
        misshaped = reviewer.model_copy(
            update={"bounds": reviewer.bounds.model_copy(update={"write_mode": WriteMode.WRITING})}
        )
        cases: tuple[tuple[str, AuthorityEnvelope, dict[str, str]], ...] = (
            ("wider", widened, {BOUNDS_WITHIN_CEILING.name: FALSE, DERIVATION_TOTAL.name: FALSE}),
            ("another boundary", implementer.model_copy(
                update={"entry_boundary": EntryStateBoundaryId(value="x")}),
                {DERIVATION_TOTAL.name: FALSE}),
            ("another stage", implementer.model_copy(
                update={"stage": GovernedStageId(value="x")}),
                {DERIVATION_TOTAL.name: FALSE, ENVELOPE_VALID.name: FALSE}),
            ("malformed", malformed, {
                BOUNDS_WITHIN_CEILING.name: FALSE, DERIVATION_TOTAL.name: FALSE,
                ENVELOPE_VALID.name: FALSE, READ_ONLY_WITHOUT_WRITE_BOUNDARY.name: FALSE}),
            ("mis-shaped", misshaped, {
                BOUNDS_WITHIN_CEILING.name: FALSE, DERIVATION_TOTAL.name: FALSE,
                ENVELOPE_VALID.name: FALSE, READ_ONLY_WITHOUT_WRITE_BOUNDARY.name: FALSE}),
            ("open", implementer.model_copy(update={"declared_closed": False}),
                {ENVELOPE_VALID.name: FALSE}),
            ("another instance", implementer.model_copy(
                update={"resolved_root": OwnerAuthorizationId(value="x")}),
                {NAMES_ROOT_INSTANCE.name: FALSE}),
        )  # fmt: skip
        for name, envelope, changed in cases:
            source = reviewer if envelope.role == DR else implementer
            assert facts(envelope) == facts(source) | changed, name
        other_role = implementer.model_copy(update={"role": REM})
        assert facts(other_role)[ENVELOPE_VALID.name] == FALSE


@pytest.mark.supports("EV-5")
@pytest.mark.traces("ST06-N6", "ST06-R1")
def test_a_c1_replay_mints_nothing_and_an_envelope_identity_is_never_reused() -> None:
    """`MC-15`, `EV-5`, `NV11-2`: a replayed `C1` finds its envelope by the derivation key and
    mints no second identity; and the store refuses a second record under one envelope
    identity, so a consumed identity cannot be revived by re-recording it."""
    with fresh_store() as store:
        e = w.resolved_epoch(store, S)
        first = e.derive(IMPL, S3)
        again = e.derive(IMPL, S3)
        assert isinstance(first, authority.EnvelopeRecorded) and not first.replayed
        assert isinstance(again, authority.EnvelopeRecorded) and again.replayed
        assert again.record == first.record and again.entry == first.entry
        assert len(store.enumerate(AuthorityEnvelopeRecord)) == 1
        revived = first.record.model_copy(
            update={"predecessor_entry": e.entries[M2Position.S1_EPOCH_OPENED].identity}
        )
        with pytest.raises(WriteRefused):
            store.create(revived)


@pytest.mark.traces("ST06-D4", "ST06-G1")
def test_c1_is_st05s_to_admit_and_only_two_facts_may_be_supplied() -> None:
    """ST-05 decides `C1`: an unaccounted mutation (ST-08's fact) refuses it and nothing is
    written. A caller may supply only `BOUNDARY_FIXED` and `UNACCOUNTED_MUTATION` — never a
    fact of ST-06's own."""
    with fresh_store() as store:
        e = w.resolved_epoch(store, S)
        predecessor = e.predecessor(S3).identity
        supplied = dict(w.SUPPLIED) | {UNACCOUNTED_MUTATION.name: TRUE}
        refused = authority.record_envelope(
            store, e.root, IMPL, S3, predecessor, w.ABSENT, supplied
        )
        assert isinstance(refused, Refused) and refused.edge == M3Edge.C1
        assert store.enumerate(AuthorityEnvelopeRecord) == ()
        with pytest.raises(ValueError):
            authority.record_envelope(
                store,
                e.root,
                IMPL,
                S3,
                predecessor,
                w.ABSENT,
                dict(w.SUPPLIED) | {BOUNDS_WITHIN_CEILING.name: TRUE},
            )


@pytest.mark.traces("ST06-D4", "ST06C-I02")
def test_the_root_is_the_instance_whichever_equivalent_record_carries_it() -> None:
    """The root input is the constituted instance: two content-equivalent records whose
    set-valued dimensions are written in different orders, with a token repeated, give
    one canonical content — so the bounds do not depend on which record is read."""
    reordered = tuple(
        m.model_copy(
            update={
                "action_classes": tuple(reversed(m.action_classes)) + m.action_classes[:1],
                "read_boundary": ReadBoundary(scopes=tuple(reversed(m.read_boundary.scopes))),
            }
        )
        for m in reversed(w.ceiling(S))
    )
    first = w.record(S, "record-a")
    second: AuthorizationRecord = w.record(S, "record-b", authority_ceiling=reordered)
    assert authority.canonical_content(first.content) == authority.canonical_content(second.content)
    with fresh_store() as store:
        e = w.resolved_epoch(store, S, first, second)
        found = e.derive(IMPL, S3)
        assert isinstance(found, authority.EnvelopeRecorded)
        assert found.record.envelope.bounds == _bounds(w.writer(S))


@pytest.mark.traces("ST06-M3", "ST06-M5", "EV-1")
def test_per_root_inputs_are_read_for_the_named_root_only() -> None:
    """Each root's resolution, records, boundary and frozen set are its own: with a second
    resolved root in the store, each epoch derives from its own inputs alone."""
    with fresh_store() as store:
        first, second = _two_epochs(store)
        for epoch in (first, second):
            found = epoch.derive(REM, S6)
            assert isinstance(found, authority.EnvelopeRecorded), found
            frozen = epoch.handles["frozen"].identity  # type: ignore[attr-defined]
            assert found.record.envelope.bounds.frozen_set_reference == Carried[FrozenFindingSetId](
                value=frozen
            )
            assert found.record.envelope.entry_boundary == epoch.boundary.boundary.identity
            assert found.record.envelope.resolved_root == epoch.root
