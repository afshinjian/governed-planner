"""Design basis: ST-09 plan §6.4–§6.6; AP-05 OB, RM, CL, SC, PF and OD."""

from __future__ import annotations

from dataclasses import replace
from typing import Literal

import pytest
from pydantic import ValidationError

import st09_world as w
from gpauto import finding_lifecycle as f
from gpauto.absence import Present
from gpauto.coordination_records import (
    ClosureAssessmentRecord,
    FindingItem,
    MemberClosureResultItem,
    OutcomeIngestionRecord,
    PostFreezeCandidateItem,
    PostFreezeCandidateRecord,
)
from gpauto.coordination_vocabulary import ClosedVerdict, M2Edge, M2Position, NotClosedVerdict
from gpauto.governance import ObligationExtinguishingDecision, OwnerDecision
from gpauto.identity import (
    ClosureAssessmentId,
    FindingId,
    OwnerDecisionId,
    PostFreezeCandidateId,
    RemediationObligationId,
)
from gpauto.review import ClosureAssessment, FrozenFindingSet, RemediationObligation
from gpauto.vocabulary import OwnerDecisionKind, Role
from st03_ingest import ingest
from st03_world import world as original_world
from st04_world import token

GPAUTO_STAGE = "GP-AUTO-ST-09"


@pytest.mark.traces("ST09-N5", "SC-2", "SC-3", "SC-6")
def test_unavailable_closure_inputs_remain_indeterminate() -> None:
    for record_class in (OutcomeIngestionRecord, FrozenFindingSet):
        for knowledge in ("unreadable", "unstable"):
            with w.world() as x:
                frozen, occurrence = w.freeze_enter(x)
                closer = w.close_cycle(x, frozen, occurrence, persist=False)
                records = x.snapshot()
                assert f.closure_admissibility(records, closer.identity) == f.Admissible()
                unavailable = (
                    replace(records, unreadable=frozenset({record_class}))
                    if knowledge == "unreadable"
                    else replace(records, unstable=frozenset({record_class}))
                )
                assert f.closure_admissibility(
                    unavailable, closer.identity
                ) == f.LifecycleIndeterminate(f.LifecycleCause.UNREADABLE_RECORDS)
                ingestion = next(
                    r
                    for r in records.records
                    if isinstance(r, OutcomeIngestionRecord) and r.activation == closer.identity
                )
                for items, cause in (
                    ((FindingItem(),), f.LifecycleCause.OUTCOME_NONCONFORMANT),
                    ((ingestion.items[0],) * 2, f.LifecycleCause.OUTCOME_NONCONFORMANT),
                    (
                        (
                            MemberClosureResultItem(
                                member=FindingId(value="non-member"), verdict=ClosedVerdict()
                            ),
                        ),
                        f.LifecycleCause.NON_MEMBER_ASSESSED,
                    ),
                ):
                    nonconformant = replace(
                        records,
                        records=tuple(
                            r.model_copy(update={"items": items}) if r == ingestion else r
                            for r in records.records
                        ),
                    )
                    assert f.closure_admissibility(
                        nonconformant, closer.identity
                    ) == f.Nonconformant((cause,))


@pytest.mark.traces("ST09-D5", "PF-1", "PF-2", "PF-3", "AP04-I30")
def test_raising_a_candidate_writes_only_candidates() -> None:
    assert hasattr(f, "record_post_freeze_candidates"), "candidate act is absent"
    with w.world() as x:
        frozen = f.freeze(x.store, x.discovery().identity, w.B5)
        assert isinstance(frozen, f.Frozen)
        first = f.enter_first_occurrence(x.store, x.root, frozen.entry.identity, w.B6A)
        assert isinstance(first, f.OccurrenceEstablished)
        x.refresh()
        run = x.activation(Role.REMEDIATOR, (PostFreezeCandidateItem(),), cycle=first.occurrence)
        before = frozenset(x.snapshot().records)
        result = f.record_post_freeze_candidates(x.store, run.identity)
        assert isinstance(result, f.CandidatesRecorded)
        added = frozenset(x.snapshot().records) - before
        assert len(added) == 1 and all(isinstance(r, PostFreezeCandidateRecord) for r in added)
        assert w.rows(x.store, FrozenFindingSet) == (frozen.frozen_set,)
        assert len(w.rows(x.store, RemediationObligation)) == 2
        assert f.post_freeze_candidates(x.snapshot(), x.root) == frozenset(
            r.candidate.identity for r in added if isinstance(r, PostFreezeCandidateRecord)
        )


def _obligations(x: w.LifecycleWorld) -> tuple[RemediationObligationId, ...]:
    return tuple(o.identity for o in w.rows(x.store, RemediationObligation))


def _waive(
    x: w.LifecycleWorld,
    obligation: RemediationObligationId,
    kind: Literal[OwnerDecisionKind.WAIVER, OwnerDecisionKind.DEFERRAL] = OwnerDecisionKind.WAIVER,
) -> None:
    decision = OwnerDecision(
        identity=OwnerDecisionId(value=token()),
        stage=w.rows(x.store, FrozenFindingSet)[0].stage,
        act=ObligationExtinguishingDecision(
            kind=kind, obligation=obligation, produced_authorization=w.ABSENT, corrects=w.ABSENT
        ),
    )
    ingest(x.store.path, (decision,))


@pytest.mark.traces("OB-2", "OB-3", "OB-4", "OB-5", "OB-6", "SC-10", "AP05-I16", "ST09-T4")
@pytest.mark.supports("OB-13", "OD-6")
def test_a_waived_obligation_leaves_the_admitted_set() -> None:
    for kind in (OwnerDecisionKind.WAIVER, OwnerDecisionKind.DEFERRAL):
        with w.world() as x:
            frozen, occurrence = w.freeze_enter(x)
            obligations = _obligations(x)
            before = f.admitted_set(x.snapshot(), occurrence.identity)
            assert isinstance(before, f.AdmittedSet) and before.obligations == frozenset(
                obligations
            )
            _waive(x, obligations[0], kind)
            after = f.admitted_set(x.snapshot(), occurrence.identity)
            assert after == f.AdmittedSet(occurrence.identity, frozenset(obligations[1:]))
            assert w.rows(x.store, FrozenFindingSet) == (frozen,)
            assert _obligations(x) == obligations


@pytest.mark.traces("RM-5", "RM-6", "RM-7", "RM-8", "RM-9", "AP04-I49", "ST09-N3")
def test_an_item_outside_the_admitted_set_is_x08() -> None:
    with w.world() as x:
        _, occurrence = w.freeze_enter(x)
        obligations = _obligations(x)
        _waive(x, obligations[0])
        run = x.activation(Role.REMEDIATOR, cycle=occurrence, dispositions=obligations)
        result = f.remediation_admissibility(x.snapshot(), run.identity)
        assert isinstance(result, f.Expansion) and result.cause == f.LifecycleCause.EXPANSION_X08
        assert {i.obligation for i in result.items} == {obligations[0]}
    _remediation_control()


def _remediation_control() -> None:
    with w.world() as x:
        _, occurrence = w.freeze_enter(x)
        obligations = _obligations(x)
        run = x.activation(Role.REMEDIATOR, cycle=occurrence, dispositions=obligations)
        assert f.remediation_admissibility(x.snapshot(), run.identity) == f.Admissible()


@pytest.mark.traces("RM-5", "RM-8", "AP04-I49", "ST09-N4")
def test_a_missing_disposition_item_is_nonconformant() -> None:
    with w.world() as x:
        _, occurrence = w.freeze_enter(x)
        obligations = _obligations(x)
        run = x.activation(Role.REMEDIATOR, cycle=occurrence, dispositions=obligations[:1])
        assert isinstance(f.remediation_admissibility(x.snapshot(), run.identity), f.Nonconformant)
    _remediation_control()


@pytest.mark.traces("PF-8", "PF-9", "FZ-11", "ST09-N5")
def test_a_finding_item_after_the_freeze_is_never_a_finding() -> None:
    for role in (Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER):
        with w.world() as x:
            frozen, occurrence = w.freeze_enter(x)
            if role == Role.BOUNDED_CLOSURE_VERIFIER:
                x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, occurrence)
            run = x.activation(
                role,
                (FindingItem(),),
                cycle=occurrence,
                dispositions=_obligations(x) if role == Role.REMEDIATOR else None,
            )
            result = (
                f.remediation_admissibility if role == Role.REMEDIATOR else f.closure_admissibility
            )(x.snapshot(), run.identity)
            assert isinstance(result, f.Nonconformant)
            assert w.rows(x.store, FrozenFindingSet) == (frozen,)
    _remediation_control()


@pytest.mark.traces("OP-8", "AP04-I49", "BC-6", "ST09-N3")
def test_c2_8_is_unequal_when_the_package_obligations_differ() -> None:
    for role in (Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER):
        for correct in (False, True):
            with w.world() as x:
                _, occurrence = w.freeze_enter(x)
                obligations = _obligations(x)
                run = x.activation(
                    role, cycle=occurrence, obligations=obligations if correct else obligations[:1]
                )
                assert f.admitted_obligations_fact(
                    x.snapshot(), run.envelope, run.input_package
                ) == {"ADMITTED_OBLIGATIONS_AGREE": "EQUAL" if correct else "UNEQUAL"}


@pytest.mark.traces("SC-2", "SC-3", "SC-4", "AP03-I24", "ST09-N2")
def test_an_assessment_of_a_non_member_is_refused() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, occurrence)
        stranger = FindingId(value=token())
        run = x.activation(Role.BOUNDED_CLOSURE_VERIFIER, cycle=occurrence)
        records = x.snapshot()
        bad = replace(
            records,
            records=tuple(
                r.model_copy(
                    update={
                        "items": (
                            MemberClosureResultItem(member=stranger, verdict=ClosedVerdict()),
                        )
                    }
                )
                if isinstance(r, OutcomeIngestionRecord) and r.activation == run.identity
                else r
                for r in records.records
            ),
        )
        assert f.closure_admissibility(bad, run.identity) == f.Nonconformant(
            (f.LifecycleCause.NON_MEMBER_ASSESSED,)
        )
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(f, "read_lifecycle_records", lambda store: bad)
            assert f.record_closure_assessments(x.store, run.identity) == f.NotRecorded(
                f.LifecycleCause.NON_MEMBER_ASSESSED
            )
    _closure_control()


def _closure_control() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        closer = w.close_cycle(x, frozen, occurrence)
        assert f.closure_admissibility(x.snapshot(), closer.identity) == f.Admissible()


@pytest.mark.traces("SC-2", "AP03-I24", "ST09-T3")
def test_closure_scope_outside_membership_is_false() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        closer = w.close_cycle(x, frozen, occurrence)
        records = x.snapshot()
        stranger = FindingId(value="stranger")
        assessments = tuple(
            r.model_copy(
                update={
                    "assessment": ClosureAssessment(
                        identity=ClosureAssessmentId(
                            assessed_finding=stranger, closure_activation=closer.identity
                        )
                    )
                }
            )
            if isinstance(r, ClosureAssessmentRecord) and isinstance(r.verdict, ClosedVerdict)
            else r
            for r in records.records
        )
        assert f.closure_scope_facts(
            replace(records, records=assessments), occurrence.identity
        ) == {"CLOSURE_SCOPE_WITHIN_MEMBERSHIP": "FALSE"}
        assert f.closure_scope_facts(records, occurrence.identity) == {
            "CLOSURE_SCOPE_WITHIN_MEMBERSHIP": "TRUE"
        }


@pytest.mark.traces("BC-6", "SC-4", "ST09-N3")
def test_a_closure_result_outside_the_admitted_bound_is_refused() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        obligations = _obligations(x)
        _waive(x, obligations[0])
        closer = w.close_cycle(x, frozen, occurrence, persist=False)
        assert f.closure_admissibility(x.snapshot(), closer.identity) == f.OutsideClosureBound(
            frozenset({obligations[0].member_finding})
        )
        assert f.record_closure_assessments(x.store, closer.identity) == f.NotRecorded(
            f.LifecycleCause.OUTSIDE_CLOSURE_BOUND
        )
    _closure_control()


@pytest.mark.traces("CL-10", "SC-6", "ST09-D4")
def test_assessments_are_recorded_once_per_closure_activation() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        closer = w.close_cycle(x, frozen, occurrence)
        before = frozenset(x.snapshot().records)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                x.store, "create_unit", lambda rows: pytest.fail("assessment replay wrote")
            )
            patch.setattr(f, "mint_value", lambda: pytest.fail("assessment replay minted"))
            replay = f.record_closure_assessments(x.store, closer.identity)
        assert isinstance(replay, f.AssessmentsReplayed) and len(replay.assessments) == 2
        assert frozenset(x.snapshot().records) == before
        assert {a.assessment.identity.assessed_finding for a in replay.assessments} == set(
            frozen.members
        )


@pytest.mark.traces("PF-3", "ST09-D5")
def test_candidates_are_recorded_once_per_activation() -> None:
    with w.world() as x:
        _, occurrence = w.freeze_enter(x)
        run = x.activation(
            Role.REMEDIATOR,
            (PostFreezeCandidateItem(), PostFreezeCandidateItem()),
            cycle=occurrence,
        )
        first = f.record_post_freeze_candidates(x.store, run.identity)
        assert isinstance(first, f.CandidatesRecorded) and len(first.candidates) == 2
        before = frozenset(x.snapshot().records)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                x.store, "create_unit", lambda rows: pytest.fail("candidate replay wrote")
            )
            patch.setattr(f, "mint_value", lambda: pytest.fail("candidate replay minted"))
            assert f.record_post_freeze_candidates(x.store, run.identity) == f.CandidatesReplayed(
                frozenset(first.candidates)
            )
        assert frozenset(x.snapshot().records) == before


@pytest.mark.traces("PF-3", "DO-16", "ST09-N4")
def test_no_candidate_is_recorded_from_an_unadopted_outcome() -> None:
    with w.world() as x:
        _, occurrence = w.freeze_enter(x)
        run = x.activation(
            Role.REMEDIATOR, (PostFreezeCandidateItem(),), cycle=occurrence, adopted=False
        )
        before = frozenset(x.snapshot().records)
        assert f.record_post_freeze_candidates(x.store, run.identity) == f.NotRecorded(
            f.LifecycleCause.NOT_COMPLETED_ADOPTED
        )
        assert frozenset(x.snapshot().records) == before
    test_raising_a_candidate_writes_only_candidates()


@pytest.mark.traces("PF-4", "PF-5", "PF-6", "FZ-10", "AP05-I07", "ST09-N1")
def test_a_candidate_identity_is_never_a_member() -> None:
    frozen = original_world().handles["frozen"]
    assert isinstance(frozen, FrozenFindingSet)
    data = dict(frozen)
    data["members"] = (PostFreezeCandidateId(value="candidate"),)
    schema = f.FrozenFindingSet  # type: ignore[attr-defined]
    with pytest.raises(ValidationError):
        schema(**data)
    assert dict(schema(**dict(frozen))) == dict(frozen)


@pytest.mark.traces(
    "SC-6",
    "CL-2",
    "CL-3",
    "CL-4",
    "CL-6",
    "CL-7",
    "CL-8",
    "CL-9",
    "AP05-I17",
    "AP05-I18",
    "ST09-T3",
)
def test_closure_keeps_verdict_and_legitimate_unassessed_members_distinct() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x, 3)
        closer = w.close_cycle(x, frozen, occurrence, (True, False, None))
        assessments = w.rows(x.store, ClosureAssessmentRecord)
        assert len(assessments) == 2
        assert {a.assessment.identity.assessed_finding for a in assessments} == set(
            frozen.members[:2]
        )
        assert {type(a.verdict) for a in assessments} == {ClosedVerdict, NotClosedVerdict}
        assert f.closure_admissibility(x.snapshot(), closer.identity) == f.Admissible()
        assert isinstance(
            f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE), f.GateDue
        )


@pytest.mark.traces("CL-10", "SC-3", "ST09-D4")
def test_incompatible_closer_effect_is_rejected_before_assessment_creation() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        foreign = x.activation(
            Role.BOUNDED_CLOSURE_VERIFIER, cycle=occurrence, adopted=False, outcome="unadopted"
        )
        x.store.create(
            ClosureAssessmentRecord(
                assessment=ClosureAssessment(
                    identity=ClosureAssessmentId(
                        assessed_finding=frozen.members[0], closure_activation=foreign.identity
                    )
                ),
                verdict=ClosedVerdict(),
                cycle_occurrence=Present(value=occurrence.identity),
            )
        )
        closer = w.close_cycle(x, frozen, occurrence, persist=False)
        before = frozenset(x.snapshot().records)
        assert f.record_closure_assessments(x.store, closer.identity) == f.NotRecorded(
            f.LifecycleCause.INCONSISTENT_RECORDS
        )
        assert frozenset(x.snapshot().records) == before


@pytest.mark.traces(
    "AP04-I50",
    "AP05-I19",
    "OB-10",
    "OP-1",
    "OP-3",
    "OP-4",
    "FZ-12",
    "FI-7",
    "OD-5",
    "OD-9",
    "OD-11",
    "AP05-I38",
)
@pytest.mark.supports("OD-1", "OD-2", "OD-3", "OD-4", "AP05-I29", "AP05-I30")
def test_only_owner_extinguishment_changes_force_and_no_act_changes_membership() -> None:
    from gpauto import derivations as dv
    from gpauto.coordination_records import DisputeItem, FindingRecord, WorkerRefusalOrExpansionItem
    from gpauto.governance import DisputeResolutionDecision, ObligationChangeDecision

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        obligations = _obligations(x)
        baseline = frozenset(w.rows(x.store, FindingRecord))
        run = x.activation(
            Role.REMEDIATOR,
            (DisputeItem(), WorkerRefusalOrExpansionItem()),
            cycle=occurrence,
            dispositions=obligations,
        )
        admission = f.remediation_admissibility(x.snapshot(), run.identity)
        assert admission == f.Admissible((DisputeItem(),), (WorkerRefusalOrExpansionItem(),))
        before = f.admitted_set(x.snapshot(), occurrence.identity)
        x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, occurrence)
        closer = x.activation(
            Role.BOUNDED_CLOSURE_VERIFIER,
            tuple(
                MemberClosureResultItem(member=m, verdict=ClosedVerdict()) for m in frozen.members
            ),
            cycle=occurrence,
        )
        assert isinstance(
            f.record_closure_assessments(x.store, closer.identity), f.AssessmentsRecorded
        )
        assert f.admitted_set(x.snapshot(), occurrence.identity) == before
        for act in (
            DisputeResolutionDecision(
                kind=OwnerDecisionKind.FINDING_DISPUTE,
                member=frozen.members[0],
                produced_authorization=w.ABSENT,
                corrects=w.ABSENT,
            ),
            ObligationChangeDecision(
                kind=OwnerDecisionKind.OBLIGATION_CHANGE,
                obligation=obligations[0],
                replacement_requirement="OWNER replacement, never interpreted",
                produced_authorization=w.ABSENT,
            ),
        ):
            ingest(
                x.store.path,
                (
                    OwnerDecision(
                        identity=OwnerDecisionId(value=token()), stage=frozen.stage, act=act
                    ),
                ),
            )
            force = dv.derive_obligation_force(x.snapshot(), obligations[0])
            assert isinstance(force, dv.ObligationForce) and force.in_force
            assert w.rows(x.store, FrozenFindingSet) == (frozen,)
            assert frozenset(w.rows(x.store, FindingRecord)) == baseline
        _waive(x, obligations[0])
        assert w.rows(x.store, FrozenFindingSet) == (frozen,)
        assert frozenset(w.rows(x.store, FindingRecord)) == baseline


@pytest.mark.traces("OB-8", "OB-9", "OD-12", "AP05-I16", "AP05-I38")
def test_force_ends_at_terminal_and_deferral_does_not_transfer_to_another_epoch() -> None:
    from gpauto import derivations as dv

    with w.world("first") as x:
        frozen, occurrence = w.freeze_enter(x)
        obligations = _obligations(x)
        deferred = next(o for o in obligations if o.member_finding == frozen.members[0])
        _waive(x, deferred, OwnerDecisionKind.DEFERRAL)
        w.close_cycle(x, frozen, occurrence, (None, False))
        x.advance(M2Position.S8_GATE_REACHED, M2Edge.B8, occurrence)
        x.advance(M2Position.S10_EPOCH_SETTLED, M2Edge.B10, occurrence)
        for o in obligations:
            force = dv.derive_obligation_force(x.snapshot(), o)
            assert isinstance(force, dv.ObligationForce) and not force.in_force
        assert w.rows(x.store, FrozenFindingSet) == (frozen,)
        assert _obligations(x) == obligations
        with w.world("second") as y:
            other, cycle = w.freeze_enter(y)
            assert x.root != y.root and other.identity != frozen.identity
            admitted = f.admitted_set(y.snapshot(), cycle.identity)
            assert isinstance(admitted, f.AdmittedSet)
            assert len(admitted.obligations) == 2 and admitted.obligations.isdisjoint(obligations)


@pytest.mark.traces("RM-11", "RM-12", "DO-16", "CL-5", "ST09-N2")
@pytest.mark.supports("CL-1", "AP05-I20")
def test_unadopted_outcomes_supply_no_closure_or_candidate_effect() -> None:
    for role in (Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER):
        with w.world() as x:
            frozen, occurrence = w.freeze_enter(x)
            run = x.activation(role, (PostFreezeCandidateItem(),), cycle=occurrence, adopted=False)
            before = frozenset(x.snapshot().records)
            result = f.record_closure_assessments(x.store, run.identity)
            assert isinstance(result, f.NotRecorded)
            assert result.cause == (
                f.LifecycleCause.WRONG_ROLE
                if role == Role.REMEDIATOR
                else f.LifecycleCause.NOT_COMPLETED_ADOPTED
            )
            assert f.record_post_freeze_candidates(x.store, run.identity) == f.NotRecorded(
                f.LifecycleCause.NOT_COMPLETED_ADOPTED
            )
            assert frozenset(x.snapshot().records) == before
            assert len(_obligations(x)) == len(frozen.members)


@pytest.mark.traces("RM-5", "RM-6", "RM-9", "AP05-I18")
def test_duplicate_dispositions_and_foreign_change_evidence_are_nonconformant() -> None:
    from gpauto.coordination_records import ObligationDispositionItem

    with w.world() as x:
        _, occurrence = w.freeze_enter(x)
        run = x.activation(Role.REMEDIATOR, cycle=occurrence, dispositions=_obligations(x))
        records = x.snapshot()
        ingestion = next(
            r
            for r in records.records
            if isinstance(r, OutcomeIngestionRecord) and r.activation == run.identity
        )
        other = next(
            r
            for r in records.records
            if isinstance(r, OutcomeIngestionRecord) and r.activation != run.identity
        )
        first = ingestion.items[0]
        assert isinstance(first, ObligationDispositionItem)
        for change in (
            (first, first),
            (
                first.model_copy(
                    update={
                        "change_evidence": first.change_evidence.model_copy(
                            update={"production": other.objective_channel[0]}
                        )
                    }
                ),
                *ingestion.items[1:],
            ),
        ):
            bad = replace(
                records,
                records=tuple(
                    r.model_copy(update={"items": change}) if r == ingestion else r
                    for r in records.records
                ),
            )
            assert isinstance(f.remediation_admissibility(bad, run.identity), f.Nonconformant)
        assert f.remediation_admissibility(records, run.identity) == f.Admissible()


@pytest.mark.traces("OD-10", "PF-4", "AP05-I07")
def test_an_owner_decision_identity_cannot_be_a_member() -> None:
    frozen = original_world().handles["frozen"]
    assert isinstance(frozen, FrozenFindingSet)
    data = dict(frozen)
    data["members"] = (OwnerDecisionId(value="decision"),)
    with pytest.raises(ValidationError):
        FrozenFindingSet(**data)
