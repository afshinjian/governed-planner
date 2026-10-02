"""Design basis: ST-09 plan §6.3, §6.6, §9; AP-04 CE-*; AP-08 CB-*."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

import st09_world as w
from gpauto import finding_lifecycle as f
from gpauto import state_machine_model as model
from gpauto.coordination_records import CycleOccurrence, MemberClosureResultItem
from gpauto.coordination_vocabulary import ClosedVerdict, M2Edge, M2Position, NotClosedVerdict
from gpauto.minting import mint_value
from gpauto.vocabulary import Role

GPAUTO_STAGE = "GP-AUTO-ST-09"


@pytest.mark.traces("ST09-R2", "CY-10", "CY-11", "CY-12", "BC-10")
def test_a_replayed_b6a_after_position_advance_references_the_existing_occurrence() -> None:
    assert hasattr(f, "enter_first_occurrence"), "B6a lifecycle act is absent"
    with w.world() as x:
        frozen = f.freeze(x.store, x.discovery().identity, w.B5)
        assert isinstance(frozen, f.Frozen)
        predecessor = frozen.entry.identity
        first = f.enter_first_occurrence(x.store, x.root, predecessor, w.B6A)
        assert isinstance(first, f.OccurrenceEstablished)
        assert x.refresh().state == M2Position.S6_REMEDIATION_ACTIVE
        replay = f.enter_first_occurrence(x.store, x.root, predecessor, w.B6A)
        assert replay == f.OccurrenceReplayed(first.occurrence, first.entry)
        assert len(w.rows(x.store, CycleOccurrence)) == 1


@pytest.mark.traces("ST09-T5", "ST09-D6", "CB-1", "CB-2", "CY-25", "AP04-I47")
def test_a_replayed_b15_after_position_advance_references_the_existing_occurrence() -> None:
    assert hasattr(f, "route_after_closure"), "B15 lifecycle act is absent"
    with w.world() as x:
        frozen = f.freeze(x.store, x.discovery().identity, w.B5)
        assert isinstance(frozen, f.Frozen)
        first = f.enter_first_occurrence(x.store, x.root, frozen.entry.identity, w.B6A)
        assert isinstance(first, f.OccurrenceEstablished)
        x.refresh()
        x.activation(Role.REMEDIATOR, cycle=first.occurrence)
        x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, first.occurrence)
        predecessor = x.head.identity
        closer = x.activation(
            Role.BOUNDED_CLOSURE_VERIFIER,
            (
                MemberClosureResultItem(
                    member=frozen.frozen_set.members[0], verdict=ClosedVerdict()
                ),
                MemberClosureResultItem(
                    member=frozen.frozen_set.members[1],
                    verdict=NotClosedVerdict(indeterminacy_reason=w.ABSENT),
                ),
            ),
            cycle=first.occurrence,
        )
        assert isinstance(
            f.record_closure_assessments(x.store, closer.identity), f.AssessmentsRecorded
        )
        facts = f.cycle_facts(x.snapshot(), first.occurrence.identity, w.CYCLE)
        assert all(
            facts.get(getattr(model, name).name) == "TRUE"
            for name in (
                "CE_0A",
                "CE_0B",
                "CE_0C",
                "CE_0D",
                "CE_1",
                "CE_2",
                "CE_3",
                "CE_4",
                "CE_5",
                "CE_6",
            )
        ), facts
        routed = f.route_after_closure(x.store, x.root, predecessor, w.CYCLE)
        assert isinstance(routed, f.OccurrenceEstablished), routed
        assert x.refresh().state == M2Position.S6_REMEDIATION_ACTIVE
        assert f.b15_budget(x.snapshot(), x.root) == f.BudgetExhausted(1)
        assert f.route_after_closure(x.store, x.root, predecessor, w.CYCLE) == f.OccurrenceReplayed(
            routed.occurrence, routed.entry
        )


def _eligible_control() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        w.close_cycle(x, frozen, occurrence)
        assert isinstance(
            f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE),
            f.OccurrenceEstablished,
        )


def _fact_case(
    name: str,
    verdicts: tuple[bool | None, ...],
    expected: str | None,
    upstream: dict[str, str] | None = None,
    change: str = "",
) -> None:
    from dataclasses import replace

    from gpauto import state_machine_model as model
    from gpauto.authorization import ConsumedDisposition, SuspendedDisposition
    from gpauto.coordination_identity import DispositionRecordId
    from gpauto.coordination_records import (
        DispositionEstablishingRecord,
        FindingRecord,
        M4PositionEntry,
    )
    from gpauto.coordination_vocabulary import M4Edge
    from gpauto.identity import RefusalId, StageOutcomeId, WorkerActivationId
    from gpauto.vocabulary import AuthorizationDisposition
    from st03_world import m4

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x, len(verdicts))
        w.close_cycle(
            x,
            frozen,
            occurrence,
            verdicts,
            persist=change != "unadopted",
            adopted=change != "unadopted",
        )
        records = x.snapshot()
        if change == "m4-absent":
            records = replace(records, unreadable=frozenset({M4PositionEntry}))
        if change == "event-absent":
            records = replace(records, unreadable=frozenset({DispositionEstablishingRecord}))
        if change in {"m4-false", "event"}:
            disposition = (
                ConsumedDisposition(
                    established_by_outcome=StageOutcomeId(
                        parent_stage=frozen.stage, local_discriminator="consumed"
                    )
                )
                if change == "m4-false"
                else SuspendedDisposition(established_by_event=RefusalId(value="unresolved-event"))
            )
            row = DispositionEstablishingRecord(
                identity=DispositionRecordId(authorization=x.root, discriminator="disposition"),
                disposition=disposition,
            )
            entry = m4(
                x.root,
                AuthorizationDisposition.CONSUMED
                if change == "m4-false"
                else AuthorizationDisposition.SUSPENDED,
                M4Edge.G2 if change == "m4-false" else M4Edge.G1,
                None,
            )
            records = replace(records, records=records.records + (row, entry))
        if change == "changed":
            records = replace(
                records,
                records=tuple(
                    r.model_copy(
                        update={
                            "finding": r.finding.model_copy(
                                update={
                                    "originating_activation": WorkerActivationId(
                                        value="wrong-origin"
                                    )
                                }
                            )
                        }
                    )
                    if isinstance(r, FindingRecord)
                    else r
                    for r in records.records
                ),
            )
        facts = w.CYCLE if upstream is None else upstream
        supplied = f.cycle_facts(records, occurrence.identity, facts)
        assert supplied.get(getattr(model, name).name) == expected, supplied
        before = frozenset(x.snapshot().records)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(f, "read_lifecycle_records", lambda store: records)
            routed = f.route_after_closure(x.store, x.root, x.head.identity, facts)
        if name.startswith("CE_0") or expected is None:
            assert isinstance(routed, f.NotRouted), routed
        else:
            assert isinstance(routed, f.GateDue), routed
        assert frozenset(x.snapshot().records) == before
    _eligible_control()


@pytest.mark.traces("CY-2", "CB-5", "ST09-N7")
@pytest.mark.supports("CE-0a", "CE-0b", "CE-0c", "CE-0d", "CE-T1")
def test_a_tier_0_failure_never_writes_b15_or_reports_b8() -> None:
    _fact_case("CE_0C", (True, False), "FALSE", w.CYCLE | {"UNACCOUNTED_MUTATION": "TRUE"})


@pytest.mark.traces("CB-6", "CL-5", "AP05-I21", "RM-10")
@pytest.mark.supports("CE-0a")
def test_ce_0a_requires_completed_adopted_closure() -> None:
    _fact_case("CE_0A", (True, False), "FALSE", change="unadopted")


@pytest.mark.traces("CY-2", "BC-2", "BC-12")
@pytest.mark.supports("CE-0b")
def test_ce_0b_is_false_when_a_component_is_false() -> None:
    _fact_case("CE_0B", (True, False), "FALSE", change="m4-false")
    for name in ("BOUNDARY_FIXED", "BINDINGS_MATCH"):
        _fact_case("CE_0B", (True, False), "FALSE", w.CYCLE | {name: "FALSE"})


@pytest.mark.traces("CY-2", "BC-12")
@pytest.mark.supports("CE-0b")
def test_an_absent_component_leaves_ce_0b_indeterminate() -> None:
    _fact_case("CE_0B", (True, False), None, change="m4-absent")
    for name in ("BOUNDARY_FIXED", "BINDINGS_MATCH"):
        _fact_case("CE_0B", (True, False), None, {k: v for k, v in w.CYCLE.items() if k != name})


@pytest.mark.traces("RM-10", "CL-5", "AP05-I21")
@pytest.mark.supports("CE-0c")
def test_ce_0c_is_false_when_unaccounted_mutation_is_true() -> None:
    _fact_case("CE_0C", (True, False), "FALSE", w.CYCLE | {"UNACCOUNTED_MUTATION": "TRUE"})


@pytest.mark.traces("CY-2", "CB-5")
@pytest.mark.supports("CE-0c")
def test_ce_0c_is_false_when_an_unresolved_event_exists() -> None:
    _fact_case("CE_0C", (True, False), "FALSE", change="event")


@pytest.mark.traces("CY-2", "BC-12")
@pytest.mark.supports("CE-0c")
def test_an_indeterminate_event_state_leaves_ce_0c_indeterminate() -> None:
    _fact_case("CE_0C", (True, False), None, change="event-absent")


@pytest.mark.traces("CY-2", "BC-12")
@pytest.mark.supports("CE-0c")
def test_an_absent_unaccounted_mutation_fact_leaves_ce_0c_indeterminate() -> None:
    _fact_case(
        "CE_0C",
        (True, False),
        None,
        {k: v for k, v in w.CYCLE.items() if k != "UNACCOUNTED_MUTATION"},
    )


@pytest.mark.traces("AP04-I45", "CY-6")
@pytest.mark.supports("CE-0d")
def test_ce_0d_rejects_a_changed_frozen_set() -> None:
    _fact_case("CE_0D", (True, False), "FALSE", change="changed")


@pytest.mark.traces("CY-4", "CL-11")
@pytest.mark.supports("CE-1")
def test_ce_1_is_false_for_an_empty_scope() -> None:
    _fact_case("CE_1", (None, None), "FALSE")


@pytest.mark.traces("CY-4", "CL-11")
@pytest.mark.supports("CE-2")
def test_ce_2_requires_a_not_closed_member() -> None:
    _fact_case("CE_2", (True, True), "FALSE")


@pytest.mark.traces("CY-4", "CL-8")
@pytest.mark.supports("CE-3")
def test_ce_3_requires_a_closed_member() -> None:
    _fact_case("CE_3", (False, False), "FALSE")


@pytest.mark.traces("SC-9", "AP05-I24", "ST09-T4")
def test_no_cycle_when_no_member_was_attested_closed() -> None:
    _fact_case("CE_3", (False, False), "FALSE")


@pytest.mark.traces("CY-4", "CL-11")
@pytest.mark.supports("CE-4", "SC-5")
def test_ce_4_requires_the_complete_admitted_identity_set() -> None:
    _fact_case("CE_4", (True, None), "FALSE")


@pytest.mark.traces("CY-4", "CL-11")
@pytest.mark.supports("CE-5")
def test_ce_5_requires_a_nonempty_next_bound() -> None:
    _fact_case("CE_5", (True, True), "FALSE")


@pytest.mark.traces("CB-4", "CY-26", "AP05-I47", "ST09-N6")
def test_an_unavailable_policy_makes_ce_6_indeterminate() -> None:
    from gpauto import state_machine_model as model

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        w.close_cycle(x, frozen, occurrence)
        assert isinstance(f.b15_budget(x.snapshot(), x.root, None), f.BudgetIndeterminate)
        assert model.CE_6.name not in f.cycle_facts(
            x.snapshot(), occurrence.identity, w.CYCLE, None
        )
        assert isinstance(
            f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE, None), f.NotRouted
        )
    _eligible_control()


@pytest.mark.traces("CY-3", "BC-12", "ST09-N6")
@pytest.mark.supports("CE-T3")
def test_an_indeterminate_tier_1_admits_neither_edge() -> None:
    test_an_unavailable_policy_makes_ce_6_indeterminate()


@pytest.mark.traces("CB-3", "CY-25", "CY-26", "CY-27", "ST09-T6", "AP04-I47")
def test_a_committed_b15_exhausts_the_budget_to_b8() -> None:
    from gpauto import state_machine_model as model

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x, 3)
        w.close_cycle(x, frozen, occurrence, (True, False, False))
        second = f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE)
        assert isinstance(second, f.OccurrenceEstablished)
        x.refresh()
        w.close_cycle(x, frozen, second.occurrence, (None, True, False))
        assert f.b15_budget(x.snapshot(), x.root) == f.BudgetExhausted(1)
        assert (
            f.cycle_facts(x.snapshot(), second.occurrence.identity, w.CYCLE)[model.CE_6.name]
            == "FALSE"
        )
        assert isinstance(
            f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE), f.GateDue
        )


@pytest.mark.traces("CB-3", "ST09-T6")
@pytest.mark.supports("CE-6")
def test_ce_6_is_false_when_the_budget_is_exhausted() -> None:
    test_a_committed_b15_exhausts_the_budget_to_b8()


@pytest.mark.traces("CY-3", "ST09-M6")
def test_contradictory_evaluator_results_are_refused_before_writing() -> None:
    from unittest.mock import patch as spy

    from gpauto import state_machine as sm

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        w.close_cycle(x, frozen, occurrence)
        real = sm.evaluate

        def contradictory(*args: object, **kwargs: object) -> sm.Evaluation:
            if args[0] == M2Edge.B8:
                return sm.Admitted(
                    M2Edge.B8, M2Position.S7_CLOSURE_ACTIVE, M2Position.S8_GATE_REACHED
                )
            return real(*args, **kwargs)  # type: ignore[arg-type]

        before = frozenset(x.snapshot().records)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sm, "evaluate", contradictory)
            with (
                spy.object(f, "mint_value", wraps=mint_value) as mint_calls,
                spy.object(x.store, "create_unit", wraps=x.store.create_unit) as writes,
            ):
                result = f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE)
                assert result == f.NotRouted(f.LifecycleCause.INCONSISTENT_RECORDS)
                assert mint_calls.call_count == writes.call_count == 0
        assert result == f.NotRouted(f.LifecycleCause.INCONSISTENT_RECORDS)
        assert frozenset(x.snapshot().records) == before
    _eligible_control()


@pytest.mark.traces("CL-10", "ST09-T3")
def test_a_persisted_partial_assessment_effect_cannot_route() -> None:
    from unittest.mock import patch as spy

    from gpauto import state_machine as sm
    from gpauto.absence import Present
    from gpauto.coordination_records import ClosureAssessmentRecord
    from gpauto.identity import ClosureAssessmentId
    from gpauto.review import ClosureAssessment
    from gpauto.store import open_store

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        closer = w.close_cycle(x, frozen, occurrence, persist=False)
        x.store.create(
            ClosureAssessmentRecord(
                assessment=ClosureAssessment(
                    identity=ClosureAssessmentId(
                        assessed_finding=frozen.members[0], closure_activation=closer.identity
                    )
                ),
                verdict=ClosedVerdict(),
                cycle_occurrence=Present(value=occurrence.identity),
            )
        )
        path = x.store.path
        x.store.close()
        with open_store(path) as reopened:
            before = frozenset(f.read_lifecycle_records(reopened).records)
            with (
                spy.object(sm, "evaluate", wraps=sm.evaluate) as evaluations,
                spy.object(f, "mint_value", wraps=mint_value) as mints,
                spy.object(reopened, "create_unit", wraps=reopened.create_unit) as writes,
            ):
                result = f.route_after_closure(reopened, x.root, x.head.identity, w.CYCLE)
                assert result == f.NotRouted(f.LifecycleCause.INCONSISTENT_RECORDS)
                assert evaluations.call_count == mints.call_count == writes.call_count == 0
            assert frozenset(f.read_lifecycle_records(reopened).records) == before
    _fact_case("CE_4", (True, None), "FALSE")


@pytest.mark.traces("OP-9", "OP-10", "OP-11", "CY-18", "CY-19", "CY-20", "CY-21", "AP05-I48")
def test_the_admitted_set_of_an_occurrence_subtracts_only_its_predecessors() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        before = f.admitted_set(x.snapshot(), occurrence.identity)
        w.close_cycle(x, frozen, occurrence)
        assert f.admitted_set(x.snapshot(), occurrence.identity) == before
        second = f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE)
        assert isinstance(second, f.OccurrenceEstablished)
        after = f.admitted_set(x.snapshot(), second.occurrence.identity)
        assert isinstance(after, f.AdmittedSet)
        assert {o.member_finding for o in after.obligations} == {frozen.members[1]}


@pytest.mark.traces("CB-4", "ST09-M7")
def test_an_unreadable_or_broken_chain_makes_ce_6_indeterminate() -> None:
    from dataclasses import replace

    from gpauto.coordination_identity import M2PositionEntryId

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        records = x.snapshot()
        for broken in (
            replace(records, unreadable=frozenset({CycleOccurrence})),
            replace(
                records,
                records=tuple(
                    c.model_copy(
                        update={
                            "predecessor_entry": M2PositionEntryId(
                                epoch_root=x.root, discriminator="missing"
                            )
                        }
                    )
                    if isinstance(c, CycleOccurrence)
                    else c
                    for c in records.records
                ),
            ),
        ):
            assert isinstance(f.b15_budget(broken, x.root), f.BudgetIndeterminate)


@pytest.mark.traces("CB-1", "CB-4")
def test_a_b15_occurrence_without_its_entry_is_indeterminate() -> None:
    from dataclasses import replace

    from gpauto.coordination_records import M2PositionEntry

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        w.close_cycle(x, frozen, occurrence)
        result = f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE)
        assert isinstance(result, f.OccurrenceEstablished)
        records = x.snapshot()
        broken = replace(
            records,
            records=tuple(
                r
                for r in records.records
                if not (isinstance(r, M2PositionEntry) and r.edge == M2Edge.B15)
            ),
        )
        assert isinstance(f.b15_budget(broken, x.root), f.BudgetIndeterminate)


@pytest.mark.traces("CY-9", "CB-7")
def test_a_new_cycle_never_originates_from_a_halt() -> None:
    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        w.close_cycle(x, frozen, occurrence)
        predecessor = x.head.identity
        x.advance(M2Position.S9_EPOCH_HALTED, M2Edge.B9, occurrence)
        assert f.route_after_closure(x.store, x.root, predecessor, w.CYCLE) == f.NotRouted(
            f.LifecycleCause.EPOCH_NOT_AT_POSITION
        )


@pytest.mark.traces("SC-9", "SC-10", "OP-11", "ST09-T4")
def test_an_equal_sized_but_different_scope_is_not_the_applicable_set() -> None:
    from gpauto import state_machine_model as model
    from gpauto.review import RemediationObligation
    from test_ga45_st09_obligations_closure_and_candidates import _waive

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x, 3)
        w.close_cycle(x, frozen, occurrence, (True, False, None))
        obligation = next(
            o.identity
            for o in w.rows(x.store, RemediationObligation)
            if o.identity.member_finding == frozen.members[0]
        )
        _waive(x, obligation)
        facts = f.cycle_facts(x.snapshot(), occurrence.identity, w.CYCLE)
        assert facts[model.CE_4.name] == "FALSE"
    _eligible_control()


@pytest.mark.traces("CY-3", "ST09-T5")
@pytest.mark.supports("CE-T2", "CE-T3")
def test_b8_and_b15_are_never_both_admitted() -> None:
    from gpauto import state_machine as sm

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        w.close_cycle(x, frozen, occurrence)
        facts = f.cycle_facts(x.snapshot(), occurrence.identity, w.CYCLE)
        assert isinstance(sm.evaluate(M2Edge.B15, x.head.state, facts), sm.Admitted)
        assert isinstance(sm.evaluate(M2Edge.B8, x.head.state, facts), sm.Refused)


@pytest.mark.traces("CY-11", "ST09-R2")
def test_a_replayed_b15_references_the_existing_occurrence() -> None:
    test_a_replayed_b15_after_position_advance_references_the_existing_occurrence()


@pytest.mark.traces("CL-10", "CY-18", "ST09-T3")
def test_every_closure_consulted_by_dv3_must_have_a_reconciled_occurrence() -> None:
    from gpauto.coordination_records import ClosureAssessmentRecord
    from gpauto.identity import ClosureAssessmentId
    from gpauto.review import ClosureAssessment

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        orphan = x.activation(Role.BOUNDED_CLOSURE_VERIFIER)
        w.close_cycle(x, frozen, occurrence)
        x.store.create(
            ClosureAssessmentRecord(
                assessment=ClosureAssessment(
                    identity=ClosureAssessmentId(
                        assessed_finding=frozen.members[1], closure_activation=orphan.identity
                    )
                ),
                verdict=ClosedVerdict(),
                cycle_occurrence=w.ABSENT,
            )
        )
        before = frozenset(x.snapshot().records)
        assert f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE) == f.NotRouted(
            f.LifecycleCause.INCONSISTENT_RECORDS
        )
        assert frozenset(x.snapshot().records) == before


@pytest.mark.traces(
    "NF-3",
    "PF-10",
    "CY-6",
    "CY-7",
    "CY-13",
    "CY-15",
    "CY-17",
    "CB-9",
    "AP04-I45",
    "AP05-I22",
    "AP05-I23",
    "AP05-I27",
    "AP05-I43",
    "AP05-I44",
    "AP05-I45",
    "AP05-I46",
    "OP-7",
    "OP-P3",
    "BC-1",
    "BC-7",
    "BC-11",
    "BC-15",
)
@pytest.mark.supports("BC-4", "CB-8", "CL-12", "PF-7", "AP05-I31", "AP05-I32", "AP05-I33")
def test_candidates_leave_cycle_facts_and_membership_unchanged_across_b15() -> None:
    from gpauto import derivations as dv
    from gpauto.coordination_records import (
        ClosureAssessmentRecord,
        FindingRecord,
        PostFreezeCandidateItem,
    )
    from gpauto.review import FrozenFindingSet, RemediationObligation

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        run = x.activation(Role.REMEDIATOR, (PostFreezeCandidateItem(),), cycle=occurrence)
        x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, occurrence)
        closer = x.activation(
            Role.BOUNDED_CLOSURE_VERIFIER,
            (
                MemberClosureResultItem(member=frozen.members[0], verdict=ClosedVerdict()),
                MemberClosureResultItem(
                    member=frozen.members[1],
                    verdict=NotClosedVerdict(indeterminacy_reason=w.ABSENT),
                ),
            ),
            cycle=occurrence,
        )
        assert isinstance(
            f.record_closure_assessments(x.store, closer.identity), f.AssessmentsRecorded
        )
        facts = f.cycle_facts(x.snapshot(), occurrence.identity, w.CYCLE)
        before = frozenset(
            r
            for r in x.snapshot().records
            if isinstance(
                r,
                FindingRecord | FrozenFindingSet | RemediationObligation | ClosureAssessmentRecord,
            )
        )
        candidates = f.record_post_freeze_candidates(x.store, run.identity)
        assert isinstance(candidates, f.CandidatesRecorded)
        assert f.cycle_facts(x.snapshot(), occurrence.identity, w.CYCLE) == facts
        second = f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE)
        assert isinstance(second, f.OccurrenceEstablished)
        after = f.admitted_set(x.snapshot(), second.occurrence.identity)
        assert isinstance(after, f.AdmittedSet)
        assert {o.member_finding for o in after.obligations} == {frozen.members[1]}
        derived = dv.derive_cycle_bound(x.snapshot(), x.root)
        assert isinstance(derived, dv.CycleBound) and derived.members == after.obligations
        assert (
            frozenset(
                r
                for r in x.snapshot().records
                if isinstance(
                    r,
                    FindingRecord
                    | FrozenFindingSet
                    | RemediationObligation
                    | ClosureAssessmentRecord,
                )
            )
            == before
        )
        assert f.post_freeze_candidates(x.snapshot(), x.root) == frozenset(
            c.candidate.identity for c in candidates.candidates
        )
        assert second.occurrence.envelope == second.occurrence.activation == f.ABSENT


@pytest.mark.traces("CL-2", "CL-3", "RM-3", "SC-7", "AP05-I17")
@pytest.mark.supports("B7", "AP03-I15", "ST06C-I02", "ST06C-I04", "AP05-I20")
def test_b7_combines_lifecycle_scope_with_each_required_upstream_bound() -> None:
    from gpauto import state_machine as sm

    with w.world() as x:
        _, occurrence = w.freeze_enter(x)
        x.activation(Role.REMEDIATOR, cycle=occurrence)
        rule = next(r for r in model.EDGES if r.edge == M2Edge.B7)
        assert isinstance(rule.guard, model.Conjunctive)
        facts = {c.fact.name: c.admitted[0] for c in rule.guard.alternatives[0]}
        facts.update(f.membership_facts(x.snapshot(), x.root))
        facts.update(f.closure_scope_facts(x.snapshot(), occurrence.identity))
        assert isinstance(sm.evaluate(M2Edge.B7, x.head.state, facts), sm.Admitted)
        for name in (
            "READ_ONLY_WITHOUT_WRITE_BOUNDARY",
            "E14_REFERENCES_FROZEN_SET",
            "E20_DESIGNATES_INPUTS",
        ):
            for missing in (False, True):
                bad = dict(facts)
                if missing:
                    bad.pop(name)
                else:
                    bad[name] = "FALSE"
                assert isinstance(sm.evaluate(M2Edge.B7, x.head.state, bad), sm.Refused)


@pytest.mark.traces("RM-2", "RM-4", "CL-6", "BC-1", "ST09-N7")
def test_two_completed_workers_of_one_role_in_an_occurrence_are_inconsistent() -> None:
    from dataclasses import replace

    from gpauto.absence import Present
    from gpauto.coordination_records import (
        AuthorityEnvelopeRecord,
        ConformanceDetermination,
        M3PositionEntry,
        WorkerActivationRecord,
    )
    from gpauto.identity import AuthorityEnvelopeId, WorkerActivationId

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        w.close_cycle(x, frozen, occurrence)
        records = x.snapshot()
        for role in (Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER):
            run = next(
                r
                for r in records.records
                if isinstance(r, WorkerActivationRecord) and r.role == role
            )
            new_run, new_env = (
                WorkerActivationId(value="duplicate-run"),
                AuthorityEnvelopeId(value="duplicate-envelope"),
            )
            added: list[BaseModel] = []
            for r in records.records:
                if r == run:
                    added.append(r.model_copy(update={"identity": new_run, "envelope": new_env}))
                elif isinstance(r, AuthorityEnvelopeRecord) and r.envelope.identity == run.envelope:
                    added.append(
                        r.model_copy(
                            update={"envelope": r.envelope.model_copy(update={"identity": new_env})}
                        )
                    )
                elif isinstance(r, M3PositionEntry) and r.identity.envelope == run.envelope:
                    added.append(
                        r.model_copy(
                            update={
                                "identity": r.identity.model_copy(update={"envelope": new_env}),
                                "predecessor": Present(
                                    value=r.predecessor.value.model_copy(
                                        update={"envelope": new_env}
                                    )
                                )
                                if isinstance(r.predecessor, Present)
                                else r.predecessor,
                            }
                        )
                    )
                elif (
                    isinstance(r, ConformanceDetermination)
                    and r.identity.activation == run.identity
                ):
                    added.append(
                        r.model_copy(
                            update={
                                "identity": r.identity.model_copy(update={"activation": new_run})
                            }
                        )
                    )
            bad = replace(records, records=records.records + tuple(added))
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(f, "read_lifecycle_records", lambda store, bad=bad: bad)
                assert f.route_after_closure(
                    x.store, x.root, x.head.identity, w.CYCLE
                ) == f.NotRouted(f.LifecycleCause.INCONSISTENT_RECORDS)


@pytest.mark.traces("CL-10", "SC-3", "ST09-T3")
def test_persistence_must_match_member_verdict_occurrence_and_cardinality_before_evaluation() -> (
    None
):
    from dataclasses import replace

    from gpauto import state_machine as sm
    from gpauto.coordination_records import ClosureAssessmentRecord

    with w.world() as x:
        frozen, occurrence = w.freeze_enter(x)
        w.close_cycle(x, frozen, occurrence)
        records = x.snapshot()
        assessments_by_member = {
            r.assessment.identity.assessed_finding: r
            for r in records.records
            if isinstance(r, ClosureAssessmentRecord)
        }
        assessments = [assessments_by_member[member] for member in frozen.members]
        other = tuple(r for r in records.records if not isinstance(r, ClosureAssessmentRecord))
        for effect, cause in (
            ((), f.LifecycleCause.ASSESSMENTS_NOT_RECORDED),
            ((assessments[0],), f.LifecycleCause.INCONSISTENT_RECORDS),
            ((*assessments, assessments[0]), f.LifecycleCause.INCONSISTENT_RECORDS),
            (
                (
                    assessments[0].model_copy(
                        update={"verdict": NotClosedVerdict(indeterminacy_reason=w.ABSENT)}
                    ),
                    assessments[1],
                ),
                f.LifecycleCause.INCONSISTENT_RECORDS,
            ),
            (
                (assessments[0].model_copy(update={"cycle_occurrence": w.ABSENT}), assessments[1]),
                f.LifecycleCause.INCONSISTENT_RECORDS,
            ),
        ):
            bad = replace(records, records=other + tuple(effect))
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(f, "read_lifecycle_records", lambda store, bad=bad: bad)
                patch.setattr(
                    sm,
                    "evaluate",
                    lambda *args: pytest.fail("corrupt persistence reached routing evaluator"),
                )
                patch.setattr(f, "mint_value", lambda: pytest.fail("corrupt persistence minted"))
                patch.setattr(
                    x.store, "create_unit", lambda rows: pytest.fail("corrupt persistence wrote")
                )
                assert f.route_after_closure(
                    x.store, x.root, x.head.identity, w.CYCLE
                ) == f.NotRouted(cause)
        with pytest.MonkeyPatch.context() as patch:
            unreadable = replace(records, unreadable=frozenset({ClosureAssessmentRecord}))
            patch.setattr(f, "read_lifecycle_records", lambda store: unreadable)
            assert f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE) == f.NotRouted(
                f.LifecycleCause.UNREADABLE_RECORDS
            )
