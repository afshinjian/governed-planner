"""Design basis: ST-09 plan §6.2; AP-05 DO, FZ, FI; AP-07 WP-17."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

import pytest

import st09_world as w
from gpauto import derivations as dv
from gpauto import finding_lifecycle as f
from gpauto import state_machine as sm
from gpauto.absence import Present
from gpauto.coordination_records import (
    AuthorityEnvelopeRecord,
    DiscoveryVerdictItem,
    FindingItem,
    FindingRecord,
    M2PositionEntry,
    M3PositionEntry,
    OutcomeIngestionRecord,
    PostFreezeCandidateItem,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import (
    DiscoveryVerdict,
    M1Position,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
)
from gpauto.identity import AuthorityEnvelopeId, FindingId, OwnerAuthorizationId, WorkerActivationId
from gpauto.review import FrozenFindingSet, RemediationObligation
from gpauto.store import CoordinationRecord, WriteRefused
from gpauto.vocabulary import AuthorizationDisposition, Role
from st03_world import m3, minted

GPAUTO_STAGE = "GP-AUTO-ST-09"


@pytest.mark.traces(
    "ST09-T1",
    "ST09-D1",
    "ST09-D2",
    "ST09-D3",
    "DO-2",
    "DO-12",
    "FZ-2",
    "FZ-3",
    "FZ-4",
    "FI-1",
    "FI-2",
    "FI-3",
    "FI-4",
    "AP05-I12",
)
def test_one_finding_is_minted_per_item_even_when_identical() -> None:
    with w.world() as x:
        run = x.discovery(2)
        result = f.freeze(x.store, run.identity, w.B5)
        assert isinstance(result, f.Frozen), result
        (frozen,) = w.rows(x.store, FrozenFindingSet)
        assert len(frozen.members) == len(set(frozen.members)) == 2
        findings = w.rows(x.store, FindingRecord)
        assert {r.finding.identity for r in findings} == set(frozen.members)
        assert len(w.rows(x.store, RemediationObligation)) == 2
        assert len([e for e in w.rows(x.store, M2PositionEntry) if e.edge == M2Edge.B5]) == 1


def _no_writes(monkeypatch: pytest.MonkeyPatch, x: w.LifecycleWorld) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("refusal or replay attempted a mint/write")

    monkeypatch.setattr(f, "mint_value", forbidden)
    monkeypatch.setattr(x.store, "create_unit", forbidden)


@pytest.mark.traces(
    "FZ-1",
    "DO-4",
    "DO-7",
    "DO-8",
    "DO-9",
    "DO-15",
    "DO-16",
    "AP03-I36",
    "AP05-I01",
    "AP05-I04",
    "ST09-N2",
)
def test_no_set_from_an_unadopted_or_uncompleted_discovery() -> None:
    for outcome, adopted in (("completed", False), ("running", False), ("unadopted", False)):
        with w.world() as x:
            run = x.discovery(outcome=outcome, adopted=adopted)
            with pytest.MonkeyPatch.context() as patch:
                _no_writes(patch, x)
                assert f.freeze(x.store, run.identity, w.B5) == f.NotFrozen(
                    f.LifecycleCause.NOT_COMPLETED_ADOPTED
                )
            assert not w.rows(x.store, FrozenFindingSet)


@pytest.mark.traces("DO-6", "DO-15", "AP05-I04", "ST09-N2")
def test_a_c3_voided_discovery_envelope_never_freezes() -> None:
    with w.world() as x:
        template = x.built.handles["envelope"]
        assert isinstance(template, AuthorityEnvelopeRecord)
        envelope = template.model_copy(
            update={
                "envelope": template.envelope.model_copy(
                    update={
                        "identity": minted(AuthorityEnvelopeId),
                        "role": Role.DISCOVERY_REVIEWER,
                    }
                ),
                "predecessor_entry": x.head.identity,
                "target_state": M2Position.S4_DISCOVERY_ACTIVE,
            }
        )
        derived = m3(envelope.envelope.identity, M3Position.ENVELOPE_DERIVED, M3Edge.C1, None)
        voided = m3(envelope.envelope.identity, M3Position.ENVELOPE_VOIDED, M3Edge.C3, derived)
        x.store.create_unit((envelope, derived, voided))
        before = x.snapshot()
        reached = dv.derive_m3_position(before, envelope.envelope.identity)
        assert isinstance(reached, dv.Occupancy) and reached.reached == voided
        assert not any(
            r.envelope == envelope.envelope.identity
            for r in w.rows(x.store, WorkerActivationRecord)
        )
        with pytest.MonkeyPatch.context() as patch:
            _no_writes(patch, x)
            assert f.freeze(x.store, WorkerActivationId(value="never-dispatched"), w.B5) == (
                f.NotFrozen(f.LifecycleCause.SUBJECT_NOT_FOUND)
            )
        assert frozenset(x.snapshot().records) == frozenset(before.records)
        assert not w.rows(x.store, FrozenFindingSet)
        assert not w.rows(x.store, FindingRecord)
        assert not w.rows(x.store, RemediationObligation)
        assert not any(e.edge == M2Edge.B5 for e in w.rows(x.store, M2PositionEntry))


@pytest.mark.traces("DO-11", "DO-15", "AP05-I04", "ST09-N2")
def test_a_c6_discovery_closed_on_authority_loss_never_freezes() -> None:
    with w.world() as x:
        run = x.discovery(outcome="running", adopted=False)
        running = dv.derive_m3_position(x.snapshot(), run.envelope)
        assert isinstance(running, dv.Occupancy)
        assert running.reached.state == M3Position.ACTIVATION_RUNNING
        x.advance(M2Position.S9_EPOCH_HALTED, M2Edge.B9)
        closed = m3(
            run.envelope, M3Position.ACTIVATION_CLOSED_UNADOPTED, M3Edge.C6, running.reached
        )
        x.store.create(closed)
        before = x.snapshot()
        reached = dv.derive_m3_position(before, run.envelope)
        assert isinstance(reached, dv.Occupancy) and reached.reached == closed
        with pytest.MonkeyPatch.context() as patch:
            _no_writes(patch, x)
            assert f.freeze(x.store, run.identity, w.B5) == f.NotFrozen(
                f.LifecycleCause.NOT_COMPLETED_ADOPTED
            )
        assert f.freeze_facts(before, run.identity).get("STEP_ACTIVATION_COMPLETED") != "TRUE"
        assert frozenset(x.snapshot().records) == frozenset(before.records)
        assert not w.rows(x.store, FrozenFindingSet)
        assert not w.rows(x.store, FindingRecord)
        assert not w.rows(x.store, RemediationObligation)
        assert not any(e.edge == M2Edge.B5 for e in w.rows(x.store, M2PositionEntry))


@pytest.mark.traces("FZ-5", "OB-1", "FI-5", "AP05-I13", "AP05-I15")
def test_every_member_has_its_obligation_in_the_same_unit() -> None:
    with w.world() as x:
        run = x.discovery(3)
        units: list[tuple[object, ...]] = []
        original = x.store.create_unit

        def capture(records: Iterable[CoordinationRecord]) -> None:
            unit = tuple(records)
            units.append(unit)
            original(unit)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(x.store, "create_unit", capture)
            result = f.freeze(x.store, run.identity, w.B5)
        assert isinstance(result, f.Frozen)
        assert len(units) == 1
        assert len([o for o in units[0] if isinstance(o, RemediationObligation)]) == 3
        assert {o.identity.member_finding for o in w.rows(x.store, RemediationObligation)} == set(
            result.frozen_set.members
        )


@pytest.mark.traces("ST09-M1", "FZ-4")
def test_the_freeze_unit_carries_its_b5_entry() -> None:
    with w.world() as x:
        result = f.freeze(x.store, x.discovery().identity, w.B5)
        assert isinstance(result, f.Frozen)
        assert result.entry in w.rows(x.store, M2PositionEntry)
        assert result.entry.predecessor == Present(value=x.head.identity)


@pytest.mark.traces("FZ-6", "DO-12")
def test_finding_content_binding_follows_the_selected_rule() -> None:
    for count in (2, 0, 1):
        with w.world() as x:
            run = x.discovery(objectives=count)
            result = f.freeze(x.store, run.identity, w.B5)
            if count != 1:
                assert result == f.NotFrozen(f.LifecycleCause.CONTENT_BINDING_INDETERMINATE)
                assert not w.rows(x.store, FrozenFindingSet)
            else:
                assert isinstance(result, f.Frozen)
                (ingestion,) = w.rows(x.store, OutcomeIngestionRecord)
                assert all(
                    r.content_binding.production == ingestion.objective_channel[0]
                    for r in w.rows(x.store, FindingRecord)
                )


@pytest.mark.traces("ST09-B1", "AP05-I03")
def test_upstream_facts_cannot_supply_an_st09_fact() -> None:
    with w.world() as x:
        run = x.discovery()
        assert f.freeze(
            x.store, run.identity, w.B5 | {"VERDICT_SET_CONSISTENT": "TRUE"}
        ) == f.NotFrozen(f.LifecycleCause.UPSTREAM_FACTS_INVALID)


@pytest.mark.traces("DO-10", "DO-14", "AP05-I35")
def test_a_refused_b5_writes_nothing() -> None:
    with w.world() as x:
        run = x.discovery()
        result = f.freeze(x.store, run.identity, w.B5 | {"UNACCOUNTED_MUTATION": "TRUE"})
        assert isinstance(result, f.NotFrozen) and result.cause == f.LifecycleCause.GUARD_REFUSED
        assert not w.rows(x.store, FrozenFindingSet)
        x.advance(M2Position.S9_EPOCH_HALTED, M2Edge.B9)
        assert f.freeze(x.store, run.identity, w.B5) == f.NotFrozen(
            f.LifecycleCause.EPOCH_NOT_AT_POSITION
        )


def _second_discovery(
    records: dv.AuthoritativeRecords, run: WorkerActivationRecord
) -> dv.AuthoritativeRecords:
    """Labelled corrupt Class A view: two C4 chains, independent of FP-17."""
    other = run.model_copy(
        update={
            "identity": WorkerActivationId(value="second-discovery"),
            "envelope": AuthorityEnvelopeId(value="second-envelope"),
        }
    )
    added: list[object] = [other]
    for record in records.records:
        if isinstance(record, AuthorityEnvelopeRecord) and record.envelope.identity == run.envelope:
            added.append(
                record.model_copy(
                    update={
                        "envelope": record.envelope.model_copy(update={"identity": other.envelope})
                    }
                )
            )
        if isinstance(record, M3PositionEntry) and record.identity.envelope == run.envelope:
            predecessor = record.predecessor
            if isinstance(predecessor, Present):
                predecessor = Present(
                    value=predecessor.value.model_copy(update={"envelope": other.envelope})
                )
            added.append(
                record.model_copy(
                    update={
                        "identity": record.identity.model_copy(update={"envelope": other.envelope}),
                        "predecessor": predecessor,
                    }
                )
            )
    return replace(records, records=records.records + tuple(added))  # type: ignore[arg-type]


def _discovery_coupling(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> tuple[sm.CouplingViolation, ...]:
    subjects = []
    for run in records.records:
        if not isinstance(run, WorkerActivationRecord) or run.resolved_root != root:
            continue
        if run.role != Role.DISCOVERY_REVIEWER:
            continue
        envelope = next(
            r
            for r in records.records
            if isinstance(r, AuthorityEnvelopeRecord) and r.envelope.identity == run.envelope
        )
        position = dv.derive_m3_position(records, run.envelope)
        assert isinstance(position, dv.Occupancy)
        subjects.append(
            sm.Subject(
                run.envelope.value,
                position.reached.state,
                envelope.target_state,
                None,
                True,
                None,
            )
        )
    config = sm.Configuration(
        M1Position.ROOT_RESOLVED,
        M2Position.S4_DISCOVERY_ACTIVE,
        AuthorizationDisposition.LIVE,
        True,
        tuple(subjects),
    )
    return tuple(v for v in sm.coupling_violations(config) if v.invariant == "K-6")


@pytest.mark.traces("AP04-I31", "AP05-I11", "AP05-I34", "ST09-A1")
def test_two_completed_discoveries_under_one_root_are_inconsistent() -> None:
    for has_set in (False, True):
        with w.world() as x:
            run = x.discovery()
            if has_set:
                assert isinstance(f.freeze(x.store, run.identity, w.B5), f.Frozen)
            records = _second_discovery(x.snapshot(), run)
            assert _discovery_coupling(records, x.root) == (
                sm.CouplingViolation("K-6", "two completed subjects at S4_DISCOVERY_ACTIVE"),
            )
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(f, "read_lifecycle_records", lambda store, records=records: records)
                _no_writes(patch, x)
                assert f.freeze(x.store, run.identity, w.B5) == f.NotFrozen(
                    f.LifecycleCause.INCONSISTENT_RECORDS
                )
                assert (
                    f.freeze_facts(records, run.identity).get("STEP_ACTIVATION_COMPLETED") != "TRUE"
                )
                if has_set:
                    assert f.membership_facts(records, x.root)["FROZEN_SET_UNCHANGED"] == "FALSE"


@pytest.mark.traces("AP04-I31", "AP05-I11", "AP05-I34", "ST09-A1")
@pytest.mark.parametrize("other", ("closed-unadopted", "different-root"))
def test_one_completed_discovery_allows_uncompleted_or_unrelated_attempts(other: str) -> None:
    with w.world() as x, w.world("unrelated") as unrelated:
        if other == "closed-unadopted":
            x.discovery(outcome="unadopted", adopted=False)
            # A fresh unfinished-step entry gives the further attempt its own
            # envelope derivation key; restoration itself is a caller fixture.
            x.advance(M2Position.S9_EPOCH_HALTED, M2Edge.B9)
            x.advance(M2Position.S4_DISCOVERY_ACTIVE, M2Edge.B13)
        else:
            unrelated.discovery()
        run = x.discovery(0)
        records = x.snapshot()
        if other == "different-root":
            assert unrelated.root != x.root
            records = replace(records, records=records.records + unrelated.snapshot().records)
        assert _discovery_coupling(records, x.root) == ()
        assert isinstance(f.discovery_determination(records, run.identity), f.DiscoveryOutcome)
        assert f.freeze_facts(records, run.identity)["STEP_ACTIVATION_COMPLETED"] == "TRUE"
        assert f.membership_facts(records, x.root) == {}
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(f, "read_lifecycle_records", lambda store: records)
            frozen = f.freeze(x.store, run.identity, w.B5)
        assert isinstance(frozen, f.Frozen)
        assert frozen.frozen_set.members == ()
        assert frozen.frozen_set.originating_activation == run.identity
        assert w.rows(x.store, FrozenFindingSet) == (frozen.frozen_set,)


@pytest.mark.traces(
    "DO-13",
    "DO-18",
    "FZ-15",
    "FZ-17",
    "FZ-18",
    "FZ-19",
    "FZ-20",
    "FZ-21",
    "FZ-22",
    "AP05-I06",
    "AP05-I09",
    "ST09-T2",
    "ST09-N1",
)
@pytest.mark.supports("FZ-16", "AP05-I05")
def test_one_completed_zero_finding_discovery_with_no_set_is_legal() -> None:
    identities = []
    for _ in range(2):
        with w.world() as x:
            run = x.discovery(0)
            assert isinstance(
                f.discovery_determination(x.snapshot(), run.identity), f.DiscoveryOutcome
            )
            assert f.membership_facts(x.snapshot(), x.root) == {}
            result = f.freeze(x.store, run.identity, w.B5)
            assert isinstance(result, f.Frozen)
            identities.append(result.frozen_set.identity)
            assert result.frozen_set.members == ()
            assert not w.rows(x.store, RemediationObligation)
            assert f.membership_facts(x.snapshot(), x.root)["MEMBERSHIP_EMPTY"] == "TRUE"
    assert identities[0] != identities[1]


@pytest.mark.traces("FZ-10", "ST09-D2")
@pytest.mark.supports("FZ-8")
def test_a_second_freeze_reads_the_key_and_mints_nothing() -> None:
    with w.world() as x:
        run = x.discovery()
        original = f.freeze(x.store, run.identity, w.B5)
        assert isinstance(original, f.Frozen)
        with pytest.MonkeyPatch.context() as patch:
            _no_writes(patch, x)
            replay = f.freeze(x.store, run.identity, w.B5)
        assert replay == f.FreezeReplayed(original.frozen_set, original.entry)


@pytest.mark.traces("ST09-N3", "FZ-4")
def test_a_replayed_freeze_with_differing_content_is_a_conflict() -> None:
    with w.world() as x:
        run = x.discovery()
        assert isinstance(f.freeze(x.store, run.identity, w.B5), f.Frozen)
        records = x.snapshot()
        changed = replace(
            records,
            records=tuple(
                r.model_copy(update={"members": r.members[:-1]})
                if isinstance(r, FrozenFindingSet)
                else r
                for r in records.records
            ),
        )
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(f, "read_lifecycle_records", lambda store: changed)
            _no_writes(patch, x)
            assert f.freeze(x.store, run.identity, w.B5) == f.NotFrozen(f.LifecycleCause.CONFLICT)


@pytest.mark.traces("AP04-I45", "ST09-N3")
def test_a_finding_outside_membership_makes_the_set_changed() -> None:
    with w.world() as x:
        assert isinstance(f.freeze(x.store, x.discovery().identity, w.B5), f.Frozen)
        records = x.snapshot()
        first = w.rows(x.store, FindingRecord)[0]
        extra = first.model_copy(
            update={
                "finding": first.finding.model_copy(update={"identity": FindingId(value="outside")})
            }
        )
        corrupt = replace(records, records=records.records + (extra,))
        assert f.membership_facts(corrupt, x.root)["FROZEN_SET_UNCHANGED"] == "FALSE"


@pytest.mark.traces("AP05-I10", "FI-4")
def test_every_member_names_the_set_originating_activation() -> None:
    with w.world() as x:
        assert isinstance(f.freeze(x.store, x.discovery().identity, w.B5), f.Frozen)
        records = x.snapshot()
        corrupt = replace(
            records,
            records=tuple(
                r.model_copy(
                    update={
                        "finding": r.finding.model_copy(
                            update={"originating_activation": WorkerActivationId(value="other")}
                        )
                    }
                )
                if isinstance(r, FindingRecord)
                else r
                for r in records.records
            ),
        )
        assert f.membership_facts(corrupt, x.root)["FROZEN_SET_UNCHANGED"] == "FALSE"


@pytest.mark.traces("DO-1", "DO-3", "DO-17", "AP05-I03")
def test_verdict_and_items_inconsistent_never_freeze() -> None:
    for items in (
        (),
        (DiscoveryVerdictItem(verdict=DiscoveryVerdict.NO_FINDINGS), FindingItem()),
        (DiscoveryVerdictItem(verdict=DiscoveryVerdict.FINDINGS_REPORTED),),
        (DiscoveryVerdictItem(verdict=DiscoveryVerdict.NO_FINDINGS),) * 2,
    ):
        with w.world() as x:
            run = x.activation(Role.DISCOVERY_REVIEWER, items)
            assert f.freeze(x.store, run.identity, w.B5) == f.NotFrozen(
                f.LifecycleCause.OUTCOME_NONCONFORMANT
            )
            assert not w.rows(x.store, FrozenFindingSet)


@pytest.mark.traces("DO-5", "NF-4", "NF-5", "PF-8")
def test_a_discovery_outcome_asserting_a_disposition_is_nonconformant() -> None:
    from gpauto.activation import ObjectiveProductionReference
    from gpauto.coordination_records import (
        DisputeItem,
        MemberClosureResultItem,
        ObligationDispositionItem,
    )
    from gpauto.coordination_vocabulary import ClosedVerdict, ObligationDisposition

    with w.world() as x:
        run = x.discovery(0)
        records = x.snapshot()
        ingestion = next(
            r
            for r in records.records
            if isinstance(r, OutcomeIngestionRecord) and r.activation == run.identity
        )
        obligation = x.built.handles["obligation"]
        assert isinstance(obligation, RemediationObligation)
        forbidden = (
            ObligationDispositionItem(
                obligation=obligation.identity,
                disposition=ObligationDisposition.ADDRESSED,
                change_evidence=ObjectiveProductionReference(
                    production=ingestion.objective_channel[0]
                ),
            ),
            MemberClosureResultItem(
                member=obligation.identity.member_finding, verdict=ClosedVerdict()
            ),
            DisputeItem(),
            PostFreezeCandidateItem(),
        )
        for item in forbidden:
            altered = replace(
                records,
                records=tuple(
                    r.model_copy(update={"items": (*ingestion.items, item)})
                    if r == ingestion
                    else r
                    for r in records.records
                ),
            )
            assert isinstance(f.discovery_determination(altered, run.identity), f.Nonconformant)
        assert isinstance(f.discovery_determination(records, run.identity), f.DiscoveryOutcome)


@pytest.mark.traces("ST09-R1", "ST09-M1")
def test_write_refused_freeze_requires_the_complete_prior_effect() -> None:
    for corruption in ("equivalent", "binding", "finding", "obligation", "entry", "unreadable"):
        with w.world() as x:
            run = x.discovery()
            before = x.snapshot()
            committed = f.freeze(x.store, run.identity, w.B5)
            assert isinstance(committed, f.Frozen)
            after = x.snapshot()
            removed = {
                "finding": FindingRecord,
                "obligation": RemediationObligation,
                "entry": M2PositionEntry,
            }.get(corruption)
            if removed:
                after = replace(
                    after,
                    records=tuple(
                        r
                        for r in after.records
                        if not isinstance(r, removed)
                        or (isinstance(r, M2PositionEntry) and r.edge != M2Edge.B5)
                    ),
                )
            if corruption == "binding":
                after = replace(
                    after,
                    records=tuple(
                        r.model_copy(
                            update={
                                "items": (
                                    DiscoveryVerdictItem(verdict=DiscoveryVerdict.NO_FINDINGS),
                                )
                            }
                        )
                        if isinstance(r, OutcomeIngestionRecord)
                        else r
                        for r in after.records
                    ),
                )
            if corruption == "unreadable":
                after = replace(after, unreadable=frozenset({FindingRecord}))
            snapshots = iter((before, after))

            def refuse(records: object) -> None:
                raise WriteRefused("competing commit / injected corrupt read")

            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(
                    f, "read_lifecycle_records", lambda store, snapshots=snapshots: next(snapshots)
                )
                patch.setattr(x.store, "create_unit", refuse)
                result = f.freeze(x.store, run.identity, w.B5)
            if corruption == "equivalent":
                assert result == f.FreezeReplayed(committed.frozen_set, committed.entry)
            else:
                expected = (
                    f.LifecycleCause.UNREADABLE_RECORDS
                    if corruption == "unreadable"
                    else f.LifecycleCause.CONFLICT
                )
                assert result == f.NotFrozen(expected)


@pytest.mark.traces("FZ-13", "FZ-19", "AP05-I08", "AP05-I39")
def test_empty_membership_refuses_b6a_and_admits_the_empty_branch() -> None:
    from gpauto import state_machine as sm
    from gpauto import state_machine_model as model
    from gpauto.coordination_records import ClosureAssessmentRecord, CycleOccurrence

    with w.world() as x:
        frozen = f.freeze(x.store, x.discovery(0).identity, w.B5)
        assert isinstance(frozen, f.Frozen)
        assert isinstance(
            f.enter_first_occurrence(x.store, x.root, frozen.entry.identity, w.B6A), f.NotEntered
        )
        rule = next(r for r in model.EDGES if r.edge == M2Edge.B6b)
        assert isinstance(rule.guard, model.Conjunctive)
        facts = {c.fact.name: c.admitted[0] for c in rule.guard.alternatives[0]}
        facts.update(f.membership_facts(x.snapshot(), x.root))
        assert isinstance(sm.evaluate(M2Edge.B6b, frozen.entry.state, facts), sm.Admitted)
        assert not w.rows(x.store, CycleOccurrence) and not w.rows(x.store, ClosureAssessmentRecord)


@pytest.mark.traces("ST09-R1", "FZ-5", "AP05-I13")
def test_an_orphan_obligation_without_a_freeze_key_is_inconsistent() -> None:
    with w.world() as x:
        run = x.discovery()
        assert isinstance(f.freeze(x.store, run.identity, w.B5), f.Frozen)
        records = x.snapshot()
        orphan = replace(
            records,
            records=tuple(
                r
                for r in records.records
                if not isinstance(r, FrozenFindingSet | FindingRecord)
                and not (isinstance(r, M2PositionEntry) and r.edge == M2Edge.B5)
            ),
        )
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(f, "read_lifecycle_records", lambda store: orphan)
            _no_writes(patch, x)
            assert f.freeze(x.store, run.identity, w.B5) == f.NotFrozen(
                f.LifecycleCause.INCONSISTENT_RECORDS
            )
