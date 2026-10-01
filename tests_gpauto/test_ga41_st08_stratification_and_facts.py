"""Design basis: AP-04 ST-1…ST-5, CP-4, RP-1…RP-3; PA9-2/PA9-3."""

from __future__ import annotations

import pytest

import st07_world as x
import st08_world as w
from gpauto import attribution as a
from gpauto import derivations as dv
from gpauto import state_machine_model as model
from gpauto.absence import Present
from gpauto.coordination_records import (
    ActivationEffectRecord,
    ConformanceDetermination,
    EnvelopeViolationRecord,
    HaltOccurrence,
)
from gpauto.identity import OwnerAuthorizationId, WorkerActivationId
from gpauto.repository import UnaccountedMutation

GPAUTO_STAGE = "GP-AUTO-ST-08"


@pytest.mark.traces(
    "ST-1", "ST-2", "ST-4", "AP04-I36", "ST08-D1", "ST08-D5", "ST08-T2", "ST08-A1", "AT9-0"
)
def test_a_lawful_in_boundary_write_never_self_invalidates() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("src/new", b"authorized content")
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        assert len(result.effects) == 1 and result.mutations == ()
        assert a.completion_facts(a.read_records(s.store), subject.identity) == {
            model.CP_4.name: "TRUE"
        }
        assert [type(d.determination).__name__ for d in result.determinations] == [
            "EnvelopeConformanceDetermination",
            "ResidueDetermination",
        ]
        s.close(subject, adopted=True)
        records = a.read_records(s.store)
        rows = a.classify_recorded(records, s.epoch.root)
        assert isinstance(rows, tuple)
        assert [r.row for r in rows] == [a.Row.DC9_2]


@pytest.mark.traces("ST-1", "AT9-5", "AP04-I36")
def test_assessment_never_reads_its_subjects_completion() -> None:
    signatures = []
    for ending in ("running", "completed", "unadopted"):
        with w.world() as s:
            subject, opening = w.begin(s)
            s.repo.write("src/new", b"same")
            if ending != "running":
                s.close(subject, adopted=ending == "completed")
            result = w.finish(s, subject, opening)
            assert isinstance(result, a.Assessed)
            signatures.append(
                (
                    tuple(e.observed_state for e in result.effects),
                    result.classification.defeats,
                    len(result.mutations),
                )
            )
    assert signatures[0] == signatures[1] == signatures[2]


@pytest.mark.traces("ST-3", "ST-5", "DC9-2", "DC9-10", "AT9-4")
def test_prior_authorized_delta_is_not_a_difference() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("src/new", b"first stratum")
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        s.close(subject, adopted=True)
        later, later_open = w.begin(s)
        result = w.finish(s, later, later_open)
        assert isinstance(result, a.Assessed)
        assert result.classification.differences == ()
        assert result.effects == () and result.mutations == ()
        assert len(x.stored(s.store, ActivationEffectRecord)) == 1


@pytest.mark.traces("DC9-4", "DC9-13", "DC9-14", "AP03-I28", "PA9-2", "ST08-T1")
def test_dc9_4_known_producer_residue_records_no_envelope_violation() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("src/new", b"in envelope")
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        s.close(subject)
        result2 = a.record_non_completed_residue(s.store, subject.identity)
        assert isinstance(result2, a.Recorded)
        assert result2.mutation.producing_activation == Present[WorkerActivationId](
            value=subject.identity
        )
        assert not x.stored(s.store, EnvelopeViolationRecord)
        rows = a.classify_recorded(a.read_records(s.store), s.epoch.root)
        assert isinstance(rows, tuple)
        assert [r.row for r in rows] == [a.Row.DC9_4]


@pytest.mark.traces("DC9-4", "AT9-4")
def test_non_completed_residue_is_recorded_once() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("src/new", b"in envelope")
        assert isinstance(w.finish(s, subject, opening), a.Assessed)
        s.close(subject)
        first = a.record_non_completed_residue(s.store, subject.identity)
        assert isinstance(first, a.Recorded)
        records = x.store_state(s.store)
        assert a.record_non_completed_residue(s.store, subject.identity) == a.Replayed(
            mutations=(first.mutation,)
        )
        assert x.store_state(s.store) == records


@pytest.mark.traces("AP04-I36", "DC9-17", "ST08-N5")
def test_cp4_is_false_when_an_unaccounted_mutation_names_the_activation() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("src/new", b"in envelope")
        assert isinstance(w.finish(s, subject, opening), a.Assessed)
        s.close(subject)
        assert isinstance(a.record_non_completed_residue(s.store, subject.identity), a.Recorded)
        assert a.completion_facts(a.read_records(s.store), subject.identity) == {
            model.CP_4.name: "FALSE"
        }


@pytest.mark.traces("ST-2", "AP04-I36")
def test_cp4_is_absent_before_the_assessment_is_recorded() -> None:
    with w.world() as s:
        subject, _ = w.begin(s)
        assert a.completion_facts(a.read_records(s.store), subject.identity) == {}


@pytest.mark.traces("DC9-17", "ST08-N5", "PA9-3")
def test_rp1_reads_only_this_classification_context() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("outside", b"unaccounted")
        assert isinstance(w.finish(s, subject, opening), a.Assessed)
        records = a.read_records(s.store)
        assert a.violation_facts(records, s.epoch.root)[model.RP_1.name] == "FALSE"
        assert (
            a.violation_facts(records, OwnerAuthorizationId(value="other"))[model.RP_1.name]
            == "TRUE"
        )


@pytest.mark.traces("DC9-17", "ST08-N5")
def test_rp2_fails_on_any_envelope_violation_in_the_epoch() -> None:
    from st03_world import world

    # Existing lawful record fixture: this is a fact-consumer test, not ST-08-produced EV.
    source = world()
    records = dv.AuthoritativeRecords(tuple(source.records()))
    violations = [r for r in source.records() if isinstance(r, EnvelopeViolationRecord)]
    assert violations
    assert (
        a.violation_facts(records, violations[0].violation.resolved_root)[model.RP_2.name]
        == "FALSE"
    )


@pytest.mark.traces("DC9-17", "ST08-N5")
def test_rp3_is_true_only_for_a_case_a_refusal_halt() -> None:
    from gpauto.coordination_identity import HaltOccurrenceId
    from gpauto.coordination_vocabulary import M2Position
    from gpauto.identity import RefusalId, UnaccountedMutationId
    from st03_world import ABSENT

    halt = HaltOccurrence(
        identity=HaltOccurrenceId(value="halt"),
        event=RefusalId(value="refusal"),
        source_state=M2Position.S3_IMPLEMENTATION_ACTIVE,
        cycle_occurrence=ABSENT,
    )
    for event, expected in (
        (RefusalId(value="refusal"), "TRUE"),
        (UnaccountedMutationId(value="um"), "FALSE"),
    ):
        record = halt.model_copy(update={"event": event})
        assert a.halt_cause_facts(dv.AuthoritativeRecords((record,)), halt.identity) == {
            model.RP_3.name: expected
        }
    assert a.halt_cause_facts(dv.AuthoritativeRecords(()), halt.identity) == {}


@pytest.mark.traces("DC9-17", "ST08-N5")
def test_unreadable_governance_records_supply_no_fact() -> None:
    for kind in (UnaccountedMutation, EnvelopeViolationRecord):
        for field in ("unreadable", "unstable"):
            records = dv.AuthoritativeRecords((), **{field: frozenset({kind})})
            assert a.violation_facts(records, OwnerAuthorizationId(value="root")) == {}
            assert a.completion_facts(records, WorkerActivationId(value="subject")) == {}
    records = dv.AuthoritativeRecords((), unreadable=frozenset({ConformanceDetermination}))
    assert a.completion_facts(records, WorkerActivationId(value="subject")) == {}


@pytest.mark.traces("ST08-N5", "DC9-17")
def test_facts_consume_records_with_zero_repository_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    from gpauto import observation
    from gpauto.coordination_identity import HaltOccurrenceId

    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("src/fact", b"lawful")
        assert isinstance(w.finish(s, subject, opening), a.Assessed)
        records = a.read_records(s.store)
        reader = x.CountingReader()

        def forbidden(*args: object, **kwargs: object) -> None:
            pytest.fail("a record fact must not observe the repository")

        monkeypatch.setattr(observation, "observe", forbidden)
        assert a.completion_facts(records, subject.identity)[model.CP_4.name] == "TRUE"
        assert a.violation_facts(records, s.epoch.root)[model.RP_1.name] == "TRUE"
        assert a.halt_cause_facts(records, HaltOccurrenceId(value="absent")) == {}
        assert reader.calls == []
