"""Design basis: AP-09 AT9-1…AT9-5; accepted 01-A/03-B/04-A; ST-08 plan §6."""

from __future__ import annotations

import pytest

import st07_world as x
import st08_world as w
from gpauto import attribution as a
from gpauto.coordination_records import (
    ActivationEffectRecord,
    EnvelopeViolationRecord,
    M3PositionEntry,
)
from gpauto.coordination_vocabulary import Quiescence
from gpauto.repository import UnaccountedMutation

GPAUTO_STAGE = "GP-AUTO-ST-08"


@pytest.mark.traces("AT9-1", "AT9-1b", "AT9-2", "OB9-9a", "ST08-D2")
def test_running_quiescent_subject_can_take_its_own_closing_bracket() -> None:
    with w.world() as s:
        envelope = s.envelope()
        opening = a.take_opening_bracket(s.store, envelope.envelope.identity)
        assert isinstance(opening, a.Bracket)
        subject = s.dispatch(envelope)
        s.repo.write("src/new", b"lawful\n")
        s.quiesce(subject)
        history = x.stored(s.store, M3PositionEntry)
        closing = a.take_closing_bracket(s.store, subject.identity)
        assert isinstance(closing, a.Bracket)
        assert x.stored(s.store, M3PositionEntry) == history
        result = a.assess_activation(s.store, subject.identity, opening, closing)
        assert isinstance(result, a.Assessed), result
        assert len(x.stored(s.store, ActivationEffectRecord)) == 1
        assert not x.stored(s.store, UnaccountedMutation)
        assert not x.stored(s.store, EnvelopeViolationRecord)


@pytest.mark.traces("AT9-2", "ST08-N2")
def test_closing_bracket_refused_without_observed_quiescence() -> None:
    with w.world() as s:
        subject = s.dispatch(s.envelope())
        reader = x.CountingReader()
        result = a.take_closing_bracket(s.store, subject.identity, reader)
        assert isinstance(result, a.BracketIndeterminate)
        assert result.cause == a.AssessmentCause.QUIESCENCE_NOT_OBSERVED
        assert reader.calls == []


@pytest.mark.traces("AT9-2", "ST08-N2")
def test_indeterminate_quiescence_is_never_quiescence() -> None:
    for value in (Quiescence.INDETERMINATE, Quiescence.NOT_QUIESCENT):
        with w.world() as s:
            subject = s.dispatch(s.envelope())
            s.quiesce(subject, value)
            assert isinstance(
                a.take_closing_bracket(s.store, subject.identity), a.BracketIndeterminate
            )


@pytest.mark.traces("AT9-1", "ST08-D2")
def test_opening_bracket_is_taken_only_before_dispatch() -> None:
    with w.world() as s:
        subject = s.dispatch(s.envelope())
        assert isinstance(a.take_opening_bracket(s.store, subject.envelope), a.BracketIndeterminate)


@pytest.mark.traces("AT9-1b")
def test_e12_directory_prefix_and_exact_path_tokens_are_distinct() -> None:
    assert a.within_write_boundary(b"src/a", ("src/",))
    assert a.within_write_boundary(b"src", ("src",))
    assert not a.within_write_boundary(b"src/a", ("src",))
    assert not a.within_write_boundary(b"srcx/a", ("src/",))
    assert not a.within_write_boundary(b"src", ("src/",))


@pytest.mark.traces("AT9-1b")
@pytest.mark.parametrize(
    ("path", "token"),
    [
        (b"src/\xff", "src/"),
        (b"src/a", " src/"),
        (b"src/a", "SRC/"),
        (b"src/a", "src\\"),
        (b"src/a", "src/*"),
        ("e\u0301/a".encode(), "é/"),
    ],
)
def test_e12_containment_performs_no_normalization(path: bytes, token: str) -> None:
    assert not a.within_write_boundary(path, (token,))


@pytest.mark.traces("AT9-1b", "ST08-N2")
def test_closing_bracket_refused_while_another_activation_runs() -> None:
    with w.world() as s:
        subject, _ = w.begin(s)
        s.quiesce(subject)
        s.dispatch(s.envelope())
        result = a.take_closing_bracket(s.store, subject.identity)
        assert isinstance(result, a.BracketIndeterminate)
        assert result.cause == a.AssessmentCause.WRITE_DOMAIN_NOT_EXCLUSIVE


@pytest.mark.traces("AT9-1", "OB9-9a")
def test_opening_bracket_refused_until_every_predecessor_is_closed_and_quiescent() -> None:
    with w.world() as s:
        subject, _ = w.begin(s)
        s.close(subject)
        next_envelope = s.envelope()
        result = a.take_opening_bracket(s.store, next_envelope.envelope.identity)
        assert isinstance(result, a.BracketIndeterminate)
        assert result.cause == a.AssessmentCause.PREDECESSOR_NOT_CLOSED


@pytest.mark.traces("AT9-1", "OB9-9a")
def test_opening_bracket_refused_before_the_previous_determinations_exist() -> None:
    with w.world() as s:
        subject, _ = w.begin(s)
        s.quiesce(subject)
        s.close(subject)
        next_envelope = s.envelope()
        result = a.take_opening_bracket(s.store, next_envelope.envelope.identity)
        assert isinstance(result, a.BracketIndeterminate)
        assert result.cause == a.AssessmentCause.PREDECESSOR_NOT_DETERMINED


@pytest.mark.traces("AT9-1b", "ST08-N1", "ST08-T1")
@pytest.mark.supports("DC9-9")
def test_a_missing_opening_bracket_fails_closed() -> None:
    with w.world() as s:
        subject = s.dispatch(s.envelope())
        s.quiesce(subject)
        closing = a.take_closing_bracket(s.store, subject.identity)
        assert isinstance(closing, a.Bracket)
        before = x.store_state(s.store)
        result = a.assess_activation(s.store, subject.identity, None, closing)
        assert isinstance(result, a.NotAssessed)
        assert result.cause == a.AssessmentCause.OPENING_BRACKET_MISSING
        assert result.row == a.Row.DC9_9
        assert x.store_state(s.store) == before


@pytest.mark.traces("AT9-1b")
def test_a_bracket_taken_for_another_activation_is_refused() -> None:
    from dataclasses import replace

    from gpauto.identity import WorkerActivationId

    with w.world() as s:
        subject, opening = w.begin(s)
        assert isinstance(opening, a.Bracket)
        s.quiesce(subject)
        closing = a.take_closing_bracket(s.store, subject.identity)
        assert isinstance(closing, a.Bracket)
        wrong = replace(closing, activation=WorkerActivationId(value="another"))
        result = a.assess_activation(s.store, subject.identity, opening, wrong)
        assert isinstance(result, a.NotAssessed)
        assert result.cause == a.AssessmentCause.BRACKET_MISMATCH


@pytest.mark.traces("AT9-1b", "ST08-N1")
def test_a_second_writing_activation_over_the_interval_prevents_attribution() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        other = s.dispatch(s.envelope())
        s.quiesce(other)
        s.close(other)
        s.repo.write("src/new", b"not exclusive")
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        assert result.effects == ()
        assert "interval" in result.classification.defeats


@pytest.mark.traces("AT9-1b", "AT9-1a", "ST08-N1")
def test_a_read_only_envelope_is_never_attributed_an_effect() -> None:
    from test_ga40_st08_defeat_and_classification import challenge

    assert "c" in challenge("reviewer").classification.defeats


@pytest.mark.traces("AT9-1b", "AT9-1a", "ST08-N1")
def test_an_effect_outside_the_write_boundary_is_never_attributed() -> None:
    from test_ga40_st08_defeat_and_classification import challenge

    assert "a" in challenge("outside").classification.defeats


@pytest.mark.traces("IX-1a", "AT9-1c")
def test_mid_observation_change_makes_the_bracket_indeterminate() -> None:
    with w.world() as s:
        envelope = s.envelope()
        reader = x.FaultReader({("read_regular", b"/a.txt", 1): x.torn})
        result = a.take_opening_bracket(s.store, envelope.envelope.identity, reader)
        assert isinstance(result, a.BracketIndeterminate)
        assert result.cause == a.AssessmentCause.OBSERVATION_INDETERMINATE
        assert reader.fired


@pytest.mark.traces("AT9-1b", "AT9-3")
def test_remediator_correspondence_is_per_effect_objective_content() -> None:
    with w.world() as s:
        subject, opening, obligation = w.remediation(s)
        s.repo.write("src/a", b"match")
        w.ingest_change(s, subject, obligation, b"match")
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        assert len(result.effects) == 1 and not result.mutations
        assert result.effects[0].cycle_occurrence == subject.cycle_occurrence


@pytest.mark.traces("AT9-1b", "AT9-1c", "ST08-N2")
def test_one_unaccounted_remediator_effect_poisons_the_whole_bracket() -> None:
    with w.world() as s:
        subject, opening, obligation = w.remediation(s)
        s.repo.write("src/a", b"match")
        s.repo.write("src/b", b"not match")
        w.ingest_change(s, subject, obligation, b"match")
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        assert "f" in result.classification.defeats
        assert not result.effects and len(result.mutations) == 2


@pytest.mark.traces("AT9-1b", "AT9-1a", "AT9-3", "ST08-N1")
def test_an_unaccounted_remediator_effect_is_residue_not_delta() -> None:
    for mode in ("absent", "not-addressed", "report", "not-objective-channel", "deletion"):
        with w.world() as s:
            subject, opening, obligation = w.remediation(s)
            if mode == "deletion":
                (s.repo.path / "src/b.py").unlink()
            else:
                s.repo.write("src/a", b"match")
            if mode != "absent":
                w.ingest_change(
                    s,
                    subject,
                    obligation,
                    b"report" if mode == "report" else b"match",
                    addressed=mode != "not-addressed",
                    objective_channel=mode != "not-objective-channel",
                )
            result = w.finish(s, subject, opening)
            assert isinstance(result, a.Assessed)
            assert "f" in result.classification.defeats
            assert not result.effects and len(result.mutations) == 1


@pytest.mark.traces("AT9-1b", "ST08-N1")
def test_an_item_for_an_unadmitted_obligation_accounts_for_nothing() -> None:
    from gpauto import derivations as dv
    from gpauto.governance import ObligationExtinguishingDecision, OwnerDecision
    from gpauto.identity import OwnerDecisionId, RemediationObligationId
    from gpauto.vocabulary import OwnerDecisionKind
    from st03_ingest import ingest
    from st03_world import ABSENT

    with w.world() as s:
        subject, opening, obligation = w.remediation(s)
        assert isinstance(obligation, RemediationObligationId)
        s.repo.write("src/a", b"match")
        w.ingest_change(s, subject, obligation, b"match")
        # ST-09/OWNER fixture changes the recorded admitted set, not a mocked classifier.
        decision = OwnerDecision(
            identity=OwnerDecisionId(value="waive-fixture"),
            stage=subject.stage,
            act=ObligationExtinguishingDecision(
                kind=OwnerDecisionKind.WAIVER,
                obligation=obligation,
                produced_authorization=ABSENT,
                corrects=ABSENT,
            ),
        )
        ingest(s.store.path, (decision,))
        admitted = dv.derive_cycle_bound(a.read_records(s.store), s.epoch.root)
        assert isinstance(admitted, dv.CycleBound) and obligation not in admitted.members
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        assert "f" in result.classification.defeats
        assert not result.effects and len(result.mutations) == 1
