"""Design basis: AP-09 §8 as amended; PA-03-B path-specific negative evidence.

P(N,e) => C(N,e): full attribution requires writing and containment. A read-only
interval excludes P. These tests exercise real nonempty observations and recording;
they do not witness the positive established-violation branch on another path.
NV11-16 local evidence is supplied here; ST-18 retains its integrative ownership.
"""

from __future__ import annotations

import pytest

import st07_world as x
import st08_world as w
from gpauto import attribution as a
from gpauto import state_machine_model as model
from gpauto.absence import NotObserved
from gpauto.coordination_records import (
    ActivationEffectRecord,
    ConformanceDetermination,
    EnvelopeViolationRecord,
    M3PositionEntry,
)
from gpauto.repository import UnaccountedMutation
from gpauto.vocabulary import Role

GPAUTO_STAGE = "GP-AUTO-ST-08"


def challenge(kind: str, *, late: bool = False) -> a.Assessed:
    with w.world() as s:
        role = Role.DISCOVERY_REVIEWER if kind == "reviewer" else Role.IMPLEMENTER
        envelope = s.envelope(role)
        if kind == "opening":
            s.repo.write("src/pre", b"before dispatch")
        opening = a.take_opening_bracket(s.store, envelope.envelope.identity)
        assert isinstance(opening, a.Bracket)
        subject = s.dispatch(envelope)
        if late:
            s.quiesce(subject)
            s.close(subject, adopted=True)
        s.repo.write("src/good", b"inside")
        if kind in {"outside", "mixed"}:
            s.repo.write("outside", b"outside")
        if kind in {"index", "mixed"}:
            s.repo.git("add", "src/good")
        if kind in {"history", "mixed"}:
            s.repo.git("commit", "--allow-empty", "-q", "-m", "external")
        if kind == "branch":
            s.repo.git("checkout", "-q", "-b", "other")
        history = x.stored(s.store, M3PositionEntry)
        adoption = x.stored(s.store, ConformanceDetermination)
        snapshot = x.snapshot(s.repo.path)
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed), result
        assert len(result.mutations) == len(result.classification.differences) > 0
        assert result.effects == ()
        assert not x.stored(s.store, ActivationEffectRecord)
        assert not x.stored(s.store, EnvelopeViolationRecord)
        assert all(isinstance(m.producing_activation, NotObserved) for m in result.mutations)
        assert all(m.context.authorization == s.epoch.root for m in result.mutations)
        assert all(
            m.context.entry_boundary == s.boundary.boundary.boundary.identity
            for m in result.mutations
        )
        assert x.snapshot(s.repo.path) == snapshot
        assert x.stored(s.store, M3PositionEntry) == history
        assert all(d in x.stored(s.store, ConformanceDetermination) for d in adoption)
        assert a.violation_facts(a.read_records(s.store), s.epoch.root) == {
            "UNACCOUNTED_MUTATION": "TRUE",
            model.RP_1.name: "FALSE",
            model.RP_2.name: "TRUE",
        }
        assert a.completion_facts(a.read_records(s.store), subject.identity) == {
            model.CP_4.name: "TRUE"
        }
        return result


@pytest.mark.traces("AT9-1c", "ST08-D3", "ST08-N2", "AT9-7", "ST08-N3", "DC9-8")
def test_an_out_of_boundary_effect_poisons_the_whole_bracket() -> None:
    result = challenge("outside")
    assert "a" in result.classification.defeats
    assert {r.row for r in result.classification.differences} == {a.Row.DC9_8}


@pytest.mark.traces("AT9-1c", "ST08-N2")
def test_an_index_change_poisons_the_whole_bracket() -> None:
    result = challenge("index")
    assert "b" in result.classification.defeats
    assert {r.row for r in result.classification.differences} == {a.Row.DC9_6, a.Row.DC9_8}


@pytest.mark.traces("AT9-1c", "ST08-N2", "OB9-3")
def test_a_committed_history_change_poisons_the_whole_bracket() -> None:
    result = challenge("history")
    assert "b" in result.classification.defeats
    assert {r.row for r in result.classification.differences} == {a.Row.DC9_7, a.Row.DC9_8}


@pytest.mark.traces("AT9-8", "OB9-5", "PA9-4", "ST08-N2")
def test_a_read_only_interval_difference_poisons_the_whole_bracket() -> None:
    result = challenge("reviewer")
    assert "c" in result.classification.defeats
    assert {r.row for r in result.classification.differences} == {a.Row.DC9_8}


@pytest.mark.traces("AT9-1c", "GR9-8")
def test_a_pre_dispatch_change_poisons_the_bracket() -> None:
    result = challenge("opening")
    assert "opening" in result.classification.defeats


@pytest.mark.traces("DC9-6", "DC9-11", "DC9-12")
def test_an_index_entry_change_is_dc9_6_even_when_the_tree_is_unchanged() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.git("update-index", "--chmod=+x", "a.txt")
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        assert [r.row for r in result.classification.differences] == [a.Row.DC9_6]
        assert len(result.mutations) == 1


@pytest.mark.traces("DC9-7", "OB9-3")
def test_a_branch_switch_is_dc9_7() -> None:
    result = challenge("branch")
    assert any(r.row == a.Row.DC9_7 for r in result.classification.differences)


@pytest.mark.traces("DC9-7", "OB9-3")
def test_a_commit_moved_under_the_same_branch_is_dc9_7() -> None:
    result = challenge("history")
    assert {
        r.difference.subject for r in result.classification.differences if r.row == a.Row.DC9_7
    } == {"baseline", "committed-history"}


@pytest.mark.traces("AT9-6", "ST08-N4", "PA9-1")
def test_a_committed_history_change_names_no_producer() -> None:
    challenge("history")


@pytest.mark.traces("AT9-7", "DC9-8", "DC9-14", "ST08-N3")
def test_an_in_boundary_unattributed_difference_is_dc9_8_never_delta() -> None:
    challenge("outside")


@pytest.mark.traces("DC9-3", "DC9-5", "ST08-T1", "PA9-2")
def test_rows_4_and_5_record_an_unknown_producer_and_no_attribution() -> None:
    for kind in ("outside", "reviewer"):
        result = challenge(kind)
        assert {r.row for r in result.classification.differences} == {a.Row.DC9_8}
        assert all(
            r.row not in {a.Row.DC9_3, a.Row.DC9_5} for r in result.classification.differences
        )


@pytest.mark.traces("AT9-1c", "ST08-D3")
def test_a_defeated_bracket_yields_zero_activation_effects() -> None:
    challenge("mixed")


@pytest.mark.traces("DC9-6", "DC9-7", "DC9-8", "DC9-11", "DC9-12", "ST08-D4")
def test_defeated_bracket_routing_follows_dc9_7_then_dc9_6_then_dc9_8() -> None:
    result = challenge("mixed")
    for item in result.classification.differences:
        expected = {"index": a.Row.DC9_6, "tree": a.Row.DC9_8}.get(
            item.difference.subject, a.Row.DC9_7
        )
        assert item.row == expected
    assert {r.row for r in result.classification.differences} == {
        a.Row.DC9_6,
        a.Row.DC9_7,
        a.Row.DC9_8,
    }


@pytest.mark.traces("AP04-I35", "DC9-16")
def test_late_residue_is_never_recorded_as_a_violation_of_the_adopted_activation() -> None:
    for kind in ("outside", "reviewer", "mixed"):
        challenge(kind, late=True)


@pytest.mark.traces("AP04-I22", "PA9-2")
def test_repository_observation_writes_no_case_b_record() -> None:
    for kind in ("outside", "reviewer", "mixed"):
        challenge(kind)
        challenge(kind, late=True)


@pytest.mark.traces("PA9-1", "AT9-1a", "ST08-N1")
def test_no_record_field_role_or_interval_names_a_producer() -> None:
    for kind in ("outside", "reviewer", "opening", "history"):
        challenge(kind)


@pytest.mark.traces("AP03-I28", "DC9-13", "PA9-2")
def test_ap03_i28_established_violation_antecedent_is_unreachable_on_repository_observation() -> (
    None
):
    """P => C and read-only excludes P: neither nonempty challenge can give P and not C."""
    test_rows_4_and_5_record_an_unknown_producer_and_no_attribution()
    from test_ga39_st08_brackets_and_attribution import (
        test_running_quiescent_subject_can_take_its_own_closing_bracket,
    )

    test_running_quiescent_subject_can_take_its_own_closing_bracket()


@pytest.mark.traces("AP04-I35")
def test_ap04_i35_late_established_violation_antecedent_is_unreachable_on_repository_observation() -> (  # noqa: E501
    None
):
    """Timing does not change P => C or the read-only exclusion of P."""
    test_late_residue_is_never_recorded_as_a_violation_of_the_adopted_activation()
    from test_ga39_st08_brackets_and_attribution import (
        test_running_quiescent_subject_can_take_its_own_closing_bracket,
    )

    test_running_quiescent_subject_can_take_its_own_closing_bracket()


@pytest.mark.traces("AP04-I22")
def test_ap04_i22_no_st08_written_case_b_record_exists_on_repository_observation() -> None:
    """P => C excludes an ST-08-written Case B; marker fixtures are not positive witnesses."""
    test_repository_observation_writes_no_case_b_record()
    from test_ga39_st08_brackets_and_attribution import (
        test_running_quiescent_subject_can_take_its_own_closing_bracket,
    )

    test_running_quiescent_subject_can_take_its_own_closing_bracket()


@pytest.mark.traces("AT9-1d", "ST08-N6", "ST08-B1")
def test_external_in_boundary_write_is_indistinguishable() -> None:
    signatures = []
    for alleged_actor in ("subject", "external"):
        # Actor labels stay in the harness; both actors supply identical observations.
        with w.world() as s:
            subject, opening = w.begin(s)
            s.repo.write("src/new", b"same bytes")
            result = w.finish(s, subject, opening)
            assert isinstance(result, a.Assessed), alleged_actor
            assert result.effects and not result.mutations
            signatures.append(
                (tuple(e.observed_state for e in result.effects), result.classification.defeats)
            )
    assert signatures[0] == signatures[1]


@pytest.mark.traces("DC9-1", "IX-1", "IX-1a", "AT9-9", "DC9-15", "OB9-15")
def test_unchanged_dirty_and_legacy_entry_state_is_not_delta_or_drift() -> None:
    with w.world(dirty=True) as s:
        subject, opening = w.begin(s)
        snapshot = x.snapshot(s.repo.path)
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        assert result.classification.differences == ()
        assert any(
            b".coord/legacy".hex() in e
            for e, row in result.classification.unchanged
            if row == a.Row.DC9_1
        )
        assert not result.effects and not result.mutations
        assert x.snapshot(s.repo.path) == snapshot


@pytest.mark.supports("OB9-16", "DC9-9")
def test_residue_records_affected_envelopes_without_taking_any_edge() -> None:
    result = challenge("outside")
    assert all(len(m.affected_envelopes) == 1 for m in result.mutations)


@pytest.mark.traces("AP03-I11", "ST-5", "DC9-12")
def test_a_new_context_does_not_reclassify_the_old_context() -> None:
    from gpauto import observation

    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("outside", b"old context residue")
        assert isinstance(w.finish(s, subject, opening), a.Assessed)
        old = tuple(r.model_dump_json() for r in x.stored(s.store, UnaccountedMutation))
        epoch = x.epoch_at_s1(s.store, s.repo, tag="second")
        fixed = observation.fix_entry_boundary(s.store, epoch.root)
        assert isinstance(fixed, observation.Fixed)
        second = w.World(s.store, s.repo, epoch, fixed, fixed.entry)
        subject2, opening2 = w.begin(second)
        result = w.finish(second, subject2, opening2)
        assert isinstance(result, a.Assessed)
        assert result.classification.differences == ()
        assert not result.mutations and not result.effects
        assert tuple(r.model_dump_json() for r in x.stored(s.store, UnaccountedMutation)) == old
