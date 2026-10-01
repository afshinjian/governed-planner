"""Design basis: ST-08 plan §8/§11; Class A restart, atomicity and per-mutant evidence."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import mutation
import st07_world as x
import st08_world as w
from gpauto import attribution as a
from gpauto import derivations as dv
from gpauto import observation
from gpauto.absence import NotObserved
from gpauto.coordination_records import (
    ActivationEffectRecord,
    ConformanceDetermination,
    EnvelopeViolationRecord,
)
from gpauto.identity import UnaccountedMutationId
from gpauto.minting import mint_value
from gpauto.repository import ClassificationContext, UnaccountedMutation
from gpauto.store import CoordinationStore, open_store
from test_ga23_st04_mutation import _keyed_accesses, _predicates

GPAUTO_STAGE = "GP-AUTO-ST-08"


@pytest.mark.traces("ST08-R1", "AT9-4", "OB9-15")
def test_a_second_assessment_reads_nothing_and_returns_the_recorded_determinations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("src/new", b"durable")
        result = w.finish(s, subject, opening)
        assert isinstance(result, a.Assessed)
        state = x.store_state(s.store)

        def forbidden(*args: object, **kwargs: object) -> None:
            pytest.fail("replay must not observe or mint")

        monkeypatch.setattr(observation, "observe", forbidden)
        monkeypatch.setattr(a, "mint_value", forbidden)
        replay = a.assess_activation(s.store, subject.identity, None, None)
        assert isinstance(replay, a.Replayed)
        assert set(replay.determinations) == set(result.determinations)
        assert x.store_state(s.store) == state


@pytest.mark.traces("ST08-R1", "AT9-4", "DC9-17")
def test_fresh_process_replays_and_recomputes_facts() -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        s.repo.write("src/new", b"durable")
        assert isinstance(w.finish(s, subject, opening), a.Assessed)
        before = a.completion_facts(a.read_records(s.store), subject.identity)
        for seed in ("7", "91"):
            done = subprocess.run(
                [sys.executable, str(Path(w.__file__)), str(s.store.path), subject.identity.value],
                env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True,
                text=True,
                check=True,
            )
            assert done.stdout.splitlines() == ["Replayed", str(before)], done.stderr
        reopened = open_store(s.store.path)
        try:
            assert a.completion_facts(a.read_records(reopened), subject.identity) == before
            assert a.classify_recorded(
                a.read_records(reopened), s.epoch.root
            ) == a.classify_recorded(a.read_records(s.store), s.epoch.root)
        finally:
            reopened.close()


@pytest.mark.traces("ST08-R1", "PA9-1", "PA9-3")
@pytest.mark.parametrize("portion", [(), ("",), (" \t\n",)])
def test_persisted_unknown_producer_without_a_portion_prefix_is_indeterminate(
    portion: tuple[str, ...],
) -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        assessed = w.finish(s, subject, opening)
        assert isinstance(assessed, a.Assessed)
        mutation_record = UnaccountedMutation(
            identity=UnaccountedMutationId(value=mint_value()),
            context=ClassificationContext(
                authorization=s.epoch.root,
                entry_boundary=s.boundary.boundary.boundary.identity,
            ),
            observed_state=portion,
            unexplained_portion=portion,
            affected_envelopes=(subject.envelope,),
            producing_activation=NotObserved(),
        )
        s.store.create(mutation_record)
        before = x.store_state(s.store)
        s.store.close()
        outcomes = []
        for _ in range(2):
            reopened = open_store(s.store.path)
            try:
                records = a.read_records(reopened)
                assert not records.unreadable and not records.unstable
                assert mutation_record in records.records
                result = a.classify_recorded(records, s.epoch.root)
                assert isinstance(result, dv.Indeterminate)
                assert result.cause == dv.IndeterminacyCause.INCONSISTENT_RECORDS
                outcomes.append(result)
                replay = a.assess_activation(reopened, subject.identity, None, None)
                assert isinstance(replay, a.Replayed)
                assert set(replay.determinations) == set(assessed.determinations)
                assert a.classify_recorded(a.read_records(reopened), s.epoch.root) == result
                persisted = x.stored(reopened, UnaccountedMutation)
                assert persisted == [mutation_record]
                assert isinstance(persisted[0].producing_activation, NotObserved)
                assert not x.stored(reopened, EnvelopeViolationRecord)
                assert x.store_state(reopened) == before
            finally:
                reopened.close()
        assert outcomes[0] == outcomes[1]


@pytest.mark.traces("ST08-R1", "ST08-D1")
def test_the_determinations_are_one_unit(monkeypatch: pytest.MonkeyPatch) -> None:
    with w.world() as s:
        subject, opening = w.begin(s)
        assert isinstance(opening, a.Bracket)
        s.repo.write("src/new", b"crash")
        s.quiesce(subject)
        closing = a.take_closing_bracket(s.store, subject.identity)
        assert isinstance(closing, a.Bracket)
        before = x.store_state(s.store)
        original = CoordinationStore._insert

        def crash(self: CoordinationStore, layout: Any, record: Any) -> None:
            if isinstance(record, ConformanceDetermination):
                raise RuntimeError("Class A crash inside assessment unit")
            original(self, layout, record)

        monkeypatch.setattr(CoordinationStore, "_insert", crash)
        with pytest.raises(RuntimeError):
            a.assess_activation(s.store, subject.identity, opening, closing)
        assert x.store_state(s.store) == before
        assert not x.stored(s.store, ActivationEffectRecord)
        monkeypatch.setattr(CoordinationStore, "_insert", original)
        assert isinstance(
            a.assess_activation(s.store, subject.identity, opening, closing), a.Assessed
        )


@pytest.mark.traces("ST08-R1")
def test_partial_determinations_and_lost_brackets_fail_closed() -> None:
    from gpauto.coordination_identity import ConformanceDeterminationId
    from gpauto.coordination_records import ResidueDetermination
    from gpauto.minting import mint_value
    from st03_world import ABSENT

    with w.world() as s:
        subject, _ = w.begin(s)
        lost = a.assess_activation(s.store, subject.identity, None, None)
        assert isinstance(lost, a.NotAssessed)
        assert lost.cause == a.AssessmentCause.OPENING_BRACKET_MISSING
        s.store.create(
            ConformanceDetermination(
                identity=ConformanceDeterminationId(
                    activation=subject.identity, discriminator=mint_value()
                ),
                determination=ResidueDetermination(mutations=ABSENT),
            )
        )
        partial = a.assess_activation(s.store, subject.identity, None, None)
        assert isinstance(partial, a.NotAssessed)
        assert partial.cause == a.AssessmentCause.INCONSISTENT_RECORDS


@pytest.mark.traces("ST08-M1", "ST08-M2", "ST08-M3", "AP03-I28", "AP04-I35", "AP04-I22")
@pytest.mark.parametrize(
    "mutant", mutation.ST08_MUTANTS, ids=[m.identifier for m in mutation.ST08_MUTANTS]
)
def test_each_st08_mutant_is_killed_by_its_named_test(mutant: mutation.LineMutant) -> None:
    assert mutation.run(mutant) == mutation.KILLED, mutant.identifier
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier
    from test_ga41_st08_stratification_and_facts import (
        test_a_lawful_in_boundary_write_never_self_invalidates,
    )

    test_a_lawful_in_boundary_write_never_self_invalidates()


@pytest.mark.traces("ST08-M1", "ST08-M2", "ST08-M3")
def test_every_st08_guard_predicate_and_keyed_access_is_inventoried() -> None:
    source = mutation.source_path(a).read_text("utf-8")
    lines = source.splitlines()
    for line in lines:
        if "# guard:" in line:
            assert any(m.original in line for m in mutation.ST08_MUTANTS), line
    assert {g for g, guard in mutation.GUARDS.items() if guard.module is a} == set(
        mutation.ST08_GUARDS
    )
    for mutant in mutation.ST08_MUTANTS:
        mutation.mutated_source(mutant)
    assert len({m.identifier for m in mutation.ST08_MUTANTS}) == len(mutation.ST08_MUTANTS)
    predicates = _predicates(ast.parse(source))
    untagged = {(f, text) for f, line, text in predicates if "# guard:" not in lines[line - 1]}
    assert untagged == set(mutation.ST08_UNMUTATED_PREDICATES)
    assert all(reason.strip() for reason in mutation.ST08_UNMUTATED_PREDICATES.values())
    counts: dict[tuple[str, str], int] = {}
    for access in _keyed_accesses(ast.parse(source)):
        counts[access] = counts.get(access, 0) + 1
    assert set(counts) == set(mutation.ST08_KEYED_ACCESSES)
    for key, (count, classification, reason) in mutation.ST08_KEYED_ACCESSES.items():
        assert counts[key] == count and reason.strip()
        assert classification in (
            mutation.NON_SELECTION,
            mutation.SINGLE_LAWFUL_VALUE,
            mutation.FAIL_CLOSED,
        )
