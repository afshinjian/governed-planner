"""Design basis: ST-09 §8.2, §11.3; Class A subprocess restart and named mutants."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import mutation
import st09_world as w
from gpauto import finding_lifecycle as f
from gpauto.absence import KnownAbsent, Present
from gpauto.coordination_records import CycleOccurrence, M2PositionEntry, PostFreezeCandidateItem
from gpauto.coordination_vocabulary import M2Edge, M2Position
from gpauto.identity import WorkerActivationId
from gpauto.store import open_store
from gpauto.vocabulary import Role
from st04_world import rendered

GPAUTO_STAGE = "GP-AUTO-ST-09"


def _child(
    x: w.LifecycleWorld, kind: str, subject: str, window: str, seed: str = "7"
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(Path(w.__file__)),
            str(x.store.path),
            kind,
            x.root.value,
            subject,
            window,
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
    )


def _prepared(x: w.LifecycleWorld, kind: str) -> str:
    if kind == "freeze":
        return x.discovery().identity.value
    if kind == "b6a":
        frozen = f.freeze(x.store, x.discovery().identity, w.B5)
        assert isinstance(frozen, f.Frozen)
        return frozen.entry.identity.discriminator
    frozen_set, occurrence = w.freeze_enter(x)
    if kind == "candidates":
        return x.activation(
            Role.REMEDIATOR,
            (PostFreezeCandidateItem(), PostFreezeCandidateItem()),
            cycle=occurrence,
        ).identity.value
    closer = w.close_cycle(x, frozen_set, occurrence, persist=kind != "assessments")
    return closer.identity.value if kind == "assessments" else x.head.identity.discriminator


@pytest.mark.traces("ST09-R1", "ST09-R2", "FZ-21", "AP05-I13", "CY-12")
@pytest.mark.parametrize("kind", ("freeze", "b6a", "b15", "assessments", "candidates"))
@pytest.mark.parametrize("window", ("before", "inside", "after"))
def test_atomic_units_survive_each_class_a_crash_window(kind: str, window: str) -> None:
    with w.world() as x:
        subject = _prepared(x, kind)
        before = frozenset(x.snapshot().records)
        child = _child(x, kind, subject, window)
        assert child.returncode == {"before": 91, "inside": 92, "after": 93}[window], child.stderr
        with open_store(x.store.path) as reopened:
            state = frozenset(f.read_lifecycle_records(reopened).records)
            if window != "after":
                assert state == before
            else:
                assert before < state
            first = w.act(reopened, kind, x.root, subject)
            expected_type = {
                "freeze": f.FreezeReplayed if window == "after" else f.Frozen,
                "b6a": f.OccurrenceReplayed if window == "after" else f.OccurrenceEstablished,
                "b15": f.OccurrenceReplayed if window == "after" else f.OccurrenceEstablished,
                "assessments": f.AssessmentsReplayed
                if window == "after"
                else f.AssessmentsRecorded,
                "candidates": f.CandidatesReplayed if window == "after" else f.CandidatesRecorded,
            }[kind]
            assert isinstance(first, expected_type), first
            replay = w.act(reopened, kind, x.root, subject)
            expected = [rendered(replay), w.replay_state(reopened, x.root)]
        for seed in ("7", "91"):
            child = _child(x, kind, subject, "replay", seed)
            assert child.returncode == 0, child.stderr
            assert child.stdout.splitlines() == expected


@pytest.mark.traces("ST09-R2", "CY-11", "CY-12", "BC-10")
def test_an_occurrence_replay_requires_the_complete_effect() -> None:
    for kind in ("b6a", "b15"):
        with w.world() as x:
            subject = _prepared(x, kind)
            first = w.act(x.store, kind, x.root, subject)
            assert isinstance(first, f.OccurrenceEstablished)
            x.refresh()
            records = x.snapshot()
            changes = (
                {
                    "predecessor_closure_activation": Present(
                        value=WorkerActivationId(value="different")
                    )
                },
                {"establishing_edge": M2Edge.B15 if kind == "b6a" else M2Edge.B6a},
                {"activation": KnownAbsent(basis="different absence")},
                {"envelope": KnownAbsent(basis="different absence")},
            )
            corrupt = [
                replace(
                    records,
                    records=tuple(
                        r.model_copy(update=change) if r == first.occurrence else r
                        for r in records.records
                    ),
                )
                for change in changes
            ]
            corrupt += [
                replace(records, records=tuple(r for r in records.records if r != first.entry)),
                replace(
                    records,
                    records=tuple(
                        r.model_copy(update={"cycle_occurrence": w.ABSENT})
                        if r == first.entry
                        else r
                        for r in records.records
                    ),
                ),
            ]
            for bad in corrupt:
                with pytest.MonkeyPatch.context() as patch:
                    patch.setattr(f, "read_lifecycle_records", lambda store, bad=bad: bad)
                    patch.setattr(f, "mint_value", lambda: pytest.fail("corrupt replay minted"))
                    patch.setattr(
                        x.store, "create_unit", lambda rows: pytest.fail("corrupt replay wrote")
                    )
                    result = w.act(x.store, kind, x.root, subject)
                assert isinstance(result, f.NotEntered | f.NotRouted)
                assert result.cause == f.LifecycleCause.CONFLICT
            for record_class in (M2PositionEntry, CycleOccurrence):
                bad = replace(records, unreadable=frozenset({record_class}))
                with pytest.MonkeyPatch.context() as patch:
                    patch.setattr(f, "read_lifecycle_records", lambda store, bad=bad: bad)
                    result = w.act(x.store, kind, x.root, subject)
                assert isinstance(result, f.NotEntered | f.NotRouted)
                assert result.cause == f.LifecycleCause.UNREADABLE_RECORDS
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(f, "mint_value", lambda: pytest.fail("lawful replay minted"))
                patch.setattr(
                    x.store, "create_unit", lambda rows: pytest.fail("lawful replay wrote")
                )
                assert w.act(x.store, kind, x.root, subject) == f.OccurrenceReplayed(
                    first.occurrence, first.entry
                )
            assert frozenset(x.snapshot().records) == frozenset(records.records)


@pytest.mark.traces("ST09-M1", "ST09-M2", "ST09-M3", "ST09-M4", "ST09-M5", "ST09-M6", "ST09-M7")
@pytest.mark.parametrize(
    "mutant", mutation.ST09_MUTANTS, ids=[m.identifier for m in mutation.ST09_MUTANTS]
)
def test_each_named_mutant_is_killed_and_its_control_survives(
    mutant: mutation.LineMutant | mutation.SchemaMutant,
) -> None:
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier
    assert mutation.run(mutant) == mutation.KILLED, mutant.identifier
    _spared_lawful_control(mutant)


@pytest.mark.traces("ST09-R2", "BC-10")
def test_write_refused_occurrence_rereads_its_named_predecessor() -> None:
    from gpauto.store import WriteRefused

    for kind in ("b6a", "b15"):
        with w.world() as x:
            subject = _prepared(x, kind)
            before = x.snapshot()
            committed = w.act(x.store, kind, x.root, subject)
            assert isinstance(committed, f.OccurrenceEstablished)
            after = x.snapshot()
            bad = replace(
                after,
                records=tuple(
                    r
                    for r in after.records
                    if not (
                        isinstance(r, M2PositionEntry)
                        and r.identity == committed.occurrence.predecessor_entry
                    )
                ),
            )
            reads = iter((before, bad))

            def refuse(*args: object) -> None:
                raise WriteRefused("Class A competing commit")

            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(f, "read_lifecycle_records", lambda store, reads=reads: next(reads))
                patch.setattr(x.store, "create_unit", refuse)
                result = w.act(x.store, kind, x.root, subject)
            assert isinstance(result, f.NotEntered | f.NotRouted)
            assert result.cause == f.LifecycleCause.CONFLICT


def _conflicting_entry(
    first: f.OccurrenceEstablished, corruption: str, other_predecessor: M2PositionEntry
) -> M2PositionEntry:
    if corruption == "competing-edge":
        return first.entry.model_copy(
            update={
                "identity": first.entry.identity.model_copy(update={"discriminator": "competing"}),
                "edge": M2Edge.B6b if first.entry.edge == M2Edge.B6a else M2Edge.B8,
                "state": M2Position.S8_GATE_REACHED,
                "cycle_occurrence": w.ABSENT,
            }
        )
    return first.entry.model_copy(
        update={
            "identity": first.entry.identity.model_copy(update={"discriminator": "duplicate"}),
            "predecessor": Present(value=other_predecessor.identity),
        }
    )


@pytest.mark.traces("ST09-R2", "CY-11", "CY-12", "BC-10")
def test_conflicting_occurrence_entries_refuse_replay() -> None:
    for kind in ("b6a", "b15"):
        for corruption in ("competing-edge", "duplicate-reference"):
            with w.world() as x:
                subject = _prepared(x, kind)
                first = w.act(x.store, kind, x.root, subject)
                assert isinstance(first, f.OccurrenceEstablished)
                x.refresh()
                later = x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, first.occurrence)
                extra = _conflicting_entry(first, corruption, later)
                # Duplicate references are persistable. Competing successors violate the
                # store's unique key, so supply that corruption as a Class A read snapshot.
                if corruption == "duplicate-reference":
                    x.store.create(extra)
                records = x.snapshot()
                if corruption == "competing-edge":
                    records = replace(records, records=records.records + (extra,))
                before = frozenset(x.snapshot().records)
                expected = (
                    f.NotEntered(f.LifecycleCause.CONFLICT)
                    if kind == "b6a"
                    else f.NotRouted(f.LifecycleCause.CONFLICT)
                )
                with open_store(x.store.path) as reopened:
                    with pytest.MonkeyPatch.context() as patch:
                        if corruption == "competing-edge":
                            patch.setattr(
                                f, "read_lifecycle_records", lambda store, records=records: records
                            )
                        patch.setattr(f, "mint_value", lambda: pytest.fail("conflict minted"))
                        patch.setattr(
                            reopened, "create_unit", lambda rows: pytest.fail("conflict wrote")
                        )
                        assert w.act(reopened, kind, x.root, subject) == expected
                if corruption == "duplicate-reference":
                    child = _child(x, kind, subject, "replay")
                    assert child.returncode == 0, child.stderr
                    assert child.stdout.splitlines()[0] == rendered(expected)
                assert frozenset(x.snapshot().records) == before


@pytest.mark.traces("ST09-R2", "BC-10")
@pytest.mark.parametrize("kind", ("b6a", "b15"))
@pytest.mark.parametrize("corruption", ("competing-edge", "duplicate-reference"))
def test_write_refused_occurrence_reconciles_conflicting_entries(
    kind: str, corruption: str
) -> None:
    from gpauto.store import WriteRefused

    with w.world() as x:
        subject = _prepared(x, kind)
        before = x.snapshot()
        committed = w.act(x.store, kind, x.root, subject)
        assert isinstance(committed, f.OccurrenceEstablished)
        x.refresh()
        later = x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, committed.occurrence)
        after = x.snapshot()
        after = replace(
            after, records=after.records + (_conflicting_entry(committed, corruption, later),)
        )
        persisted = frozenset(x.snapshot().records)
        reads = iter((before, after))

        def refuse(*args: object) -> None:
            raise WriteRefused("Class A conflicting commit")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(f, "read_lifecycle_records", lambda store: next(reads))
            patch.setattr(x.store, "create_unit", refuse)
            result = w.act(x.store, kind, x.root, subject)
        expected = (
            f.NotEntered(f.LifecycleCause.CONFLICT)
            if kind == "b6a"
            else f.NotRouted(f.LifecycleCause.CONFLICT)
        )
        assert result == expected
        assert frozenset(x.snapshot().records) == persisted


@pytest.mark.traces("ST09-R2", "BC-10", "CB-1")
@pytest.mark.parametrize("kind", ("b6a", "b15"))
def test_later_positions_referencing_an_occurrence_allow_restart_replay(kind: str) -> None:
    with w.world() as x:
        subject = _prepared(x, kind)
        first = w.act(x.store, kind, x.root, subject)
        assert isinstance(first, f.OccurrenceEstablished)
        x.refresh()
        x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, first.occurrence)
        x.advance(M2Position.S9_EPOCH_HALTED, M2Edge.B9, first.occurrence)
        before = frozenset(x.snapshot().records)
        expected = f.OccurrenceReplayed(first.occurrence, first.entry)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(f, "mint_value", lambda: pytest.fail("replay minted"))
            patch.setattr(x.store, "create_unit", lambda rows: pytest.fail("replay wrote"))
            assert w.act(x.store, kind, x.root, subject) == expected
        child = _child(x, kind, subject, "replay")
        assert child.returncode == 0, child.stderr
        assert child.stdout.splitlines() == [rendered(expected), w.replay_state(x.store, x.root)]
        assert f.b15_budget(x.snapshot(), x.root) == (
            f.BudgetAvailable(0) if kind == "b6a" else f.BudgetExhausted(1)
        )
        assert frozenset(x.snapshot().records) == before


def _spared_lawful_control(mutant: mutation.LineMutant | mutation.SchemaMutant) -> None:
    """The mutation stays enabled while a separate, applicable lawful stimulus runs."""
    name = mutant.identifier.removeprefix("ST09-")
    with w.world() as x:
        if name in {"LO-8", "LO-9"}:
            with mutation.st09_substituted(mutant):
                for kind in ("b6a", "b15"):
                    test_later_positions_referencing_an_occurrence_allow_restart_replay(kind)
            return
        if name == "FA-8":
            from test_ga44_st09_freeze import (
                test_one_completed_discovery_allows_uncompleted_or_unrelated_attempts,
            )

            with mutation.st09_substituted(mutant):
                for other in ("closed-unadopted", "different-root"):
                    test_one_completed_discovery_allows_uncompleted_or_unrelated_attempts(other)
            return
        if name == "MI-3":
            original_set = x.built.handles["frozen"]
            with mutation.st09_substituted(mutant):
                assert dict(f.FrozenFindingSet(**dict(original_set))) == dict(original_set)  # type: ignore[attr-defined]
            return
        if name == "LO-1":
            subject = x.discovery(1).identity.value
            with mutation.st09_substituted(mutant):
                assert isinstance(w.act(x.store, "freeze", x.root, subject), f.Frozen)
            return
        if name.startswith("FA-") or name in {"MI-1", "MI-2", "MI-4"}:
            run = x.discovery(1)
            freeze_result = f.freeze(x.store, run.identity, w.B5)
            assert isinstance(freeze_result, f.Frozen)
            with mutation.st09_substituted(mutant):
                assert f.freeze(x.store, run.identity, w.B5) == f.FreezeReplayed(
                    freeze_result.frozen_set, freeze_result.entry
                )
            return
        if name in {"LO-2", "LO-5", "LO-6", "LO-7", "LO-3", "LO-4", "PC-1"}:
            kind = {
                "LO-2": "b15",
                "LO-5": "b6a",
                "LO-6": "b15",
                "LO-7": "b6a",
                "LO-3": "assessments",
                "LO-4": "candidates",
                "PC-1": "candidates",
            }[name]
            subject = _prepared(x, kind)
            if name == "LO-7":
                committed = w.act(x.store, kind, x.root, subject)
                assert isinstance(committed, f.OccurrenceEstablished)
                with mutation.st09_substituted(mutant):
                    assert w.act(x.store, kind, x.root, subject) == f.OccurrenceReplayed(
                        committed.occurrence, committed.entry
                    )
            else:
                with mutation.st09_substituted(mutant):
                    assert isinstance(
                        w.act(x.store, kind, x.root, subject),
                        f.OccurrenceEstablished | f.AssessmentsRecorded | f.CandidatesRecorded,
                    )
            return
        frozen, occurrence = w.freeze_enter(x)
        if name == "PC-2":
            run = x.activation(Role.REMEDIATOR, cycle=occurrence)
            with mutation.st09_substituted(mutant):
                assert f.record_post_freeze_candidates(x.store, run.identity) == f.NothingToRecord()
            return
        if name in {"OA-1", "OA-2", "OC-2", "OC-3", "OC-4"}:
            from gpauto.review import RemediationObligation

            obligations = tuple(o.identity for o in w.rows(x.store, RemediationObligation))
            run = x.activation(
                Role.REMEDIATOR, cycle=occurrence, dispositions=obligations, obligations=obligations
            )
            with mutation.st09_substituted(mutant):
                assert f.remediation_admissibility(x.snapshot(), run.identity) == f.Admissible()
                assert f.admitted_obligations_fact(
                    x.snapshot(), run.envelope, run.input_package
                ) == {"ADMITTED_OBLIGATIONS_AGREE": "EQUAL"}
            return
        if name == "SS-1":
            before = f.admitted_set(x.snapshot(), occurrence.identity)
            w.close_cycle(x, frozen, occurrence, (False, False))
            with mutation.st09_substituted(mutant):
                assert f.admitted_set(x.snapshot(), occurrence.identity) == before
            return
        if name == "OC-5":
            w.close_cycle(x, frozen, occurrence, (True, None))
            with mutation.st09_substituted(mutant):
                assert isinstance(
                    f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE), f.GateDue
                )
            return
        w.close_cycle(x, frozen, occurrence)
        with mutation.st09_substituted(mutant):
            assert isinstance(
                f.route_after_closure(x.store, x.root, x.head.identity, w.CYCLE),
                f.OccurrenceEstablished,
            )


def _st09_predicates(source: str) -> list[tuple[str, int, str]]:
    """Include conditionals, comprehension filters, and boolean value expressions."""
    tree = ast.parse(source)
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    found = set()
    for node in ast.walk(tree):
        tests: list[ast.expr] = []
        if isinstance(node, ast.If | ast.IfExp | ast.While):
            tests.append(node.test)
        elif isinstance(node, ast.comprehension):
            tests.extend(node.ifs)
        elif isinstance(node, ast.Compare | ast.BoolOp) or (
            isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
        ):
            tests.append(node)
        for test in tests:
            enclosing = [fn for fn in functions if fn.lineno <= test.lineno <= (fn.end_lineno or 0)]
            if enclosing:
                fn = max(enclosing, key=lambda f: f.lineno)
                found.add((fn.name, test.lineno, ast.unparse(test)))
    return sorted(found)


@pytest.mark.traces("ST09-M1", "ST09-M2", "ST09-M3", "ST09-M4", "ST09-M5", "ST09-M6", "ST09-M7")
def test_every_predicate_and_keyed_access_is_guarded_or_has_an_explicit_reason() -> None:
    from collections import Counter

    from test_ga23_st04_mutation import _keyed_accesses

    source = mutation.source_path(f).read_text()
    lines = source.splitlines()
    predicates = _st09_predicates(source)
    untagged = {(fn, text) for fn, line, text in predicates if "# guard:" not in lines[line - 1]}
    assert untagged == set(mutation.ST09_UNMUTATED_PREDICATES)
    assert all(reason.strip() for reason in mutation.ST09_UNMUTATED_PREDICATES.values())
    actual = Counter(_keyed_accesses(ast.parse(source)))
    assert actual == {key: value[0] for key, value in mutation.ST09_KEYED_ACCESSES.items()}
    assert all(reason.strip() for _, reason in mutation.ST09_KEYED_ACCESSES.values())
    assert set(mutation.ST09_GUARDS) == {
        g for g, info in mutation.GUARDS.items() if info.module is f
    }
    tags = mutation.guard_tags()
    for guard in mutation.ST09_GUARDS:
        assert tags[guard] and all(p.startswith("finding_lifecycle.py:") for p in tags[guard])
        assert any(m.guard == guard for m in mutation.ST09_MUTANTS)
    assert len(mutation.ST09_MUTANTS) == 66
    for mutant in mutation.ST09_MUTANTS:
        assert mutant.killer.startswith("tests_gpauto/test_ga4")
        if isinstance(mutant, mutation.LineMutant):
            assert mutation.mutated_source(mutant) != mutation.mutated_source(mutant, control=True)
