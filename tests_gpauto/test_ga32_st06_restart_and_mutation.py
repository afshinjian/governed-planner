"""`GP-AUTO-ST-06`: restart and reconstruction (Class A), and mutation per guard and mutant.

Design basis: AP-11 §16 `GP-AUTO-ST-06` (Restart/persistence evidence: *"Resolution outcome
and exclusions durable; resolution occurs once per epoch with no re-resolution path"*;
Mutation: *"Uniqueness guard; eligibility completeness guard; bounds-≤-ceiling;
equivalent-or-narrower; role and write-mode checks"*); AP-11 §8 (`MU11-1`…`MU11-7`), §11
(`FI11-1a` Class A); the frozen ST-06 clarification §18 (mutation), §19 (restart); AP-07
`MC-3`, `MC-15`, `MC-17`, `DV-14`.

Restart is Class A: the store is closed and re-opened at each window a crash could leave,
and the acts are re-run over what was durably recorded. Nothing is carried between the two
processes but the store file. Mutation is per guard and per mutant, each with its named
killer and a surviving control; no score is reported (`MU11-2a`).
"""

from __future__ import annotations

import ast
import dataclasses
from typing import Any

import pytest

import mutation
import st06_world as w
import traceability
from gpauto import authority
from gpauto.coordination_records import (
    AuthorityEnvelopeRecord,
    CandidateExclusionRecord,
    M1PositionEntry,
)
from gpauto.coordination_vocabulary import M1Edge, M2Position
from gpauto.state_machine_model import DERIVATION_TOTAL, TRUE
from gpauto.store import CoordinationStore, open_store
from gpauto.vocabulary import Role
from st03_world import fresh_store
from test_ga23_st04_mutation import _keyed_accesses, _predicates

GPAUTO_STAGE = "GP-AUTO-ST-06"

S = w.scope()
ST06 = mutation.ST06_MUTANTS
ST06_GUARDS = (
    "ga_root_uniqueness",
    "ga_eligibility_completeness",
    "ga_bounds_within_ceiling",
    "ga_equivalent_or_narrower",
    "ga_role_write_mode",
    "ga_envelope_validity",
)


def _of[R](store: CoordinationStore, kind: type[R]) -> list[R]:
    return [r for r in store.enumerate(kind) if isinstance(r, kind)]  # type: ignore[arg-type]


def _reopened(store: CoordinationStore) -> CoordinationStore:
    """The process ends; a new one opens the same file and holds nothing else."""
    store.close()
    return open_store(store.path)


# --- restart and reconstruction, Class A --------------------------------------------------


@pytest.mark.traces("ST06-R1", "M1-7")
def test_after_a1_a_restarted_process_completes_from_the_recorded_occurrence() -> None:
    """The window after `A1`: an open resolution is a complete stored state. A new process
    finds it by its anchor, mints nothing, and completes it from records alone."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a")])
        opened = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened)
        again = _reopened(store)
        try:
            found = authority.open_resolution(again, S.project, S.stage)
            assert found == authority.Opened(opened.resolution, replayed=True)
            done = authority.complete_resolution(again, opened.resolution)
            assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A2
        finally:
            again.close()


@pytest.mark.traces("ST06-R1", "ST06C-I07")
def test_after_the_exclusion_unit_a_restart_appends_nothing_and_completes() -> None:
    """The window after the exclusion unit: a restart recomputes the same exclusions, finds
    them recorded as the canonical prefix (`MC-3`), appends nothing, and completes."""
    with fresh_store() as store:
        w.supply(
            store,
            S,
            [
                w.record(S, "record-a"),
                w.record(S, "record-y", "x", owner_human_label_present=False),
                w.record(S, "record-z", "x", authorized_roles=()),
            ],
        )
        opened = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened)
        records = authority.read_authority_records(store)
        evaluation = authority.evaluate_resolution(records, opened.resolution)
        assert isinstance(evaluation, authority.ResolutionEvaluation)
        store.create_unit(authority._exclusion_chain(evaluation.exclusions))
        recorded = _of(store, CandidateExclusionRecord)
        again = _reopened(store)
        try:
            done = authority.complete_resolution(again, opened.resolution)
            assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A2
            assert _of(again, CandidateExclusionRecord) == recorded
        finally:
            again.close()


@pytest.mark.traces("ST06-R1", "M1-7")
def test_an_interrupted_completing_unit_leaves_nothing_and_a_rerun_completes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash inside the completing unit leaves nothing of it — no half-written refusal,
    no entry without its record — and a rerun completes the resolution exactly once."""
    with fresh_store() as store:
        w.supply(store, S, [])
        opened = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened)
        original = CoordinationStore._insert

        def crash(self: CoordinationStore, layout: Any, record: Any) -> None:
            if isinstance(record, M1PositionEntry) and record.edge == M1Edge.A3:
                raise RuntimeError("the process ends here")
            original(self, layout, record)

        monkeypatch.setattr(CoordinationStore, "_insert", crash)
        with pytest.raises(RuntimeError):
            authority.complete_resolution(store, opened.resolution)
        monkeypatch.setattr(CoordinationStore, "_insert", original)
        again = _reopened(store)
        try:
            assert [e.edge for e in _of(again, M1PositionEntry)] == [M1Edge.A1]
            assert authority.read_authority_records(again).derivable.records
            done = authority.complete_resolution(again, opened.resolution)
            assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A3
            replay = authority.complete_resolution(again, opened.resolution)
            assert isinstance(replay, authority.Resolved) and replay.replayed
            assert len(_of(again, M1PositionEntry)) == 2
        finally:
            again.close()


@pytest.mark.traces("ST06-R1", "ST06C-I03")
def test_after_c1_a_restart_finds_the_envelope_and_re_derives_the_same_bounds() -> None:
    """The window after `C1`: a new process finds the envelope by its `MC-15` key and mints
    nothing; re-deriving from `RC-12`, `RC-17` and `RC-26` gives the recorded bounds again,
    because nothing derived is stored and the derivation has no free input."""
    with fresh_store() as store:
        e = w.resolved_epoch(store, S)
        first = e.derive(Role.IMPLEMENTER, M2Position.S3_IMPLEMENTATION_ACTIVE)
        assert isinstance(first, authority.EnvelopeRecorded)
        again = _reopened(store)
        try:
            e.store = again
            replay = e.derive(Role.IMPLEMENTER, M2Position.S3_IMPLEMENTATION_ACTIVE)
            assert isinstance(replay, authority.EnvelopeRecorded) and replay.replayed
            assert replay.record == first.record
            records = authority.read_authority_records(again)
            facts = authority.envelope_facts(
                records, first.record.envelope, e.root, M2Position.S3_IMPLEMENTATION_ACTIVE
            )
            assert facts[DERIVATION_TOTAL.name] == TRUE
            assert len(_of(again, AuthorityEnvelopeRecord)) == 1
        finally:
            again.close()


@pytest.mark.traces("ST06-R1", "ST06-G1")
def test_nothing_derived_is_stored_and_no_derived_result_is_a_record() -> None:
    """`DV-14`: every result `authority.py` returns is a frozen dataclass, never a record
    model, and the store has no write operation that could accept one."""
    tree = ast.parse(mutation.source_path(authority).read_text(encoding="utf-8"))
    classes = [n.name for n in tree.body if isinstance(n, ast.ClassDef)]
    enums = {"NotDerivableReason", "Order"}
    for name in classes:
        cls = getattr(authority, name)
        if name in enums:
            continue
        assert dataclasses.is_dataclass(cls), name
        assert vars(cls)["__dataclass_params__"].frozen, name
    from gpauto import store_schema

    stored = set(store_schema.build_catalogue().by_record)
    assert not {getattr(authority, name) for name in classes} & stored


# --- mutation ------------------------------------------------------------------------------


@pytest.mark.traces("ST06-M1", "ST06-M2", "ST06-M3", "ST06-M4", "ST06-M5")
@pytest.mark.parametrize("mutant", ST06, ids=[m.identifier for m in ST06])
def test_each_st06_mutant_is_killed_by_its_named_test(mutant: mutation.LineMutant) -> None:
    """`MU11-7`: the mutant is detected by its named test, and its control is not."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST06-M1", "ST06-M2", "ST06-M3", "ST06-M4", "ST06-M5")
def test_every_guarded_line_carries_a_mutant_and_st06_adds_exactly_its_six_guards() -> None:
    """`MU11-3`, `MU11-2b`: each guard is fixed in `authority.py` where it is written; every
    tagged line carries at least one mutant and every mutant sits on exactly one tagged
    line; each guard names frozen guarantees that are rows of the inventory; each killer is
    an ST-06 test; and ST-06 adds these six guards and no other."""
    source = mutation.source_path(authority).read_text(encoding="utf-8")
    tagged = [line for line in source.splitlines() if "# guard:" in line]
    for line in tagged:
        assert [m for m in ST06 if m.original in line], line
    for mutant in ST06:
        (line,) = [line for line in tagged if mutant.original in line]
        assert f"# guard:{mutant.guard}" in line, mutant.identifier
        assert mutant.killer.split("::")[0] in (
            mutation.ST06_ELIGIBILITY,
            mutation.ST06_RESOLUTION,
            mutation.ST06_ENVELOPE,
        )
    assert len({m.identifier for m in ST06}) == len(ST06)
    owned = {g for g, guard in mutation.GUARDS.items() if guard.module is authority}
    assert owned == set(ST06_GUARDS)
    assert {m.guard for m in ST06} == set(ST06_GUARDS)
    inventory = set(traceability.inventory())
    for guard in ST06_GUARDS:
        assert set(mutation.GUARDS[guard].guarantees) <= inventory, guard
        tags = mutation.guard_tags()[guard]
        assert tags and all(t.startswith("authority.py:") for t in tags), guard


@pytest.mark.traces("ST06-M2", "ST06-M1")
def test_every_predicate_is_mutated_or_inventoried_with_its_reason() -> None:
    """The `ST04-IMPL-R02` lesson, applied here: every comprehension filter and `if` test in
    `authority.py` is on a guarded line — and so carries a mutant — or is listed, with the
    reason it carries none, in `ST06_UNMUTATED_PREDICATES`; nothing is both, nothing listed
    is stale, and every reason is stated."""
    source = mutation.source_path(authority).read_text(encoding="utf-8")
    lines = source.splitlines()
    predicates = _predicates(ast.parse(source))
    listed = mutation.ST06_UNMUTATED_PREDICATES
    tagged = {(f, text) for f, line, text in predicates if "# guard:" in lines[line - 1]}
    untagged = {(f, text) for f, _, text in predicates} - tagged
    assert untagged == set(listed), (untagged - set(listed), set(listed) - untagged)
    assert all(reason.strip() for reason in listed.values())


@pytest.mark.traces("ST06-M2", "ST06-M3")
def test_every_keyed_access_is_inventoried_with_its_count_class_and_reason() -> None:
    """Every subscript, `.get` or `.setdefault` in `authority.py` is listed with its count,
    its class and its reason; none is a keyed selection of a record (those are the tagged
    comprehension filters `RW-16`, `BC-02`, `BC-03`, `BC-19`)."""
    source = mutation.source_path(authority).read_text(encoding="utf-8")
    counted: dict[tuple[str, str], int] = {}
    for access in _keyed_accesses(ast.parse(source)):
        counted[access] = counted.get(access, 0) + 1
    listed = mutation.ST06_UNQUALIFIED_KEYED_ACCESSES
    assert set(counted) == set(listed), (set(counted) - set(listed), set(listed) - set(counted))
    for access, (count, classification, reason) in listed.items():
        assert counted[access] == count, access
        assert classification in (
            mutation.NON_SELECTION,
            mutation.SINGLE_LAWFUL_VALUE,
            mutation.FAIL_CLOSED,
        ), access
        assert reason.strip(), access
    keyed = {"RW-16-member-keyed-by-another-role", "BC-19-ceiling-member-keyed-as-implementer"}
    keyed |= {"BC-02-remediator-keyed-as-implementer", "BC-03-implementer-keyed-as-remediator"}
    assert keyed <= {m.identifier for m in ST06}
