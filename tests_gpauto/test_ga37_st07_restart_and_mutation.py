"""`GP-AUTO-ST-07`: restart (Class A) — the boundary is durable and never re-observed — and
mutation per guard and mutant.

Design basis: AP-11 §16 `GP-AUTO-ST-07` (Restart/persistence evidence: *"Boundary durable and
unrepeatable; restart never re-observes it"* `AV11-14`; Mutation: *"each coherence condition;
each defeat test; the once-per-root constraint; the non-mutating-mode guard"*); AP-11 §8
(`MU11-1`…`MU11-7`), §11 (`FI11-1a` Class A); AP-07 `WP-12`, `CW-2`; AP-09 `OB9-14`, `FR-8`;
`AP03-I08`; plan §11, §12.

Restart is Class A: the store is closed and re-opened, and a fresh interpreter under another
hash seed opens the same file. Nothing crosses the process boundary but the store — and the
repository, which has changed by then, and is not read. A crash inside the unit leaves no
torn half. Mutation is per guard and per mutant, each with its named killer and a surviving
control; no score is reported (`MU11-2a`).
"""

from __future__ import annotations

import ast
import dataclasses
import os
import subprocess
import sys
from typing import Any

import pytest

import mutation
import st07_world as x
import traceability
from gate_scope import REPOSITORY_ROOT
from gpauto import observation, store_schema
from gpauto.coordination_records import EntryStateBoundaryRecord, M2PositionEntry
from gpauto.coordination_vocabulary import M2Edge
from gpauto.observation import Fixed, Replayed
from gpauto.store import CoordinationStore, open_store
from st03_world import fresh_store
from test_ga23_st04_mutation import _keyed_accesses, _predicates

GPAUTO_STAGE = "GP-AUTO-ST-07"

ST07 = mutation.ST07_MUTANTS
ST07_GUARDS = (
    "ga_observation_read_only",
    "ga_observation_coherence",
    "ga_observation_defeat",
    "ga_entry_once_per_root",
)


def _reopened(store: CoordinationStore) -> CoordinationStore:
    """The process ends; a new one opens the same file and holds nothing else."""
    store.close()
    return open_store(store.path)


# --- restart and reconstruction, Class A --------------------------------------------------


@pytest.mark.traces("ST07-R1", "ST07-N8", "AP03-I08", "OB9-14", "RS7-4")
def test_restart_never_reobserves_even_after_the_tree_changed() -> None:
    """`AV11-14`, `FR-8`: after `B2`, a reopened store and two fresh interpreters under other
    hash seeds each find the one recorded boundary by its key and read nothing from the
    repository — which by then holds a new commit, a new branch position and new files."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        fixed = observation.fix_entry_boundary(store, epoch.root)
        assert isinstance(fixed, Fixed)
        repo.write("a.txt", b"after entry\n")
        repo.write("brand-new.txt", b"new\n")
        repo.git("add", "-A")
        repo.git("commit", "-q", "-m", "after entry")
        again = _reopened(store)
        try:
            reader = x.CountingReader()
            found = observation.fix_entry_boundary(again, epoch.root, reader)
            assert found == Replayed(fixed.boundary, fixed.entry)
            assert reader.calls == []
            path = again.path
        finally:
            again.close()
        for seed in ("0", "4242"):
            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "tests_gpauto" / "st07_world.py"),
                    str(path),
                    epoch.root.value,
                ],
                capture_output=True,
                text=True,
                cwd=REPOSITORY_ROOT,
                env={**os.environ, "PYTHONHASHSEED": seed},
                check=True,
            )
            identity = fixed.boundary.boundary.identity.value
            assert completed.stdout.split() == ["Replayed", identity, "0"], completed.stderr
        final = open_store(path)
        try:
            assert [b.boundary for b in x.stored(final, EntryStateBoundaryRecord)] == [
                fixed.boundary.boundary
            ]
        finally:
            final.close()


@pytest.mark.traces("ST07-R1", "RS7-1", "OB9-13")
def test_a_crash_inside_the_unit_leaves_nothing_and_a_rerun_fixes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`WP-12`, `CW-2`: a crash after the boundary row and before its `S2` entry leaves
    neither — no torn unit — and nothing of the observation became authoritative. A rerun
    is the first fixing, not a re-observation of a fixed boundary (§22 `I5`); after it, the
    boundary is fixed once."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        original = CoordinationStore._insert

        def crash(self: CoordinationStore, layout: Any, record: Any) -> None:
            if isinstance(record, M2PositionEntry) and record.edge == M2Edge.B2:
                raise RuntimeError("the process ends here")
            original(self, layout, record)

        monkeypatch.setattr(CoordinationStore, "_insert", crash)
        with pytest.raises(RuntimeError):
            observation.fix_entry_boundary(store, epoch.root)
        monkeypatch.setattr(CoordinationStore, "_insert", original)
        again = _reopened(store)
        try:
            assert not again.enumerate(EntryStateBoundaryRecord)
            assert [e.edge for e in x.stored(again, M2PositionEntry)] == [M2Edge.B1]
            fixed = observation.fix_entry_boundary(again, epoch.root)
            assert isinstance(fixed, Fixed)
            replay = observation.fix_entry_boundary(again, epoch.root)
            assert replay == Replayed(fixed.boundary, fixed.entry)
            assert len(again.enumerate(EntryStateBoundaryRecord)) == 1
        finally:
            again.close()


@pytest.mark.traces("ST07-R1", "ST07-G1")
def test_nothing_derived_is_stored_and_no_result_is_a_record() -> None:
    """`DV-14`: every result `observation.py` returns is a frozen dataclass, never a record
    model, and the store has no write operation that could accept one. The observation
    itself is transient: only the `RC-17` elements and the `S2` entry are ever written."""
    tree = ast.parse(mutation.source_path(observation).read_text(encoding="utf-8"))
    classes = [n.name for n in tree.body if isinstance(n, ast.ClassDef)]
    not_results = {"Kind", "ObservationCause", "NotFixedReason", "Reader", "FilesystemReader"}
    not_results |= {"_Malformed", "_Unsupported"}
    for name in classes:
        if name in not_results:
            continue
        cls = getattr(observation, name)
        assert dataclasses.is_dataclass(cls), name
        assert vars(cls)["__dataclass_params__"].frozen, name
    stored = set(store_schema.build_catalogue().by_record)
    assert not {getattr(observation, name) for name in classes} & stored


# --- mutation ------------------------------------------------------------------------------


@pytest.mark.traces("ST07-M1", "ST07-M2", "ST07-M3", "ST07-M4")
@pytest.mark.parametrize("mutant", ST07, ids=[m.identifier for m in ST07])
def test_each_st07_mutant_is_killed_by_its_named_test(mutant: mutation.LineMutant) -> None:
    """`MU11-7`: the mutant is detected by its named test, and its control is not."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST07-M1", "ST07-M2", "ST07-M3", "ST07-M4")
def test_every_guarded_line_carries_a_mutant_and_st07_adds_exactly_its_four_guards() -> None:
    """`MU11-3`, `MU11-2b`: each guard is fixed in `observation.py` where it is written; every
    tagged line carries at least one mutant and every mutant sits on exactly one tagged line;
    each guard names frozen guarantees that are rows of the inventory; each killer is an
    ST-07 test; and ST-07 adds these four guards and no other. The plan's `CO-1`, `CO-1b`,
    `CO-2`, `CO-3`, `DF-1`…`DF-8`, `WN-1`, `ON-1`…`ON-4`, `RO-1`…`RO-5` and `DC-1`…`DC-3`
    are all present."""
    source = mutation.source_path(observation).read_text(encoding="utf-8")
    tagged = [line for line in source.splitlines() if "# guard:" in line]
    for line in tagged:
        assert [m for m in ST07 if m.original in line], line
    for mutant in ST07:
        (line,) = [line for line in tagged if mutant.original in line]
        assert f"# guard:{mutant.guard}" in line, mutant.identifier
        assert mutant.killer.split("::")[0] in (
            mutation.ST07_SUBJECTS,
            mutation.ST07_COHERENCE,
            mutation.ST07_BOUNDARY,
            mutation.ST07_GATES,
        )
    identifiers = [m.identifier for m in ST07]
    assert len(set(identifiers)) == len(identifiers)
    planned = [
        "CO-1-", "CO-1b-", "CO-2-", "CO-3-", "WN-1-",
        *(f"DF-{n}-" for n in range(1, 9)),
        *(f"ON-{n}-" for n in range(1, 5)),
        *(f"RO-{n}" for n in range(1, 6)),
        *(f"DC-{n}-" for n in range(1, 4)),
    ]  # fmt: skip
    for prefix in planned:
        assert [i for i in identifiers if i.startswith(prefix)], prefix
    owned = {g for g, guard in mutation.GUARDS.items() if guard.module is observation}
    assert owned == set(ST07_GUARDS)
    assert {m.guard for m in ST07} == set(ST07_GUARDS)
    inventory = set(traceability.inventory())
    for guard in ST07_GUARDS:
        assert set(mutation.GUARDS[guard].guarantees) <= inventory, guard
        tags = mutation.guard_tags()[guard]
        assert tags and all(t.startswith("observation.py:") for t in tags), guard


@pytest.mark.traces("ST07-M1", "ST07-M2")
def test_every_predicate_is_mutated_or_inventoried_with_its_reason() -> None:
    """The `ST04-IMPL-R02` lesson: every comprehension filter and `if` test in
    `observation.py` is on a guarded line — and so carries a mutant — or is listed, with the
    reason it carries none, in `ST07_UNMUTATED_PREDICATES`; nothing is both, nothing listed
    is stale, and every reason is stated."""
    source = mutation.source_path(observation).read_text(encoding="utf-8")
    lines = source.splitlines()
    predicates = _predicates(ast.parse(source))
    listed = mutation.ST07_UNMUTATED_PREDICATES
    tagged = {(f, text) for f, line, text in predicates if "# guard:" in lines[line - 1]}
    untagged = {(f, text) for f, _, text in predicates} - tagged
    assert untagged == set(listed), (untagged - set(listed), set(listed) - untagged)
    assert not tagged & set(listed)
    assert all(reason.strip() for reason in listed.values())


@pytest.mark.traces("ST07-M1", "ST07-M3")
def test_every_keyed_access_is_inventoried_with_its_count_class_and_reason() -> None:
    """Every subscript, `.get` or `.setdefault` in `observation.py` is listed with its count,
    its class and its reason; none is a keyed selection of a record — those are the tagged
    filters `ON-1`, `DC-3` and `CO-1e`."""
    source = mutation.source_path(observation).read_text(encoding="utf-8")
    counted: dict[tuple[str, str], int] = {}
    for access in _keyed_accesses(ast.parse(source)):
        counted[access] = counted.get(access, 0) + 1
    listed = mutation.ST07_KEYED_ACCESSES
    assert set(counted) == set(listed), (set(counted) - set(listed), set(listed) - set(counted))
    for access, (count, classification, reason) in listed.items():
        assert counted[access] == count, access
        assert classification in (
            mutation.NON_SELECTION,
            mutation.SINGLE_LAWFUL_VALUE,
            mutation.FAIL_CLOSED,
        ), access
        assert reason.strip(), access
    keyed = {
        "ON-1-key-read-deleted",
        "DC-3-any-recorded-baseline",
        "CO-1e-another-branch-packed-ref",
    }
    assert keyed <= {m.identifier for m in ST07}
