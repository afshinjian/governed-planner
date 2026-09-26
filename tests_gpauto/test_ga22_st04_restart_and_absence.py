"""`GP-AUTO-ST-04`: restart evidence, no persistence, and the global no-stored-form check.

Design basis: AP-11 ST-04 derivation-ownership amendment §2 (Restart/persistence evidence,
Negative tests, Tests (b)–(d), Acceptance), `DO11-2`…`DO11-6`, `DO11-8`, `AP11-I74`; AP-07
§8 (`DV-12`, `DV-14`), §3.3 (`RC-54`); AP-11 §6 (`PV11-12`), §11 (`FI11-1a`).

**Restart evidence is Class A and one step further** (`FI11-1a`). The records are created
through the store's own create path and the outside party's ingest path, the store is
closed and reopened, and every derivation ST-04 implements is recomputed and compared —
and then recomputed again in a **fresh interpreter process** with a different hash seed,
so nothing held in memory, and no set-iteration order, can be what made the two agree.
Nothing derived was persisted to make that possible: the store's contents are identical
before and after deriving, and its schema has nowhere a derived value could be kept.

**The no-stored-form check is global** (`DO11-5`): every table, column, index and view of
the accepted schema, over every `DV-1` … `DV-11` — including the decision package, the
mirror and the equivalence result, which ST-04 does not compute. That check is structural
and negative; it computes nothing for `DV-9`, `DV-10` or ST-06's portion of `DV-4`
(`global structural absence verification != global derivation implementation`).
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Literal, TypeAliasType, cast, get_args, get_origin

import pytest
from pydantic import BaseModel

import st03_ingest
from gate_scope import REPOSITORY_ROOT
from gpauto import derivations as dv
from gpauto import equivalence
from gpauto.authorization import AuthorizationRecord
from gpauto.governance import OwnerDecision
from gpauto.store import (
    CoordinationStore,
    UnreadableRecord,
    WriteRefused,
    create_store,
    open_store,
)
from gpauto.store_schema import build_catalogue, schema_statements, table_columns
from introspect import source_files
from st04_world import derive_all, persisted_extended_world, rendered
from test_ga17_st03_store import PINNED_SCHEMA_DIGEST

GPAUTO_STAGE = "GP-AUTO-ST-04"

RECORD_CLASSES = frozenset(f"RC-{number}" for number in range(10, 42))
"""AP-07's record classes, `RC-10` … `RC-41`: the authoritative records the store holds."""

REFUSAL_ONLY_ACTION = re.compile(r"SELECT RAISE\(ABORT, '[^']*'\); END")
"""The one trigger action the accepted schema has: abort the statement. A trigger that
inserts, updates or replaces could materialize a value; one that only refuses cannot."""


@pytest.fixture
def directory() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="gpauto-st04-") as location:
        yield Path(location)


def raw_contents(path: Path) -> list[str]:
    """Every schema object and every row of the file, read outside GP-AUTO."""
    connection = sqlite3.connect(path)
    try:
        return list(connection.iterdump())
    finally:
        connection.close()


def stored_derivation_surfaces(path: Path) -> list[str]:
    """Every surface of the store at `path` that could hold a value no record class
    declares — the form any stored `DV-1` … `DV-11` result would need. Empty for the
    accepted schema.

    Decided by **structure**, never by a name, so a lawful record field is never refused
    for resembling a derivation (`ST04-IMPL-R04`):

    * **objects** — only tables, indexes and triggers; a view is a stored query;
    * **tables** — each is the storage of one catalogue layout of an `RC-10` … `RC-41`
      record class;
    * **columns** — exactly the columns that layout declares for its record's fields, in
      order, none generated or hidden;
    * **indexes** — every key is a stored column of its own table; an expression key
      would be a computed value, kept;
    * **triggers** — every action only refuses; none inserts, updates or replaces.
    """
    catalogue = build_catalogue()
    offenders: list[str] = []
    connection = sqlite3.connect(path)
    try:
        objects = connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_schema")
        for kind, name, table, sql in objects.fetchall():
            if kind == "table":
                layout = catalogue.layouts.get(name)
                if layout is None or layout.spec.rc not in RECORD_CLASSES:
                    offenders.append(f"table {name}: the storage of no record class")
                    continue
                columns = connection.execute(f"PRAGMA table_xinfo({name})").fetchall()
                for column in columns:
                    if int(column[6]) != 0:
                        offenders.append(f"column {name}.{column[1]}: generated or hidden")
                if [str(c[1]) for c in columns] != [c.name for c in table_columns(layout)]:
                    offenders.append(f"table {name}: a column its record does not declare")
            elif kind == "index":
                stored = {str(c[1]) for c in connection.execute(f"PRAGMA table_xinfo({table})")}
                for entry in connection.execute(f"PRAGMA index_xinfo('{name}')"):
                    if int(entry[5]) and (int(entry[1]) < 0 or entry[2] not in stored):
                        offenders.append(f"index {name}: a key that is not a stored column")
            elif kind == "trigger":
                action = str(sql).split(" BEGIN ", 1)[-1]
                if not REFUSAL_ONLY_ACTION.fullmatch(action):
                    offenders.append(f"trigger {name}: an action other than refusal")
            else:
                offenders.append(f"{kind} {name}: not a table, index or trigger")
    finally:
        connection.close()
    return offenders


def carried_types(record: type[BaseModel]) -> set[type]:
    """Every type a record class's fields can hold, followed through nested models,
    unions, generics and type aliases."""
    found: set[type] = set()
    pending: list[object] = [record]
    while pending:
        annotation = pending.pop()
        if isinstance(annotation, TypeAliasType):
            pending.append(annotation.__value__)
            continue
        origin = get_origin(annotation)
        if origin is Literal:
            continue
        if origin is not None:
            pending.extend(get_args(annotation))
            annotation = origin
        if not isinstance(annotation, type) or annotation in found:
            continue
        found.add(annotation)
        if issubclass(annotation, BaseModel):
            pending.extend(f.annotation for f in annotation.model_fields.values())
    return found


# --- restart / persistence evidence ---------------------------------------------------------


@pytest.mark.traces("ST04-R1", "DV-12", "DO11-1", "ST04-T1")
def test_every_owned_derivation_reproduces_identically_after_store_restart(
    directory: Path,
) -> None:
    """`DV-12`: derive; close; reopen from the same persisted records; derive again —
    identical, for every derivation and portion ST-04 implements. The values are
    non-trivial: a stratified effect term, an extinguishing waiver, a consumed instance,
    a completed resolution, a settled epoch."""
    with persisted_extended_world(directory) as (store, _, subjects):
        path = store.path
        before = derive_all(dv.read_authoritative_records(store), subjects)
    assert not [k for k, v in before.items() if isinstance(v, dv.Indeterminate)], before

    second = before["DV-1/second"]
    assert isinstance(second, dv.PriorAuthorizedState) and len(second.terms) == 1
    force = before["DV-5"]
    assert isinstance(force, dv.ObligationForce)
    assert not force.in_force and len(force.extinguished_by) == 1 and force.epoch_terminal
    live = before["DV-4/liveness/root"]
    assert isinstance(live, dv.Liveness) and not live.live and live.consumed_by
    assert isinstance(before["DV-4/recorded-eligibility"], dv.CompletedResolution)

    reopened = open_store(path)
    try:
        after = derive_all(dv.read_authoritative_records(reopened), subjects)
    finally:
        reopened.close()
    assert rendered(after) == rendered(before)
    assert after == before


@pytest.mark.traces("ST04-R1", "DV-12", "ST04-N2")
def test_every_owned_derivation_reproduces_in_a_fresh_process_under_another_hash_seed(
    directory: Path,
) -> None:
    """A new interpreter opens the store, reads it and derives: its rendering equals this
    process's. Only the persisted records cross the process boundary — no derived value,
    and no read or iteration order, can be what made them agree."""
    with persisted_extended_world(directory) as (store, _, subjects):
        path = store.path
        here = rendered(derive_all(dv.read_authoritative_records(store), subjects))
    for seed in ("0", "4242"):
        completed = subprocess.run(
            [sys.executable, str(REPOSITORY_ROOT / "tests_gpauto" / "st04_world.py"), str(path)]
            + subjects.argv(),
            capture_output=True,
            text=True,
            cwd=REPOSITORY_ROOT,
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == here


@pytest.mark.traces("ST04-R1", "ST04-N1", "DV-14", "ST04-A1")
def test_deriving_writes_nothing_and_needs_nothing_derived_persisted(directory: Path) -> None:
    """`DV-14`: the file's every schema object and row are identical before and after
    every derivation has run, twice — nothing was written, cached or snapshotted — and a
    derivation result has no write operation in the store at all."""
    with persisted_extended_world(directory) as (store, _, subjects):
        before = raw_contents(store.path)
        records = dv.read_authoritative_records(store)
        results = derive_all(records, subjects)
        derive_all(dv.read_authoritative_records(store), subjects)
        assert raw_contents(store.path) == before
        for result in results.values():
            with pytest.raises(WriteRefused, match="no write operation"):
                store.create(cast(BaseModel, result))  # type: ignore[arg-type]
        assert raw_contents(store.path) == before


@pytest.mark.traces("ST04-T1", "DV-12", "ST04-D1")
def test_an_unreadable_stored_decision_makes_force_indeterminate_not_in_force(
    directory: Path,
) -> None:
    """`RC-4`, `VM-6`: a stored `RC-13` record under a format this definition does not
    cover might be the extinguishing waiver, so force is indeterminate — never read as in
    force from the readable remainder."""
    with persisted_extended_world(directory) as (store, built, subjects):
        waiver = next(
            d
            for unit in built.deferred_ingest.values()
            for d in unit
            if d.identity.value.startswith("waive-")
        )
        with st03_ingest.external_connection(store.path) as connection:
            st03_ingest.write(
                connection,
                waiver.model_copy(update={"identity": type(waiver.identity)(value="later")}),
                record_format="gpauto.coordination-record/999",
            )
        records = dv.read_authoritative_records(store)
        assert OwnerDecision in records.unreadable
        outcome = derive_all(records, subjects)["DV-5"]
        assert isinstance(outcome, dv.Indeterminate)
        assert outcome.cause == dv.IndeterminacyCause.UNREADABLE_INPUT


class _Moving:
    """A store whose records change between two read passes, as a concurrent unit would."""

    def __init__(self, store: CoordinationStore) -> None:
        self.store = store
        self.reads = 0
        self.undecodable = 0

    def enumerate(self, kind: type[BaseModel]) -> tuple[object, ...]:
        self.reads += 1
        found = self.store.enumerate(kind)
        self.undecodable += sum(isinstance(item, UnreadableRecord) for item in found)
        return found[:-1] if self.reads <= len(dv.DERIVATION_INPUTS) and found else found


@pytest.mark.traces("ST04-T1", "DV-12")
def test_a_read_that_changes_between_passes_is_reported_unstable_never_used(
    directory: Path,
) -> None:
    """Each class is read in its own read transaction, so a unit committed mid-read could
    tear the record set. The read is taken twice and used only when both agree; otherwise
    no record is kept, every class is reported **unstable** — both passes decoded, so
    nothing is reported unreadable — and every derivation over it is indeterminate as an
    unstable read. The store is read exactly twice: there is no retry
    (`ST04-IMPL-R03`)."""
    with persisted_extended_world(directory) as (store, _, subjects):
        moving = _Moving(store)
        records = dv.read_authoritative_records(cast(CoordinationStore, moving))
        assert moving.reads == 2 * len(dv.DERIVATION_INPUTS)
        assert moving.undecodable == 0
        assert records.records == ()
        assert records.unreadable == frozenset()
        assert records.unstable == frozenset(dv.DERIVATION_INPUTS)
        for outcome in derive_all(records, subjects).values():
            assert isinstance(outcome, dv.Indeterminate)
            assert outcome.cause == dv.IndeterminacyCause.UNSTABLE_READ


# --- the global no-stored-form check (DO11-5) ------------------------------------------------


@pytest.mark.traces("DO11-5", "ST04-N1", "ST04-A1", "DV-14", "AP11-I74")
def test_no_table_column_or_view_stores_any_derivation(directory: Path) -> None:
    """`DO11-5`, `PV11-12`, `RC-54`: the store created is the accepted schema v3 — its
    objects are exactly the canonical DDL, whose digest is the one ST-03 pinned — and it
    has no surface that could hold any `DV-1` … `DV-11` result: no view, no table that is
    not a record class's storage, no column its record does not declare, no generated
    column, no expression index, no trigger that writes.

    The check reads structure, not names: the schema is full of lawful record fields that
    *sound* derived — `resolved_root`, `within_envelope`, `scope_frame`, `cycle_occurrence`
    — and every one passes. The AP-10 mirror is a non-authoritative rendering outside this
    file; the check reads only the authoritative store, so a mirror is neither inspected
    nor classified here — and a mirror *table* inside the store would be caught as a table
    no record class declares."""
    store = create_store(directory / "fresh.sqlite")
    store.close()
    statements = schema_statements(build_catalogue())
    digest = hashlib.sha256("\n;\n".join(statements).encode("utf-8")).hexdigest()
    assert digest == PINNED_SCHEMA_DIGEST
    connection = sqlite3.connect(directory / "fresh.sqlite")
    try:
        objects = connection.execute("SELECT type, name, sql FROM sqlite_schema").fetchall()
        columns = {
            str(column[1])
            for (table,) in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
            for column in connection.execute(f"PRAGMA table_xinfo({table})")
        }
    finally:
        connection.close()
    assert {str(sql) for _, _, sql in objects if sql is not None} == set(statements)
    kinds = Counter(str(kind) for kind, _, _ in objects)
    assert kinds == {"table": 71, "trigger": 169, "index": 113}, kinds
    assert {sp.rc for sp in build_catalogue().specs} == RECORD_CLASSES
    for lookalike in ("resolved_root", "within_envelope", "scope_frame", "cycle_occurrence"):
        assert any(lookalike in column for column in columns), lookalike
    assert stored_derivation_surfaces(directory / "fresh.sqlite") == []


@pytest.mark.traces("ST04-N3", "DO11-5", "DV-14")
def test_every_index_is_over_recorded_columns_and_stores_no_result(directory: Path) -> None:
    """`DV-14`: a read-optimizing index over recorded facts is permitted; one storing a
    computed value is not. Every index — the seven the schema declares and the ones its
    keys imply — has only stored columns of its own table as keys: no expression."""
    store = create_store(directory / "fresh.sqlite")
    store.close()
    connection = sqlite3.connect(directory / "fresh.sqlite")
    try:
        indexes = connection.execute(
            "SELECT name, tbl_name, sql FROM sqlite_schema WHERE type = 'index'"
        ).fetchall()
        assert len([sql for _, _, sql in indexes if sql is not None]) == 7
        for index, table, _ in indexes:
            stored = {str(c[1]) for c in connection.execute(f"PRAGMA table_xinfo({table})")}
            keys = [e for e in connection.execute(f"PRAGMA index_xinfo('{index}')") if e[5]]
            assert keys, index
            for entry in keys:
                assert int(entry[1]) >= 0 and entry[2] in stored, (index, entry)
    finally:
        connection.close()


@pytest.mark.traces("ST04-N1", "DO11-5", "DV-14")
def test_every_trigger_only_refuses_so_none_can_materialize_a_value(directory: Path) -> None:
    """`DV-14`: a trigger is the one schema object that could compute and keep a value on
    a write. Every trigger of the accepted schema only aborts the statement — create-only
    enforcement, referential checks — and none inserts, updates or replaces anything."""
    store = create_store(directory / "fresh.sqlite")
    store.close()
    connection = sqlite3.connect(directory / "fresh.sqlite")
    try:
        triggers = connection.execute(
            "SELECT name, sql FROM sqlite_schema WHERE type = 'trigger'"
        ).fetchall()
    finally:
        connection.close()
    assert len(triggers) == 169
    for name, sql in triggers:
        assert REFUSAL_ONLY_ACTION.fullmatch(str(sql).split(" BEGIN ", 1)[1]), name


@pytest.mark.traces("ST04-N1", "DO11-5", "DV-14")
def test_no_record_class_or_field_carries_a_derived_value() -> None:
    """`RC-52`, `RC-54`: no stored record class can hold a derivation's result. Every type
    any record field can carry, followed through nested models, unions and aliases, is
    declared outside the derivations module and outside ST-02's equivalence module — so
    no `DV-1` … `DV-8` result and no `DV-11` outcome is storable in any record — and
    `LIVE` is not storable as an establishing record: it is the absence of one (`WP-9`)."""
    from gpauto.coordination_records import DispositionEstablishingRecord

    catalogue = build_catalogue()
    assert {sp.record for sp in catalogue.specs} == set(catalogue.by_record)
    results = {
        value
        for value in vars(dv).values()
        if isinstance(value, type) and value.__module__ == dv.__name__
    }
    assert {dv.PriorAuthorizedState, dv.CycleBound, dv.Liveness, dv.Indeterminate} <= results
    for record in catalogue.by_record:
        carried = carried_types(record)
        assert record in carried and len(carried) > 1, record
        foreign = {t for t in carried if t.__module__ in {dv.__name__, equivalence.__name__}}
        assert not foreign, (record.__name__, foreign)
        assert not carried & results, record.__name__
    annotation = DispositionEstablishingRecord.model_fields["disposition"].annotation
    assert "LiveDisposition" not in repr(annotation)
    assert equivalence.EquivalenceOutcome not in set().union(
        *(carried_types(r) for r in catalogue.by_record)
    )


NON_CONFORMANT_SURFACES: dict[str, tuple[str, str]] = {
    "view": ("CREATE VIEW ledger_view AS SELECT identity FROM rc10_project", "view ledger_view"),
    "undeclared table": ("CREATE TABLE ledger (entry TEXT) STRICT", "table ledger"),
    "undeclared column": (
        "ALTER TABLE rc10_project ADD COLUMN note TEXT",
        "table rc10_project: a column",
    ),
    "generated column": (
        "ALTER TABLE rc10_governed_stage ADD COLUMN note TEXT "
        "GENERATED ALWAYS AS (project) VIRTUAL",
        "column rc10_governed_stage.note: generated",
    ),
    "expression index": (
        "CREATE INDEX lookup ON rc10_project (lower(identity))",
        "index lookup",
    ),
    "writing trigger": (
        "CREATE TRIGGER copy AFTER INSERT ON rc10_project BEGIN "
        "INSERT INTO rc10_project (identity, record_format) VALUES (NEW.identity, 'x'); END",
        "trigger copy",
    ),
    "write before refusal": (
        "CREATE TRIGGER sneak AFTER INSERT ON rc10_project BEGIN "
        "DELETE FROM rc10_project; SELECT RAISE(ABORT, 'x'); END",
        "trigger sneak",
    ),
}
"""One surface of each kind a stored derivation could use, each under a **neutral** name,
so the check can only report it by structure (`SD11-12b`: the check is shown to fail)."""


@pytest.mark.traces("DO11-5", "ST04-N1", "ST04-N3")
@pytest.mark.parametrize("surface", list(NON_CONFORMANT_SURFACES), ids=str)
def test_the_absence_check_is_structural_and_reports_each_derived_storage_surface(
    directory: Path, surface: str
) -> None:
    """`SD11-12b`: the check is not vacuous. Each non-conformant surface, added to an
    otherwise accepted store under a name that denotes nothing derived, is reported —
    and the same store without it reports nothing."""
    path = directory / "fixture.sqlite"
    create_store(path).close()
    assert stored_derivation_surfaces(path) == []
    statement, expected = NON_CONFORMANT_SURFACES[surface]
    connection = sqlite3.connect(path)
    try:
        connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    offenders = stored_derivation_surfaces(path)
    assert any(o.startswith(expected) for o in offenders), offenders


# --- DV-11: reuse boundary (DO11-6) --------------------------------------------------------


@pytest.mark.traces("DO11-6", "ST04-T6")
def test_equivalence_is_reached_only_through_st02s_function_and_st04_adds_no_comparator() -> None:
    """`DO11-6`, `SRB11-4`: the only comparison of authority-bearing content in GP-AUTO is
    ST-02's `equivalence.py`. The derivations module declares no comparator, normal form
    or canonicalization, imports neither `equivalence` nor any canonicalization primitive,
    and needs none — no derivation it implements compares authority-bearing content."""
    comparators: dict[str, list[str]] = {}
    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and any(
                word in node.name.lower()
                for word in ("compar", "equivalen", "normal", "canonical", "normform")
            ):
                comparators.setdefault(path.name, []).append(node.name)
    assert set(comparators) <= {"equivalence.py", "content_identity.py", "preimage.py"}
    assert "derivations.py" not in comparators

    tree = ast.parse(inspect.getsource(dv))
    imported = {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not {
        m for m in imported if m.endswith("equivalence") or m.startswith(("gplanner", "rfc8785"))
    }
    assert "gpauto.content_identity" not in imported and "gpauto.codec" not in imported


@pytest.mark.traces("DO11-6", "ST04-T6", "ST04-R1")
def test_dv11_recomputes_identically_after_restart_through_st02s_function(
    directory: Path,
) -> None:
    """Test-only evidence (`DO11-6`, `DV-12`): the `RC-12` records under one identity, read
    back from the store, compare through `equivalence.compare_records` — imported, never
    re-implemented — to the same outcome before and after restart. Nothing of the
    comparison is stored (see the schema checks above)."""

    def outcomes(store: CoordinationStore) -> dict[tuple[str, str], str]:
        records = [
            r for r in store.enumerate(AuthorizationRecord) if isinstance(r, AuthorizationRecord)
        ]
        found: dict[tuple[str, str], str] = {}
        for first in records:
            for second in records:
                if first.authorization_identity == second.authorization_identity:
                    key = (first.identity.value, second.identity.value)
                    found[key] = equivalence.compare_records(first, second).value
        return found

    with persisted_extended_world(directory) as (store, _, _subjects):
        path = store.path
        before = outcomes(store)
    reopened = open_store(path)
    try:
        after = outcomes(reopened)
    finally:
        reopened.close()
    assert after == before
    assert before[("record-a", "record-b")] == equivalence.EquivalenceOutcome.EQUIVALENT.value
    assert len(before) == 5


# --- DV-9, DV-10 and ST-06's DV-4 portion: structural absence only (DO11-2 … DO11-4) -------


@pytest.mark.traces("DO11-4", "ST04-T7")
def test_st04_computes_neither_the_decision_package_nor_the_mirror() -> None:
    """`DO11-4`: `DV-9` and `DV-10` are ST-15's. ST-04 declares no function, class or
    module for either — its only responsibility for them is the storage absence the
    schema tests above verify. No computation of either is tested here, because none
    exists to test."""
    tree = ast.parse(inspect.getsource(dv))
    declared = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.ClassDef)
    }
    assert not {n for n in declared if "package" in n.lower() or "mirror" in n.lower()}
    assert not [p for p in source_files() if "mirror" in p.stem or "package" in p.stem]


@pytest.mark.traces("DO11-3", "DO11-2", "ST04-T8", "DO11-8")
def test_st04_executes_no_authority_resolution_and_depends_on_no_later_stage() -> None:
    """`DO11-2`, `DO11-3`: no `RA-00` … `RA-09` evaluation, binding match, candidate
    validity, exactly-one selection or instance constitution — the module reads no
    `RC-12` record, `RC-15` exclusion or `RC-16` ambiguity and names none of their types;
    it produces no ST-06 result. `DO11-8`: it imports only ST-01 … ST-03 modules."""
    source = inspect.getsource(dv)
    tree = ast.parse(source)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        alias.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for alias in n.names
    }
    for forbidden in (
        "AuthorizationRecord", "AuthorityBearingContent", "CandidateExclusion",
        "CandidateExclusionRecord", "RaAttribute", "AuthorityAmbiguity", "OwnerAuthorization",
        "RootResolution", "compare_records", "equivalence",
    ):  # fmt: skip
        assert forbidden not in names, forbidden
    functions = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for word in ("resolve", "select", "match", "constitut", "evaluat", "exclu", "candidate"):
        assert not [f for f in functions if word in f.lower()], word
    assert not {AuthorizationRecord} & set(dv.DERIVATION_INPUTS)
    st03_modules = {
        "absence", "authorization", "coordination_identity", "coordination_records",
        "coordination_vocabulary", "governance", "identity", "repository", "review", "store",
        "vocabulary",
    }  # fmt: skip
    gpauto_imports = {
        (n.module or "").split(".", 1)[1]
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("gpauto.")
    }
    assert gpauto_imports <= st03_modules
