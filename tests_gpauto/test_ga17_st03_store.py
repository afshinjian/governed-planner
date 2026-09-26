"""`GP-AUTO-ST-03`: the store — every class, create-only, references, units, schema, placement.

Design basis: AP-11 §16 (`GP-AUTO-ST-03` Tests, Negative tests, Restart/persistence
evidence) as replaced by the ST-03 store-realization amendment §11.1 and the follow-on §3;
AP-07 §3, §5.1, §6, §7, §17, §22.1, §23; AP-10 §5 (`PB-2`, `PB-8`); AP-03 `AP03-I10`,
`AP03-I19`, `AP03-I27`, `AP03-I35`.

The evidence is read through the store's public surface wherever the claim is about that
surface, and through a **raw connection** wherever the claim is about the schema — a second
connection that bypasses GP-AUTO's write surface, so the create-only, referential and
closure rules are shown to live in the schema and not only in GP-AUTO's own writer. A
claim that depends on a connection's pragmas is made only for a connection that adopts the
store's configuration (`store.PRAGMAS`). The file is not an access-control boundary: no
claim here is made against an actor who opens it otherwise, or alters its schema.
"""

from __future__ import annotations

import ast
import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from pydantic import BaseModel

import st03_ingest
import st03_world
from gate_scope import REPOSITORY_ROOT
from gpauto import minting, store_schema
from gpauto import store as store_module
from gpauto.absence import Present
from gpauto.authorization import AuthorizationRecord, ConsumedDisposition
from gpauto.coordination_identity import (
    AuditEntryId,
    DispositionRecordId,
    M1PositionEntryId,
    M2PositionEntryId,
)
from gpauto.coordination_records import (
    ActivationEffectRecord,
    ArtifactProductionRecord,
    AuditEntry,
    AuthorityEnvelopeRecord,
    CandidateExclusionRecord,
    ConformanceDetermination,
    CycleOccurrence,
    DispatchRecord,
    DispositionEstablishingRecord,
    EntryStateBoundaryRecord,
    FindingRecord,
    M1PositionEntry,
    M2PositionEntry,
    OutcomeIngestionRecord,
    RootResolutionRecord,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import AuditEntryClass, M2Edge, M2Position
from gpauto.governance import OwnerDecision, StageOutcome, StageOutcomeDecision
from gpauto.identity import (
    AuthorizationRecordId,
    EntryStateBoundaryId,
    InputPackageId,
    OwnerAuthorizationId,
    OwnerDecisionId,
    RootResolutionId,
    StageOutcomeId,
    UnaccountedMutationId,
    WorkerActivationId,
)
from gpauto.repository import UnaccountedMutation
from gpauto.review import FrozenFindingSet, RemediationObligation
from gpauto.scope_frame import (
    BaselineIdentity,
    GovernedStage,
    Project,
    RepositoryBoundary,
    StageContract,
)
from gpauto.store import StaleSchemaRefused, StoreUnavailable, UnreadableRecord, WriteRefused
from gpauto.vocabulary import OwnerDecisionKind, StageOutcomeDisposition
from st03_world import ABSENT, fresh_store, populated_store, raw

GPAUTO_STAGE = "GP-AUTO-ST-03"

INGEST_CLASSES = (
    Project,
    GovernedStage,
    RepositoryBoundary,
    BaselineIdentity,
    StageContract,
    AuthorizationRecord,
    OwnerDecision,
)


def _tables(store: store_module.CoordinationStore) -> list[str]:
    connection = raw(store)
    try:
        rows = connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'").fetchall()
        return sorted(str(row[0]) for row in rows)
    finally:
        connection.close()


def _columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]


def _refused_raw(store: store_module.CoordinationStore, sql: str, *args: object) -> bool:
    connection = raw(store)
    try:
        connection.execute(sql, args)
    except sqlite3.IntegrityError:
        return True
    finally:
        connection.close()
    return False


# --- every record class, created once ---------------------------------------------------


@pytest.mark.traces(
    "RC-10", "RC-11", "RC-12", "RC-13", "RC-14", "RC-15", "RC-16", "RC-17", "RC-18",
    "RC-19", "RC-20", "RC-21", "RC-22", "RC-23", "RC-24", "RC-25", "RC-26", "RC-27",
    "RC-28", "RC-29", "RC-30", "RC-31", "RC-32", "RC-33", "RC-34", "RC-35", "RC-36",
    "RC-37", "RC-38", "RC-39", "RC-40", "RC-41", "ST03-D1", "ST03-T1",
)  # fmt: skip
def test_every_record_class_is_created_once_and_reads_back_exactly() -> None:
    """`SRB11-1`: each of `RC-10` … `RC-41` is realized, created through its permitted
    surface — ingest classes by the outside party, coordination classes by the store —
    and read back equal to what was created, by every record, none unreadable."""
    with populated_store() as (store, built):
        catalogue = store_schema.build_catalogue()
        assert {spec.rc for spec in catalogue.specs} == {f"RC-{n}" for n in range(10, 42)}
        expected: dict[type[BaseModel], list[BaseModel]] = {}
        for record in [
            *built.ingest,
            *built.records(),
            *(r for rows in built.deferred_ingest.values() for r in rows),
        ]:
            expected.setdefault(type(record), []).append(record)
        assert set(expected) == set(catalogue.by_record), "one record of every class"
        for record_type, records in expected.items():
            stored = store.enumerate(record_type)
            assert not [r for r in stored if isinstance(r, UnreadableRecord)], record_type
            assert sorted(map(repr, stored)) == sorted(map(repr, records)), record_type


@pytest.mark.traces("AP11-I64", "ST03-A1")
def test_each_record_class_has_exactly_one_realization_and_none_is_invented() -> None:
    """`AP11-I64`: `RC-10` … `RC-41`, each realized at ST-03 exactly once — by one table,
    or by the table family its frozen row names (`RC-10`'s four entities, `RC-11`'s
    contents and preimage, `RC-30`'s two classes, `RC-34`'s four machines, `RC-37`'s two
    records) — and no table outside those classes."""
    specs = store_schema.catalogue_specs()
    record_classes = [spec.record for spec in specs]
    assert len(record_classes) == len(set(record_classes)), "one table per record class"
    families = {rc: sorted(s.name for s in specs if s.rc == rc) for rc in {s.rc for s in specs}}
    multiple = {rc for rc, names in families.items() if len(names) > 1}
    assert multiple == {"RC-10", "RC-11", "RC-30", "RC-34", "RC-37"}
    for spec in specs:
        assert spec.name.startswith(spec.rc.lower().replace("-", "")), spec.name
    catalogue = store_schema.build_catalogue()
    for layout in catalogue.layouts.values():
        assert layout.spec in specs


# --- create-only: write once, append only, no update or delete ----------------------------


@pytest.mark.traces("ST03-T4", "ST03-D2")
def test_a_write_once_record_refuses_a_second_write() -> None:
    """`W1`: a record's key exists once; writing it again is refused, whole (`IM-1`)."""
    with populated_store() as (store, built):
        for unit in built.units:
            for record in unit:
                if isinstance(record, FrozenFindingSet | FindingRecord | RemediationObligation):
                    continue  # the freeze unit is exercised whole below
                with pytest.raises(WriteRefused):
                    store.create(record)  # type: ignore[arg-type]
        with pytest.raises(WriteRefused):
            store.create_unit(built.units[10])  # type: ignore[arg-type]


@pytest.mark.traces("ST03-T5")
def test_append_only_classes_accept_only_new_rows_naming_a_predecessor() -> None:
    """`A`: a new entry names an existing predecessor of the same chain, or affirms it has
    none; a predecessor that does not exist is refused, and so is a second successor of
    one predecessor (`MC-2`: the chain cannot fork)."""
    with populated_store() as (store, built):
        s5 = built.handles["s5"]
        assert isinstance(s5, M2PositionEntry)
        root = s5.identity.epoch_root

        def entry(predecessor: object) -> M2PositionEntry:
            return M2PositionEntry(
                identity=M2PositionEntryId(epoch_root=root, discriminator=minting.mint_value()),
                state=M2Position.S8_GATE_REACHED,
                edge=M2Edge.B6b,
                predecessor=predecessor,  # type: ignore[arg-type]
                cycle_occurrence=ABSENT,
            )

        missing = M2PositionEntryId(epoch_root=root, discriminator=minting.mint_value())
        with pytest.raises(WriteRefused):
            store.create(entry(Present[M2PositionEntryId](value=missing)))
        with pytest.raises(WriteRefused):  # s5 already has a successor (the B6a entry)
            store.create(entry(Present[M2PositionEntryId](value=s5.identity)))
        with pytest.raises(WriteRefused):  # the chain already has its first entry
            store.create(entry(ABSENT))

        first = built.handles["first_audit"]
        assert isinstance(first, AuditEntry)
        later = AuditEntry(
            identity=AuditEntryId(
                audited=first.identity.audited, discriminator=minting.mint_value()
            ),
            entry_class=AuditEntryClass.DELIVERY,
            predecessor=Present[AuditEntryId](value=first.identity),
        )
        store.create(later)
        assert later in store.enumerate(AuditEntry)


@pytest.mark.traces("ST03-N1", "AP03-I27")
def test_no_update_delete_or_replace_reaches_any_table_through_a_configured_connection() -> None:
    """`WP-4`, `PV11-1`: every table — child tables included — carries the create-only
    triggers, and every table holding a record refuses `UPDATE`, `DELETE` and a replacing
    `INSERT OR REPLACE` on a connection configured as GP-AUTO configures its own.

    Scoped (GA03-R02): the `REPLACE` refusal depends on `recursive_triggers`, which GP-AUTO
    sets and verifies on its own connections; the second connection here adopts the same
    pragmas. Nothing is claimed for a connection opened without them — the file is not an
    access-control boundary."""
    with populated_store() as (store, _):
        assert store.effective_pragmas()["recursive_triggers"] == 1
        connection = raw(store)
        for name, value, expected in store_module.PRAGMAS:
            connection.execute(f"PRAGMA {name} = {value}")
            assert connection.execute(f"PRAGMA {name}").fetchone()[0] == expected, name
        try:
            triggers = {str(r[0]) for r in connection.execute("SELECT name FROM sqlite_schema")}
            exercised = 0
            for table in _tables(store):
                assert {f"{table}__no_update", f"{table}__no_delete"} <= triggers, table
                row = connection.execute(f"SELECT * FROM {table} LIMIT 1").fetchone()
                if row is None:
                    continue
                exercised += 1
                names = _columns(connection, table)
                with pytest.raises(sqlite3.IntegrityError, match="GPAUTO_NO_UPDATE"):
                    connection.execute(f"UPDATE {table} SET {names[0]} = {names[0]}")
                with pytest.raises(sqlite3.IntegrityError, match="GPAUTO_NO_DELETE"):
                    connection.execute(f"DELETE FROM {table}")
                with pytest.raises(sqlite3.IntegrityError):
                    connection.execute(
                        f"INSERT OR REPLACE INTO {table} ({', '.join(names)}) "
                        f"VALUES ({', '.join('?' for _ in names)})",
                        list(row),
                    )
            assert exercised >= 41
        finally:
            connection.close()


@pytest.mark.traces("ST03-N1", "ID-8")
def test_the_store_exposes_no_update_replace_or_delete_operation() -> None:
    """The absence is the evidence (`VP11-4`): no operation on the store, and no statement
    in its source, updates, replaces, re-keys, re-parents or deletes (`ID-8`, `WP-4`)."""
    public = {name for name in dir(store_module.CoordinationStore) if not name.startswith("_")}
    assert public == {
        "close",
        "create",
        "create_unit",
        "effective_pragmas",
        "enumerate",
        "path",
        "read",
    }
    for path in (store_module.__file__, store_schema.__file__):
        assert path is not None
        for fragment in _sql_fragments(Path(path)):
            upper = fragment.upper()
            for verb in ("UPDATE ", "DELETE ", "REPLACE ", "DROP ", "ALTER ", "UPSERT"):
                assert verb not in upper or "BEFORE" in upper, (path, fragment)


def _sql_fragments(path: Path) -> list[str]:
    """Every string in a module's source that is not documentation."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    documentation = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in documentation
    ]


# --- the ingest domain: same file, no GP-AUTO write path -----------------------------------


@pytest.mark.traces("AP11-I70", "ST03-N2")
@pytest.mark.parametrize("ingest_class", INGEST_CLASSES, ids=lambda c: c.__name__)
def test_no_gpauto_write_operation_exists_for_an_ingest_class(
    ingest_class: type[BaseModel],
) -> None:
    """`SRB11-20`: structural absence first — no write layout exists for the class — and
    then the refusal a create meets, with nothing written."""
    catalogue = store_schema.build_catalogue()
    assert ingest_class not in store_schema.writable_layouts(catalogue)
    assert catalogue.by_record[ingest_class].spec.domain is store_schema.Domain.INGEST
    built = st03_world.world()
    record = next(r for r in built.ingest if type(r) is ingest_class)
    with fresh_store() as store:
        with pytest.raises(WriteRefused, match="no write operation"):
            store.create(record)  # type: ignore[arg-type]
        assert store.enumerate(ingest_class) == ()


@pytest.mark.traces("AP11-I70", "ST03-N2")
def test_an_ingest_record_meets_no_write_operation() -> None:
    """`SRB11-20`, `RC-60`: offered an ingest record, the write surface refuses it and
    writes nothing — the refusal is the absence of an operation, for every ingest class."""
    built = st03_world.world()
    with fresh_store() as store:
        for record in built.ingest:
            with pytest.raises(WriteRefused, match="no write operation"):
                store.create(record)  # type: ignore[arg-type]
            assert store.enumerate(type(record)) == ()


@pytest.mark.traces("AP11-I70", "ST03-N2")
def test_the_ingest_writer_is_test_fixture_only_and_unreachable_from_production() -> None:
    """`SRB11-21`: the stand-in outside party lives in the test tree; no production module
    imports it, and no production module names an ingest table in a write."""
    for path in sorted((REPOSITORY_ROOT / "src" / "gpauto").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "st03_ingest" not in source, path.name
        assert "INSERT INTO rc1" not in source, path.name
    writable = store_schema.writable_layouts(store_schema.build_catalogue())
    assert all(
        layout.spec.domain is store_schema.Domain.COORDINATION for layout in writable.values()
    )
    assert {layout.spec.rc for layout in writable.values()}.isdisjoint({"RC-10", "RC-12", "RC-13"})


@pytest.mark.traces("AP11-I70", "AP03-I27", "ST03-T7")
def test_every_record_under_one_authorization_identity_is_surfaced_individually() -> None:
    """`NP-13`, `AP03-I27`: two records under one `RA-00` identity are two records; the
    store neither merges, dedupes, orders by recency nor prefers either."""
    with populated_store() as (store, built):
        records = store.enumerate(AuthorizationRecord)
        root = built.ingest[5]
        assert isinstance(root, AuthorizationRecord)
        same = [
            r
            for r in records
            if isinstance(r, AuthorizationRecord)
            and r.authorization_identity == root.authorization_identity
        ]
        assert len(same) == 2 and same[0].identity != same[1].identity


@pytest.mark.traces("EQ-9", "ST03-N6")
def test_an_uncovered_or_undecodable_record_is_surfaced_as_unreadable_never_dropped() -> None:
    """`VM-6`, `VM-12`, `NP-12`: a record under a format this definition does not cover,
    or whose content its schema refuses, is returned as `UnreadableRecord` with its
    reason — the enumeration still has every record."""
    with populated_store() as (store, built):
        record = built.ingest[5]
        assert isinstance(record, AuthorizationRecord)
        newer = record.model_copy(update={"identity": AuthorizationRecordId(value="record-newer")})
        with st03_ingest.external_connection(store.path) as connection:
            st03_ingest.write(connection, newer, record_format="gpauto.coordination-record/999")
            connection.execute(
                "INSERT INTO rc12_authorization_record VALUES (?, ?, ?, ?)",
                (
                    "record-broken",
                    record.authorization_identity.value,
                    '{"unexpected": 1}',
                    store_schema.RECORD_FORMAT,
                ),
            )
        records = store.enumerate(AuthorizationRecord)
        unreadable = [r for r in records if isinstance(r, UnreadableRecord)]
        assert len(records) == 5 and len(unreadable) == 2
        assert {r.key for r in unreadable} == {
            (("identity", "record-newer"),),
            (("identity", "record-broken"),),
        }
        assert any("not covered" in r.reason for r in unreadable)
        assert isinstance(store.read(AuthorizationRecord, newer.identity), UnreadableRecord)


# --- references --------------------------------------------------------------------------


@pytest.mark.traces("ST03-T3", "ST03-D3")
def test_every_identity_reference_in_the_schema_is_enforced() -> None:
    """`EB-2a`, `SRB11-10`: every identity-typed column that is not a table's own key is
    covered by a native foreign key, or — for an `OwnerAuthorization` instance — by an
    in-transaction existence trigger. Nothing is left to the caller."""
    catalogue = store_schema.build_catalogue()
    with fresh_store() as store:
        connection = raw(store)
        try:
            triggers = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'trigger'"
                )
            }
            for layout in catalogue.layouts.values():
                if layout.spec.json_payload:
                    continue
                keyed = {
                    str(row[3])
                    for row in connection.execute(f"PRAGMA foreign_key_list({layout.name})")
                }
                own = (
                    set()
                    if layout.is_child
                    else {c for _, cols in store_schema.key_groups(layout) for c in cols}
                )
                for node in _identity_scalars(layout.node):
                    column, annotation = node.column, node.annotation
                    if column in own and not layout.spec.key_is_reference:
                        continue
                    if annotation is OwnerAuthorizationId and column not in keyed:
                        assert f"{layout.name}__instance__{column}" in triggers, (
                            layout.name,
                            column,
                        )
                    else:
                        assert column in keyed, (layout.name, column)
        finally:
            connection.close()


def _identity_scalars(node: object) -> list[store_schema.Scalar]:
    from gpauto.identity import OpaqueIdentity

    found: list[store_schema.Scalar] = []
    if isinstance(node, store_schema.Scalar):
        if isinstance(node.annotation, type) and issubclass(node.annotation, OpaqueIdentity):
            found.append(node)
    elif isinstance(node, store_schema.Composite):
        for _, child in node.fields:
            found.extend(_identity_scalars(child))
    elif isinstance(node, store_schema.Choice):
        for _, _, child in node.variants:
            found.extend(_identity_scalars(child))
    return found


@pytest.mark.traces("ST03-T3", "ST03-N3")
def test_a_dangling_reference_is_refused_and_nothing_is_committed() -> None:
    """A reference to a record the store does not hold cannot be created (`EB-2a`)."""
    with populated_store() as (store, built):
        activation = built.handles["activation"]
        boundary = built.handles["boundary"]
        assert isinstance(activation, WorkerActivationRecord)
        assert isinstance(boundary, EntryStateBoundaryRecord)
        dangling_activation = activation.model_copy(
            update={
                "identity": WorkerActivationId(value=minting.mint_value()),
                "input_package": InputPackageId(value=minting.mint_value()),
            }
        )
        with pytest.raises(WriteRefused):
            store.create(dangling_activation)
        exclusion = built.handles["exclusion"]
        assert isinstance(exclusion, CandidateExclusionRecord)
        missing_record = exclusion.model_copy(
            update={
                "exclusion": exclusion.exclusion.model_copy(
                    update={
                        "identity": exclusion.exclusion.identity.model_copy(
                            update={
                                "excluded_record": AuthorizationRecordId(value="never-ingested")
                            }
                        )
                    }
                )
            }
        )
        with pytest.raises(WriteRefused):
            store.create(missing_record)
        assert len(store.enumerate(CandidateExclusionRecord)) == 1


@pytest.mark.traces("ST03-T3", "ST03-N3", "AP03-I35")
def test_an_instance_reference_requires_an_ingested_record_bearing_it() -> None:
    """`SRB11-10`: an `OwnerAuthorization` instance is the key of no record, so its
    reference is enforced inside the insert by requiring an `RC-12` record bearing it —
    no instance table exists (`AP03-I33`)."""
    with populated_store() as (store, built):
        boundary = built.handles["boundary"]
        assert isinstance(boundary, EntryStateBoundaryRecord)
        orphan = EntryStateBoundaryRecord(
            boundary=boundary.boundary.model_copy(
                update={"identity": EntryStateBoundaryId(value=minting.mint_value())}
            ),
            resolved_root=OwnerAuthorizationId(value="an-instance-no-record-bears"),
        )
        with pytest.raises(WriteRefused, match="GPAUTO_DANGLING_INSTANCE"):
            store.create(orphan)
        assert not [t for t in _tables(store) if "instance" in t]


@pytest.mark.traces("ST03-N3")
def test_a_classification_context_must_name_a_boundary_fixed_for_its_own_root() -> None:
    """`RS7-6`: a context is the pair (root, **its** boundary); a pair joining a root to
    another root's boundary is not a context and cannot be recorded, even though each
    half on its own resolves."""
    with populated_store() as (store, built):
        mutation = built.handles["mutation"]
        assert isinstance(mutation, UnaccountedMutation)
        other = built.ingest[7]
        assert isinstance(other, AuthorizationRecord)
        mismatched = mutation.model_copy(
            update={
                "identity": UnaccountedMutationId(value=minting.mint_value()),
                "context": mutation.context.model_copy(
                    update={"authorization": other.authorization_identity}
                ),
            }
        )
        with pytest.raises(WriteRefused):
            store.create(mismatched)
        store.create(
            mutation.model_copy(
                update={"identity": UnaccountedMutationId(value=minting.mint_value())}
            )
        )


@pytest.mark.traces("AP03-I35", "AP03-I10")
def test_references_resolve_and_new_references_are_accepted_after_consumption() -> None:
    """`AP03-I35`, `AP03-I10`, `IM-2`: after the instance is suspended and then consumed,
    its envelope, activation and effects are still held, still attributed, and a new
    audit entry may still reference them. Existence is not eligibility."""
    with populated_store() as (store, built):
        effect = built.handles["effect"]
        assert isinstance(effect, ActivationEffectRecord)
        assert store.read(ActivationEffectRecord, effect.identity) == effect
        assert effect.identity.parent_activation == built.handles["activation"].identity  # type: ignore[attr-defined]
        audit = AuditEntry(
            identity=AuditEntryId(
                audited=effect.identity.parent_activation, discriminator=minting.mint_value()
            ),
            entry_class=AuditEntryClass.REPORTED,
            predecessor=ABSENT,
        )
        store.create(audit)
        envelope = built.handles["envelope"]
        assert isinstance(envelope, AuthorityEnvelopeRecord)
        assert store.read(AuthorityEnvelopeRecord, envelope.envelope.identity) == envelope


# --- keys: the forbidden duplicates are inexpressible ---------------------------------------


@pytest.mark.traces("ST03-N4", "ST03-D2")
def test_the_frozen_keys_make_each_forbidden_duplicate_inexpressible() -> None:
    """`SRB11-8`: a second boundary per root (`RS7-1`), a second activation of one
    envelope (`CO-7`), a second dispatch per envelope (`MH-7`), a second ingestion per
    activation (`MH-13`), a second set per epoch (`FP-17`), a second adoption per
    activation (`MC-2`), a second derivation per `MC-15` key — each refused."""
    with populated_store() as (store, built):

        def fresh(record: BaseModel, path: str) -> BaseModel:
            head, _, rest = path.partition(".")
            inner = getattr(record, head)
            if rest:
                return record.model_copy(update={head: fresh(inner, rest)})
            return record.model_copy(
                update={head: inner.model_copy(update={"value": minting.mint_value()})}
            )

        boundary = built.handles["boundary"]
        activation = built.handles["activation"]
        dispatch = built.one_of(DispatchRecord)
        ingestion = built.one_of(OutcomeIngestionRecord)
        frozen = built.handles["frozen"]
        adoption = built.handles["adoption"]
        envelope = built.handles["envelope"]
        attempts: list[BaseModel] = [
            fresh(boundary, "boundary.identity"),
            fresh(activation, "identity"),
            fresh(dispatch, "identity"),
            fresh(ingestion, "identity"),
            fresh(envelope, "envelope.identity"),
        ]
        assert isinstance(adoption, ConformanceDetermination)
        cycle = built.one_of(CycleOccurrence)
        attempts.append(fresh(cycle, "identity"))
        attempts.append(
            adoption.model_copy(
                update={
                    "identity": adoption.identity.model_copy(
                        update={"discriminator": minting.mint_value()}
                    )
                }
            )
        )
        assert isinstance(frozen, FrozenFindingSet)
        attempts.append(
            frozen.model_copy(
                update={
                    "identity": frozen.identity.model_copy(update={"value": minting.mint_value()}),
                    "members": (),
                }
            )
        )
        for attempt in attempts:
            with pytest.raises(WriteRefused):
                store.create(attempt)  # type: ignore[arg-type]


# --- RC-36: several outcomes under one stage (ID-8; GA03-R01) ----------------------------

RC36 = "rc36_stage_outcome"
RC36_KEY = ("identity__parent_stage", "identity__local_discriminator")
SECOND_OUTCOME_DISCRIMINATOR = "outcome-token-b"
"""A fixed opaque test value, distinct from `st03_world.OUTCOME_DISCRIMINATOR` and derived
from nothing — no timestamp, order, epoch, authorization or stage position."""


def _second_epoch(
    store: store_module.CoordinationStore, built: st03_world.World
) -> tuple[StageOutcome, StageOutcome, DispositionEstablishingRecord]:
    """The world's outcome, and a second outcome of the **same** stage settling a second
    authorization epoch (`other_root`), established by its own ingested acceptance, with
    that epoch's consumption naming it."""
    first = built.handles["outcome"]
    assert isinstance(first, StageOutcome)
    stage = first.identity.parent_stage
    consumed = {
        record.identity.authorization
        for record in built.records()
        if isinstance(record, DispositionEstablishingRecord)
        and isinstance(record.disposition, ConsumedDisposition)
    }
    (other_root,) = {
        record.authorization_identity
        for record in built.ingest
        if isinstance(record, AuthorizationRecord)
    } - consumed
    boundary = built.handles["boundary"]
    assert isinstance(boundary, EntryStateBoundaryRecord)
    other_boundary = boundary.model_copy(
        update={
            "resolved_root": other_root,
            "boundary": boundary.boundary.model_copy(
                update={"identity": EntryStateBoundaryId(value=minting.mint_value())}
            ),
        }
    )
    store.create(other_boundary)
    from gpauto.repository import ClassificationContext

    acceptance = OwnerDecision(
        identity=OwnerDecisionId(value=f"accept-second-epoch-{stage.value}"),
        stage=stage,
        act=StageOutcomeDecision(
            kind=OwnerDecisionKind.STAGE_OUTCOME,
            produced_authorization=ABSENT,
            corrects=ABSENT,
            context=ClassificationContext(
                authorization=other_root, entry_boundary=other_boundary.boundary.identity
            ),
            outcome=StageOutcomeDisposition.ACCEPTED,
        ),
    )
    st03_ingest.ingest(store.path, (acceptance,))
    second = StageOutcome(
        identity=StageOutcomeId(
            parent_stage=stage, local_discriminator=SECOND_OUTCOME_DISCRIMINATOR
        ),
        disposition=StageOutcomeDisposition.ACCEPTED,
        established_by=acceptance.identity,
    )
    consumption = DispositionEstablishingRecord(
        identity=DispositionRecordId(authorization=other_root, discriminator=minting.mint_value()),
        disposition=ConsumedDisposition(established_by_outcome=second.identity),
    )
    return first, second, consumption


def _consumed_by(records: tuple[BaseModel | UnreadableRecord, ...]) -> dict[str, StageOutcomeId]:
    """`authorization instance -> the outcome its consumption names`, read back."""
    named: dict[str, StageOutcomeId] = {}
    for record in records:
        assert isinstance(record, DispositionEstablishingRecord), record
        if isinstance(record.disposition, ConsumedDisposition):
            named[record.identity.authorization.value] = record.disposition.established_by_outcome
    return named


@pytest.mark.traces("ID-8", "RC-36", "ST03-D2")
def test_rc36_is_keyed_on_the_whole_stage_outcome_identity() -> None:
    """`ID-8`: the parent stage alone is not the identity. `RC-36`'s key is the pair
    `(parent_stage, local_discriminator)`, and every native reference to a `StageOutcomeId`
    — found by scanning every table, not by naming one — targets that whole pair, so no
    partial `StageOutcome` reference is expressible."""
    with fresh_store() as store:
        connection = raw(store)
        try:
            key = sorted(
                (int(row[5]), str(row[1]))
                for row in connection.execute(f"PRAGMA table_info({RC36})")
                if int(row[5]) > 0
            )
            assert tuple(name for _, name in key) == RC36_KEY
            references: dict[tuple[str, int], list[tuple[str, str]]] = {}
            for table in _tables(store):
                for row in connection.execute(f"PRAGMA foreign_key_list({table})"):
                    if str(row[2]) == RC36:
                        references.setdefault((table, int(row[0])), []).append(
                            (str(row[3]), str(row[4]))
                        )
        finally:
            connection.close()
    assert references, "some table must reference RC-36"
    for (table, _), pairs in references.items():
        assert tuple(target for _, target in pairs) == RC36_KEY, table
        assert all(source.endswith(target.removeprefix("identity")) for source, target in pairs)
    assert {table for table, _ in references} == {"rc35_disposition_establishing_record"}


@pytest.mark.traces("ID-8", "RC-36", "RC-35", "ST03-T3", "ST03-R1")
def test_two_outcomes_of_one_stage_coexist_and_each_is_referenced_distinctly() -> None:
    """GA03-R01's closure evidence (`ID-8`): one stage, two outcomes under distinct local
    discriminators — both persist, both read back distinctly before and after reopen, and
    each epoch's consumption resolves to its own outcome. Parent-stage equality alone
    neither collides two outcomes nor resolves a reference."""
    with populated_store() as (store, built):
        first, second, consumption = _second_epoch(store, built)
        assert first.identity.parent_stage == second.identity.parent_stage
        assert first.identity != second.identity
        try:
            store.create_unit((second, consumption))
        except WriteRefused as refused:
            pytest.fail(f"a second outcome of one stage collided with the first: {refused}")

        outcomes = store.enumerate(StageOutcome)
        assert first in outcomes and second in outcomes
        assert store.read(StageOutcome, first.identity) == first
        assert store.read(StageOutcome, second.identity) == second
        consumed = _consumed_by(store.enumerate(DispositionEstablishingRecord))
        assert consumed == {"authorization": first.identity, "other-authorization": second.identity}

        # A reference naming the stage with an unminted discriminator resolves to nothing.
        partial = consumption.model_copy(
            update={
                "identity": consumption.identity.model_copy(
                    update={"discriminator": minting.mint_value()}
                ),
                "disposition": ConsumedDisposition(
                    established_by_outcome=StageOutcomeId(
                        parent_stage=first.identity.parent_stage,
                        local_discriminator="outcome-token-never-recorded",
                    )
                ),
            }
        )
        with pytest.raises(WriteRefused):
            store.create(partial)

        # The whole identity is the key: a second write of either occurrence is refused.
        for occurrence in (first, second):
            with pytest.raises(WriteRefused):
                store.create(
                    occurrence.model_copy(update={"disposition": StageOutcomeDisposition.ABANDONED})
                )

        connection = raw(store)
        try:
            joined = connection.execute(
                "SELECT o.identity__local_discriminator, d.identity__authorization "
                "FROM rc35_disposition_establishing_record AS d JOIN rc36_stage_outcome AS o "
                "ON o.identity__parent_stage = "
                "d.disposition__ConsumedDisposition__established_by_outcome__parent_stage "
                "AND o.identity__local_discriminator = "
                "d.disposition__ConsumedDisposition__established_by_outcome__local_discriminator"
            ).fetchall()
            count = connection.execute(f"SELECT count(*) FROM {RC36}").fetchone()[0]
        finally:
            connection.close()
        assert sorted((str(a), str(b)) for a, b in joined) == [
            (st03_world.OUTCOME_DISCRIMINATOR, "authorization"),
            (SECOND_OUTCOME_DISCRIMINATOR, "other-authorization"),
        ]
        assert count == 2

        path = store.path
        store.close()
        with store_module.open_store(path) as reopened:
            assert reopened.read(StageOutcome, first.identity) == first
            assert reopened.read(StageOutcome, second.identity) == second
            reread = [r for r in reopened.enumerate(StageOutcome) if isinstance(r, StageOutcome)]
            assert sorted(o.identity.local_discriminator for o in reread) == sorted(
                (st03_world.OUTCOME_DISCRIMINATOR, SECOND_OUTCOME_DISCRIMINATOR)
            )
            assert _consumed_by(reopened.enumerate(DispositionEstablishingRecord)) == consumed


# --- atomic coupled units, and crash consistency -----------------------------------------


@pytest.mark.traces("ST03-T2", "ST03-D4")
def test_a_coupled_unit_is_visible_whole_or_not_at_all() -> None:
    """`SRB11-11`, `WP-12`: when any record of a unit is refused, none of the unit is
    committed — including the records inserted before the refusal."""
    with fresh_store() as store:
        built = st03_world.world()
        st03_ingest.ingest(store.path, built.ingest)
        for unit in built.units[:2]:
            store.create_unit(unit)  # type: ignore[arg-type]
        resolution, a1 = built.units[1]
        again = RootResolutionRecord(
            identity=RootResolutionId(value=minting.mint_value()),
            project=resolution.project,  # type: ignore[attr-defined]
            stage=resolution.stage,  # type: ignore[attr-defined]
            predecessor_terminal_entry=Present(value=a1.identity),  # type: ignore[attr-defined]
            candidates=(),
        )
        with pytest.raises(WriteRefused):
            store.create_unit((again, a1))  # type: ignore[arg-type]
        assert store.read(RootResolutionRecord, again.identity) is None


@pytest.mark.traces("ST03-T2", "ST03-D4")
def test_a_finding_cannot_exist_outside_its_frozen_set() -> None:
    """`WP-19`, `FP-7`: a finding is created only together with the set that lists it as
    a member; alone it is refused at commit, and with its set it commits whole."""
    with fresh_store() as store:
        built = st03_world.world()
        st03_ingest.ingest(store.path, built.ingest)
        freeze_index = next(
            i
            for i, unit in enumerate(built.units)
            if any(isinstance(r, FindingRecord) for r in unit)
        )
        for unit in built.units[:freeze_index]:
            store.create_unit(unit)  # type: ignore[arg-type]
        finding, frozen, obligation, s5 = built.units[freeze_index]
        with pytest.raises(WriteRefused):
            store.create(finding)  # type: ignore[arg-type]
        assert store.enumerate(FindingRecord) == ()
        with pytest.raises(WriteRefused):
            store.create_unit((frozen, obligation))  # type: ignore[arg-type]
        store.create_unit((finding, frozen, obligation, s5))  # type: ignore[arg-type]
        assert store.enumerate(FindingRecord) == (finding,)


CRASH_CHILD = """
import os, signal, sys
from pathlib import Path
from gpauto.store import open_store
import st03_world, st03_ingest
store = open_store(Path(sys.argv[1]))
built = st03_world.world("-crash")
st03_ingest.ingest(store.path, built.ingest)
store.create_unit(built.units[0])
def unit():
    yield built.units[1][0]
    yield built.units[1][1]
    os.kill(os.getpid(), signal.SIGKILL)
store.create_unit(unit())
"""


@pytest.mark.traces("ST03-R1", "ST03-T2")
@pytest.mark.traces("SC03-V12")
def test_a_process_killed_inside_a_unit_leaves_nothing_and_committed_units_survive() -> None:
    """`CW-2`, `EB-3a`, Class A: a real `SIGKILL` between the inserts of one unit. After
    restart the committed units are whole, the interrupted unit is absent, nothing is
    torn, and the store still opens under its exact schema."""
    with tempfile.TemporaryDirectory(prefix="gpauto-st03-crash-") as directory:
        path = Path(directory) / "coordination.sqlite"
        store_module.create_store(path).close()
        environment = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                [str(REPOSITORY_ROOT / "src"), str(REPOSITORY_ROOT / "tests_gpauto")]
            ),
        }
        result = subprocess.run(
            [sys.executable, "-c", CRASH_CHILD, str(path)],
            env=environment,
            capture_output=True,
            check=False,
        )
        assert result.returncode == -9, result.stderr.decode()
        reopened = store_module.open_store(path)
        try:
            built = st03_world.world("-crash")
            assert len(reopened.enumerate(Project)) == 1
            (preimage,) = built.units[0]
            assert reopened.enumerate(type(preimage)) == (preimage,)
            assert reopened.enumerate(RootResolutionRecord) == ()
            connection = raw(reopened)
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
            connection.close()
        finally:
            reopened.close()


# --- restart, pragmas, identity stability ------------------------------------------------


@pytest.mark.traces("ST03-R1", "ID-7", "RC-21")
def test_every_record_survives_close_and_reopen_with_identity_and_bytes_unchanged() -> None:
    """`EB-3`, `ID-7`, `ID-10`: after close and re-open every record reads back equal, every
    identity is the one written, and a stored canonical preimage is the bytes stored —
    re-read as bytes, never re-serialized from an object (`RC-21`, `DC-4`)."""
    with tempfile.TemporaryDirectory(prefix="gpauto-st03-") as directory:
        path = Path(directory) / "coordination.sqlite"
        built = st03_world.world()
        with store_module.create_store(path) as store:
            st03_world.populate(store, built)
        with store_module.open_store(path) as reopened:
            for record in built.records():
                stored = reopened.enumerate(type(record))
                assert record in stored, type(record).__name__
            content = built.handles["content"]
            (stored_content,) = [r for r in reopened.enumerate(type(content)) if r == content]
            assert stored_content.canonical_preimage == content.canonical_preimage  # type: ignore[attr-defined]


@pytest.mark.traces("ST03-D5")
def test_the_store_runs_under_the_frozen_pragmas() -> None:
    """`EB-13`: WAL, `synchronous=FULL`, foreign keys on, a bounded busy timeout."""
    with fresh_store() as store:
        assert store.effective_pragmas() == {
            "journal_mode": "wal",
            "synchronous": 2,
            "foreign_keys": 1,
            "busy_timeout": 10000,
            "recursive_triggers": 1,
        }
        connection = raw(store)
        strict = {str(r[1]) for r in connection.execute("PRAGMA table_list") if r[5] == 1}
        connection.close()
        assert set(_tables(store)) <= strict


# --- stale schema: refused, never migrated, never re-created -------------------------------


def _alter(path: Path, statement: str) -> None:
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute(statement)
    finally:
        connection.close()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _refused_after(alteration: str) -> None:
    with tempfile.TemporaryDirectory(prefix="gpauto-st03-") as directory:
        path = Path(directory) / "coordination.sqlite"
        store_module.create_store(path).close()
        _alter(path, alteration)
        before = _digest(path)
        with pytest.raises(StaleSchemaRefused, match="no migration path"):
            store_module.open_store(path)
        assert _digest(path) == before


@pytest.mark.traces("AP11-I69", "ST03-N5", "ST03-A2")
@pytest.mark.traces("SC03-V11")
def test_a_store_under_another_storage_version_is_refused_and_left_untouched() -> None:
    """`VM-5`, `VM-8`, `SRB11-14`: an older or newer storage version is refused as
    unavailable — never migrated, upgraded or partially read — and not written to. Version
    1 is the unaccepted candidate whose `RC-36` was keyed on the parent stage alone: it is
    refused like any other, and no v1 reader or v1 → v2 path exists."""
    assert store_schema.STORAGE_VERSION == 3
    for version in (1, 2, 0, 4):
        _refused_after(f"PRAGMA user_version = {version}")
    with tempfile.TemporaryDirectory(prefix="gpauto-st03-") as directory:
        path = Path(directory) / "coordination.sqlite"
        store_module.create_store(path).close()
        with store_module.open_store(path) as reopened:
            assert reopened.effective_pragmas()["recursive_triggers"] == 1
        connection = sqlite3.connect(path)
        try:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        finally:
            connection.close()


@pytest.mark.traces("AP11-I69", "ST03-N5", "ST03-A2")
def test_a_store_under_an_altered_structure_is_refused_and_left_untouched() -> None:
    """`SRB11-13`: an added table, a missing trigger or a missing index is a different
    schema, refused however the version reads — never re-created or repaired."""
    for alteration in (
        "CREATE TABLE rc99_unknown (x TEXT) STRICT",
        "DROP TRIGGER rc34_m1_position_entry__no_update",
        "DROP INDEX rc34_m1_position_entry__unique_1",
    ):
        _refused_after(alteration)


@pytest.mark.traces("AP11-I69", "ST03-N5")
def test_an_absent_empty_or_foreign_store_is_never_created_over() -> None:
    """A missing location is unavailable, not a new store; an empty or foreign file is
    refused, not initialized; `create_store` never lays a schema over an existing file."""
    with tempfile.TemporaryDirectory(prefix="gpauto-st03-") as directory:
        missing = Path(directory) / "absent.sqlite"
        with pytest.raises(StoreUnavailable):
            store_module.open_store(missing)
        assert not missing.exists()
        empty = Path(directory) / "empty.sqlite"
        empty.write_bytes(b"")
        with pytest.raises(StaleSchemaRefused):
            store_module.open_store(empty)
        assert empty.read_bytes() == b""
        with pytest.raises(StoreUnavailable):
            store_module.create_store(empty)
        assert empty.read_bytes() == b""
        foreign = Path(directory) / "foreign.sqlite"
        _alter(foreign, "CREATE TABLE governance (x TEXT)")
        before = _digest(foreign)
        with pytest.raises(StaleSchemaRefused):
            store_module.open_store(foreign)
        assert _digest(foreign) == before


@pytest.mark.traces("AP11-I69", "AP11-I68", "ST03-N5")
def test_the_schema_is_pinned_to_its_version() -> None:
    """`SRB11-13`: any change to the table or constraint set is a new version. The DDL's
    digest is pinned against the version it belongs to, so a changed schema that kept
    its version fails here rather than passing the stale-schema check silently.

    Version 3 implements ST03C-1. The exact schema content is asserted independently
    before comparing its pinned digest."""
    test_st03c1_schema_content_before_digest()
    statements = store_schema.schema_statements(store_schema.build_catalogue())
    (rc36,) = [s for s in statements if s.startswith(f"CREATE TABLE {RC36} ")]
    assert f"PRIMARY KEY ({', '.join(RC36_KEY)})" in rc36
    digest = hashlib.sha256("\n;\n".join(statements).encode("utf-8")).hexdigest()
    assert store_schema.SCHEMA_VERSION == "gpauto.coordination-store/3"
    assert store_schema.STORAGE_VERSION == 3
    assert digest == PINNED_SCHEMA_DIGEST


PINNED_SCHEMA_DIGEST = "e0f8eabf489462843fe9b8966511bb94a7e18f2aa358193d0be488f0dc84f7c6"


# --- placement: PB-2(i), and (iv) by derivation from it -------------------------------------


def _outside(path: Path, boundary: Path) -> bool:
    return not path.resolve().is_relative_to(boundary.resolve())


@pytest.mark.traces("ST03-P1", "PB-2(i)", "PB-2(iv)")
def test_the_store_is_placed_by_location_outside_the_governed_repository() -> None:
    """`PB-2`(i), verified **by location** (`SRB11-27`): every file the store has — the
    database and the engine's own sidecars — resolves outside the governed repository,
    `.coord/` and `.git/` included, by path containment alone, relying on no exclude,
    ignore rule, untrackedness or permission (`PB-8`, `HF-3`). `PB-2`(iv) follows (`SRB11-28`):
    what is outside the governed repository boundary is outside the entry-state
    observation scope and the stage-delta scope, whose subject that boundary is
    (AP-09 `OB9-5`, `OB9-6`)."""
    with fresh_store() as store:
        store.create_unit(())
        connection = raw(store)
        database = Path(connection.execute("PRAGMA database_list").fetchone()[2])
        connection.close()
        files = [database, *database.parent.glob(database.name + "-*")]
        assert any(f.name.endswith("-wal") for f in files)
        for boundary in (REPOSITORY_ROOT, REPOSITORY_ROOT / ".coord", REPOSITORY_ROOT / ".git"):
            assert all(_outside(f, boundary) for f in files), boundary
        assert database.resolve() == store.path.resolve()


@pytest.mark.traces("ST03-P2")
def test_the_store_has_no_default_location_and_writes_only_where_it_is_placed() -> None:
    """`SRB11-26`, `PB-5`: no path constant exists in the store's modules; the store opens
    only a supplied location and writes nothing beside it but its own sidecars."""
    for module in (store_module, store_schema, minting):
        assert module.__file__ is not None
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not node.value.endswith((".sqlite", ".db")), node.value
                assert not node.value.startswith(("/", "~")), node.value
    with tempfile.TemporaryDirectory(prefix="gpauto-st03-") as directory:
        root = Path(directory)
        with store_module.create_store(root / "c.sqlite") as store:
            st03_world.populate(store, st03_world.world())
        assert {p.name for p in root.iterdir()} <= {"c.sqlite", "c.sqlite-wal", "c.sqlite-shm"}


# --- identity: minting, shape, sharing ---------------------------------------------------


@pytest.mark.traces("ID-3", "ID-4", "ID-5")
def test_minted_values_are_opaque_hex_and_validated_by_shape_only() -> None:
    """`ID-3`, `ID-4`, `ID-5`: a minted value is 32 lowercase hex from `uuid4` — no time,
    sequence or content in it — and the store checks its shape and nothing more: a value
    that is not 32 lowercase hex is refused, and a well-shaped value whose version bits
    are not 4 is accepted. The store itself never mints (`AP03-I27`)."""
    values = {minting.mint_value() for _ in range(256)}
    assert len(values) == 256
    assert all(len(v) == 32 and set(v) <= set("0123456789abcdef") for v in values)
    assert sorted(values) != [minting.mint_value() for _ in range(256)]
    store_source = Path(store_module.__file__ or "").read_text(encoding="utf-8")
    assert "uuid" not in store_source and "mint_value" not in store_source
    with populated_store() as (store, built):
        resolution = built.handles["resolution"]
        assert isinstance(resolution, RootResolutionRecord)
        for bad in ("RES-1", "A" * 32, "0" * 31, "g" * 32):
            with pytest.raises(WriteRefused):
                store.create(
                    resolution.model_copy(update={"identity": RootResolutionId(value=bad)})
                )
        not_v4 = "0" * 12 + "1" + "0" * 19
        a2 = built.handles["a2"]
        assert isinstance(a2, M1PositionEntry)
        store.create(
            resolution.model_copy(
                update={
                    "identity": RootResolutionId(value=not_v4),
                    "predecessor_terminal_entry": Present[M1PositionEntryId](value=a2.identity),
                }
            )
        )


@pytest.mark.traces("ID-14", "AP03-I19")
def test_identical_content_is_shared_and_two_productions_are_never_merged() -> None:
    """`ID-14`, `AT-3`, `AP03-I19`: two productions of identical bytes share one content
    record and remain two production records, each with its own provenance; no key over
    content exists, and a basis reference cannot name the worker-authored one as
    objective, even through a raw connection (`AT-8`)."""
    with populated_store() as (store, built):
        productions = store.enumerate(ArtifactProductionRecord)
        assert len(productions) == 2
        first, second = (p.production for p in productions)  # type: ignore[union-attr]
        assert first.content == second.content and first.identity != second.identity
        assert {first.provenance, second.provenance} == {"OBJECTIVE", "WORKER_AUTHORED"}
        worker = built.handles["worker_copy"]
        assert isinstance(worker, ArtifactProductionRecord)
        package = built.handles["package"]
        assert _refused_raw(
            store,
            "INSERT INTO rc20_input_package__package__authoritative_inputs "
            "(package__identity, tuple_slot, element__kind, "
            "element__ObjectiveProductionReference__production__identity, "
            "element__ObjectiveProductionReference__production__provenance) "
            "VALUES (?, 9, 'ObjectiveProductionReference', ?, 'OBJECTIVE')",
            package.package.identity.value,  # type: ignore[attr-defined]
            worker.production.identity.value,
        )
        connection = raw(store)
        indexes = connection.execute("PRAGMA index_list(rc22_artifact_production)").fetchall()
        for index in indexes:
            columns = [r[2] for r in connection.execute(f"PRAGMA index_info({index[1]})")]
            assert "production__content" not in columns
        connection.close()


# --- forbidden and derived fields: absent -------------------------------------------------

FORBIDDEN_COLUMN_WORDS = (
    "signature", "signed", "certificate", "attestation", "hash_chain", "merkle",
    "ttl", "expiry", "expires", "deadline", "freshness", "timestamp", "clock",
    "retry", "attempt", "counter", "status", "current", "latest", "superseded",
    "preferred", "effective", "token", "transcript", "memory", "cache", "reasoning",
    "thought", "cycle_bound", "closure_scope", "expected_current", "force",
    "decision_package", "successor", "next_authorization", "rank", "severity",
    "priority", "completed", "within_producing_envelope",
)  # fmt: skip


@pytest.mark.traces("ST03-N6", "EQ-7", "AP11-I73")
def test_no_forbidden_or_derived_field_is_stored_anywhere() -> None:
    """`RC-50` … `RC-61` and `SRB11-7`: no signature, expiry, retry count, status,
    current-state, stored-derivation, succession, session-continuity or triage column
    exists on any table; the three accepted ST-01 derived fields — `completed`,
    `within_producing_envelope`, and a resolution's `outcome` / `resolved_root` /
    `ambiguity` — are persisted nowhere as authority; and no column holds an equivalence
    normal form or digest (`EQ-7`)."""
    with fresh_store() as store:
        connection = raw(store)
        try:
            for table in _tables(store):
                for column in _columns(connection, table):
                    lowered = column.lower()
                    for word in FORBIDDEN_COLUMN_WORDS:
                        assert word not in lowered, (table, column)
                    assert "normal" not in lowered and "digest" not in lowered, (table, column)
            rc14 = set(_columns(connection, "rc14_root_resolution"))
            assert rc14.isdisjoint({"outcome", "resolved_root", "ambiguity"})
        finally:
            connection.close()
    assert "completed" not in WorkerActivationRecord.model_fields
    assert "within_producing_envelope" not in ActivationEffectRecord.model_fields


@pytest.mark.traces("ST03-G1")
def test_the_store_imports_no_engine_and_no_spike_module() -> None:
    """`EB-6`: the decision layer imports no engine; `EB-14`(iii): no `gplanner` module."""
    for module in (store_module, store_schema, minting):
        assert module.__file__ is not None
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            for name in names:
                assert name.split(".")[0] not in {"dbos", "gplanner", "sqlalchemy"}, name


# ST01C-2 / ST03C-1: schema content is asserted before its digest is accepted.
RC13 = "rc13_owner_decision"
F9 = "act__StageOutcomeDecision"
O6 = "act__ObligationChangeDecision"
DECISION_FORMS = {
    "AuthorizingDecision": (
        "STAGE_ENTRY_AUTHORIZATION",
        "NEXT_STAGE_AUTHORIZATION",
        "SCOPE_CHANGE",
        "AUTHORITY_EXPANSION",
    ),
    "DisputeResolutionDecision": ("FINDING_DISPUTE",),
    "ObligationExtinguishingDecision": ("WAIVER", "DEFERRAL"),
    "ObligationChangeDecision": ("OBLIGATION_CHANGE",),
    "RevocationDecision": ("REVOCATION",),
    "RefusalResolutionDecision": ("REFUSAL_RESOLUTION",),
    "StageOutcomeDecision": ("STAGE_OUTCOME",),
    "ExceptionalRecoveryDecision": ("EXCEPTIONAL_RECOVERY",),
}


def _foreign_keys(
    connection: sqlite3.Connection, table: str
) -> set[tuple[tuple[str, ...], str, tuple[str, ...]]]:
    grouped: dict[int, list[tuple[object, ...]]] = {}
    for row in connection.execute(f"PRAGMA foreign_key_list({table})"):
        grouped.setdefault(row[0], []).append(row)
    return {
        (tuple(str(r[3]) for r in rows), str(rows[0][2]), tuple(str(r[4]) for r in rows))
        for rows in grouped.values()
    }


def assert_v3_schema(connection: sqlite3.Connection) -> None:
    """Independent schema-content oracle; redundant guards are checked separately."""
    from typing import get_args

    from gpauto.governance import DecisionAct

    schema = {
        str(name): str(sql)
        for name, sql in connection.execute(
            "SELECT name, sql FROM sqlite_schema WHERE sql IS NOT NULL"
        )
    }
    ddl = schema[RC13]
    assert store_schema.SCHEMA_VERSION == "gpauto.coordination-store/3"
    assert store_schema.STORAGE_VERSION == 3
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
    assert set(DECISION_FORMS) == {
        store_schema.variant_tag(form) for form in get_args(DecisionAct.__value__)
    }
    tags = ", ".join(f"'{tag}'" for tag in DECISION_FORMS)
    assert f"CHECK (act__kind IN ({tags}))" in ddl
    assert "STAGE_OUTCOME_ACCEPTANCE" not in "\n".join(schema.values())
    foreign = _foreign_keys(connection, RC13)
    # Independent per-column presence and closed-state/value checks. Every generated
    # variant column is required exactly under its enclosing discriminator choices.
    for tag in DECISION_FORMS:
        prefix = f"act__{tag}__"
        for column in _columns(connection, RC13):
            if not column.startswith(prefix):
                continue
            condition = f"act__kind = '{tag}'"
            tail = column.removeprefix(prefix)
            for field in ("corrects", "produced_authorization"):
                for variant in ("Present", "KnownAbsent"):
                    if tail.startswith(f"{field}__{variant}__"):
                        condition += f" AND {prefix}{field}__kind = '{variant}'"
            assert f"CHECK (COALESCE({condition}, 0) = ({column} IS NOT NULL))" in ddl
            if column.endswith("corrects__kind"):
                assert f"CHECK ({column} IN ('Present', 'KnownAbsent'))" in ddl
    outcomes = "'ACCEPTED', 'REFUSED', 'ABANDONED', 'ACCEPT_PARTIAL'"
    assert f"CHECK ({F9}__outcome IN ({outcomes}))" in ddl
    assert f"CHECK (disposition IN ({outcomes}))" in schema[RC36]
    for tag, kinds in DECISION_FORMS.items():
        prefix = f"act__{tag}"
        tokens = ", ".join(f"'{kind}'" for kind in kinds)
        assert f"CHECK ({prefix}__kind IN ({tokens}))" in ddl
        if tag == "ObligationChangeDecision":
            assert f"{prefix}__corrects" not in ddl
            continue
        value = f"{prefix}__corrects__Present__value"
        assert f"CHECK ({value} IS NULL OR {value} <> identity)" in ddl
        assert ((value,), RC13, ("identity",)) in foreign
        assert f"{RC13}__prior__{tag}" in schema
        trigger = schema[f"{RC13}__prior__{tag}"]
        assert f"BEFORE INSERT ON {RC13}" in trigger
        assert f"WHEN NEW.{value} IS NOT NULL AND NOT EXISTS " in trigger
        assert f"(SELECT 1 FROM {RC13} WHERE identity = NEW.{value})" in trigger
        assert "RAISE(ABORT," in trigger
    assert (
        f"CHECK ({O6}__replacement_requirement IS NULL OR "
        f"length(CAST({O6}__replacement_requirement AS BLOB)) > 0)" in ddl
    )
    expected = {
        (("act__DisputeResolutionDecision__member",), "rc25_finding", ("finding__identity",)),
        (
            ("act__DisputeResolutionDecision__member",),
            "rc26_frozen_finding_set__members",
            ("element",),
        ),
        (
            ("act__RefusalResolutionDecision__halt_occurrence",),
            "rc31_halt_occurrence",
            ("identity",),
        ),
        (
            (f"{F9}__context__authorization", f"{F9}__context__entry_boundary"),
            "rc17_entry_state_boundary",
            ("resolved_root", "boundary__identity"),
        ),
    }
    for tag in ("ObligationExtinguishingDecision", "ObligationChangeDecision"):
        expected.add(
            (
                (
                    f"act__{tag}__obligation__parent_frozen_set",
                    f"act__{tag}__obligation__member_finding",
                ),
                "rc27_remediation_obligation",
                ("identity__parent_frozen_set", "identity__member_finding"),
            )
        )
    assert expected <= foreign
    for table, columns, target in (
        (
            "rc32_governance_event_resolution",
            ("decision", "halt_occurrence"),
            ("identity", "act__RefusalResolutionDecision__halt_occurrence"),
        ),
        (
            "rc35_disposition_establishing_record",
            ("disposition__RevokedDisposition__established_by_decision", "identity__authorization"),
            ("identity", "act__RevocationDecision__revoked"),
        ),
        (
            RC36,
            ("established_by", "identity__parent_stage", "disposition"),
            ("identity", "stage", f"{F9}__outcome"),
        ),
    ):
        assert (columns, RC13, target) in _foreign_keys(connection, table)
    for table in (RC13, RC36):
        for row in connection.execute(f"PRAGMA index_list({table})"):
            if row[2]:
                cols = tuple(r[2] for r in connection.execute(f"PRAGMA index_info('{row[1]}')"))
                assert "identity" in cols if table == RC13 else set(RC36_KEY) <= set(cols)
    rc35 = schema["rc35_disposition_establishing_record"]
    assert "SuspendedDisposition__established_by_event__AuthorityAmbiguityId" not in rc35
    for event in ("RefusalId", "EnvelopeViolationId", "UnaccountedMutationId"):
        assert f"SuspendedDisposition__established_by_event__{event}" in rc35
    for trigger_name, fragments in {
        f"{RC13}__no_outcome_succession": (
            "BEFORE INSERT",
            "NEXT_STAGE_AUTHORIZATION",
            "STAGE_OUTCOME",
            "RAISE(ABORT,",
            "NEW.act__AuthorizingDecision__corrects__Present__value",
            "NEW.act__StageOutcomeDecision__corrects__Present__value",
        ),
        "rc35_disposition_establishing_record__consumed_context": (
            "BEFORE INSERT",
            "ConsumedDisposition",
            "rc36_stage_outcome",
            RC13,
            f"{F9}__context__authorization = NEW.identity__authorization",
            "RAISE(ABORT,",
        ),
    }.items():
        assert trigger_name in schema
        for fragment in fragments:
            assert fragment in schema[trigger_name]
    for column in (
        "act__AuthorizingDecision__produced_authorization__value",
        "act__ExceptionalRecoveryDecision__produced_authorization__Present__value",
        "act__RevocationDecision__revoked",
    ):
        assert f"{RC13}__instance__{column}" in schema
    for table in (
        RC13,
        RC36,
        "rc32_governance_event_resolution",
        "rc35_disposition_establishing_record",
    ):
        for operation in ("update", "delete"):
            assert f"{table}__no_{operation}" in schema
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.traces("ST03-D1", "ST03-T3", "RC-13", "RC-32", "RC-35", "RC-36")
@pytest.mark.traces("SC01-V14", "SC03-V2", "SC03-V10", "SC03-V11")
def test_st03c1_schema_content_before_digest() -> None:
    with fresh_store() as store, st03_ingest.external_connection(store.path) as connection:
        assert_v3_schema(connection)


def _bundle_decisions(built: st03_world.World) -> tuple[OwnerDecision, ...]:
    import fixtures
    from gpauto.coordination_records import HaltOccurrence
    from gpauto.governance import (
        DisputeResolutionDecision,
        ObligationChangeDecision,
        ObligationExtinguishingDecision,
        RefusalResolutionDecision,
        RevocationDecision,
    )
    from gpauto.repository import ClassificationContext

    boundary = built.handles["boundary"]
    halt = built.handles["halt"]
    obligation = built.one_of(RemediationObligation)
    assert isinstance(boundary, EntryStateBoundaryRecord)
    assert isinstance(halt, HaltOccurrence)
    assert isinstance(obligation, RemediationObligation)
    (accepted,) = [
        d
        for rows in built.deferred_ingest.values()
        for d in rows
        if isinstance(d.act, StageOutcomeDecision)
    ]
    decisions = []
    for decision in fixtures.corrective_decisions():
        act = decision.act
        changes: dict[str, object] = {}
        if isinstance(act.produced_authorization, Present):
            changes["produced_authorization"] = Present(value=boundary.resolved_root)
        if isinstance(act, ObligationChangeDecision | ObligationExtinguishingDecision):
            changes["obligation"] = obligation.identity
        elif isinstance(act, DisputeResolutionDecision):
            changes["member"] = obligation.identity.member_finding
        elif isinstance(act, RevocationDecision):
            changes["revoked"] = boundary.resolved_root
        elif isinstance(act, RefusalResolutionDecision):
            changes["halt_occurrence"] = halt.identity
        elif isinstance(act, StageOutcomeDecision):
            changes["context"] = ClassificationContext(
                authorization=boundary.resolved_root, entry_boundary=boundary.boundary.identity
            )
        decisions.append(
            decision.model_copy(
                update={"stage": accepted.stage, "act": act.model_copy(update=changes)}
            )
        )
    return tuple(decisions)


def _insert_decision_rows(connection: sqlite3.Connection, *rows: dict[str, object]) -> None:
    columns = sorted(set().union(*(row.keys() for row in rows)))
    placeholders = "(" + ", ".join("?" for _ in columns) + ")"
    connection.execute(
        f"INSERT INTO {RC13} ({', '.join(columns)}) VALUES "
        + ", ".join(placeholders for _ in rows),
        [row.get(column) for row in rows for column in columns],
    )


def _refused_decision_rows(connection: sqlite3.Connection, *rows: dict[str, object]) -> None:
    before = tuple(connection.iterdump())
    with pytest.raises(sqlite3.IntegrityError):
        _insert_decision_rows(connection, *rows)
    assert tuple(connection.iterdump()) == before


@pytest.mark.traces("RC-13", "ST03-T1", "ST03-N3")
@pytest.mark.traces("SC03-V1", "SC03-V3", "SC03-V6", "SC03-V7")
def test_st03c1_all_kinds_forms_presence_and_referents() -> None:
    """SC03-V1/V3/V6/V7: direct SQL cannot bypass the closed physical form."""
    with populated_store() as (store, built), st03_ingest.external_connection(store.path) as conn:
        decisions = _bundle_decisions(built)
        assert {d.act.kind for d in decisions} == set(OwnerDecisionKind)
        rows = [st03_ingest._decision_row(d) for d in decisions]
        for decision, row in zip(decisions, rows, strict=True):
            st03_ingest.ingest(store.path, (decision,))
            assert store.read(OwnerDecision, decision.identity) == decision
            duplicate = {**row, "identity": f"duplicate-{row['identity']}"}
            _insert_decision_rows(conn, duplicate)  # referents are intentionally not unique
            for column in row:
                if column not in ("identity", "record_format"):
                    _refused_decision_rows(conn, {**duplicate, "identity": "missing", column: None})
            for tag in DECISION_FORMS:
                if tag != row["act__kind"]:
                    _refused_decision_rows(
                        conn, {**duplicate, "identity": "wrong-form", "act__kind": tag}
                    )
            for other in rows:
                if other["act__kind"] != row["act__kind"]:
                    kind_column = f"act__{other['act__kind']}__kind"
                    _refused_decision_rows(
                        conn,
                        {
                            **other,
                            "identity": "wrong-kind-in-complete-form",
                            kind_column: row[f"act__{row['act__kind']}__kind"],
                        },
                    )
                for column, value in other.items():
                    if column.startswith("act__") and column not in row:
                        _refused_decision_rows(
                            conn, {**duplicate, "identity": "stray", column: value}
                        )
            for columns, target, _ in _foreign_keys(conn, RC13):
                if target == RC13:
                    continue
                if all(row.get(column) is not None for column in columns):
                    _refused_decision_rows(
                        conn, {**duplicate, "identity": "dangling", columns[0]: "0" * 32}
                    )
            for column in row:
                if column.endswith("produced_authorization__value") or column.endswith("__revoked"):
                    _refused_decision_rows(
                        conn,
                        {**duplicate, "identity": "missing-instance", column: "missing-instance"},
                    )


@pytest.mark.traces("RC-13", "ST03-T3", "ST03-N3")
@pytest.mark.traces("SC03-V4")
def test_st03c1_o6_exact_unicode_and_empty_string() -> None:
    from gpauto.governance import ObligationChangeDecision

    with populated_store() as (store, built), st03_ingest.external_connection(store.path) as conn:
        base = next(
            d for d in _bundle_decisions(built) if isinstance(d.act, ObligationChangeDecision)
        )
        for index, value in enumerate(("\0", "\0requirement", "inside\0text", " e\u0301 漢字\n")):
            decision = base.model_copy(
                update={
                    "identity": OwnerDecisionId(value=f"o6-{index}"),
                    "act": base.act.model_copy(update={"replacement_requirement": value}),
                }
            )
            st03_ingest.ingest(store.path, (decision,))
            assert store.read(OwnerDecision, decision.identity) == decision
            assert (
                conn.execute(
                    f"SELECT {O6}__replacement_requirement FROM {RC13} WHERE identity=?",
                    (decision.identity.value,),
                ).fetchone()[0]
                == value
            )
        row = st03_ingest._decision_row(base)
        _refused_decision_rows(conn, {**row, f"{O6}__replacement_requirement": ""})


@pytest.mark.traces("RC-13", "ST03-T3", "ST03-N3", "AP03-I25")
@pytest.mark.traces("SC01-V14", "SC01-V16", "SC03-V5")
def test_st03c1_corrections_prior_targets_cycles_and_sa9_2() -> None:
    from gpauto.governance import ObligationChangeDecision

    with populated_store() as (store, built), st03_ingest.external_connection(store.path) as conn:
        decisions = _bundle_decisions(built)
        st03_ingest.ingest(store.path, decisions)
        for base in decisions:
            if isinstance(base.act, ObligationChangeDecision):
                continue
            prior_bytes = store.read(OwnerDecision, base.identity)
            for index in range(2):
                correction = base.model_copy(
                    update={
                        "identity": OwnerDecisionId(value=f"correction-{base.act.kind}-{index}"),
                        "act": base.act.model_copy(
                            update={"corrects": Present(value=base.identity)}
                        ),
                    }
                )
                st03_ingest.ingest(store.path, (correction,))
                assert store.read(OwnerDecision, correction.identity) == correction
            assert store.read(OwnerDecision, base.identity) == prior_bytes
            # SC01-V14: in-memory self-reference is structural; authoritative ingest refuses.
            for identity in (OwnerDecisionId(value="missing"), base.identity):
                changed = base.model_copy(
                    update={
                        "identity": OwnerDecisionId(value="self"),
                        "act": base.act.model_copy(update={"corrects": Present(value=identity)}),
                    }
                )
                if identity == base.identity:
                    changed = changed.model_copy(
                        update={
                            "act": changed.act.model_copy(
                                update={"corrects": Present(value=changed.identity)}
                            )
                        }
                    )
                before = tuple(conn.iterdump())
                with pytest.raises(sqlite3.IntegrityError):
                    st03_ingest.ingest(store.path, (changed,))
                assert tuple(conn.iterdump()) == before
            row = st03_ingest._decision_row(base)
            prefix = f"act__{type(base.act).__name__}__corrects"
            present = {k: v for k, v in row.items() if not k.startswith(prefix)}
            present.update({f"{prefix}__kind": "Present", f"{prefix}__Present__state": "PRESENT"})
            first = {**present, "identity": "first", f"{prefix}__Present__value": "second"}
            second = {**row, "identity": "second"}
            _refused_decision_rows(conn, first, second)  # forward reference, same statement
            _refused_decision_rows(
                conn, first, {**present, "identity": "second", f"{prefix}__Present__value": "first"}
            )
            # Earlier rows in the same statement are permissible prior targets.
            _insert_decision_rows(
                conn,
                {**row, "identity": f"early-{base.act.kind}"},
                {
                    **present,
                    "identity": f"later-{base.act.kind}",
                    f"{prefix}__Present__value": f"early-{base.act.kind}",
                },
            )
        next_stage = next(
            d for d in decisions if d.act.kind == OwnerDecisionKind.NEXT_STAGE_AUTHORIZATION
        )
        outcome = next(d for d in decisions if isinstance(d.act, StageOutcomeDecision))
        for source, target in ((next_stage, outcome), (outcome, next_stage)):
            correction = source.model_copy(
                update={
                    "identity": OwnerDecisionId(value="prohibited"),
                    "act": source.act.model_copy(
                        update={"corrects": Present(value=target.identity)}
                    ),
                }
            )
            _refused_decision_rows(conn, st03_ingest._decision_row(correction))
            forward_id = OwnerDecisionId(value="forward-target")
            correction = correction.model_copy(
                update={
                    "act": correction.act.model_copy(update={"corrects": Present(value=forward_id)})
                }
            )
            later = target.model_copy(update={"identity": forward_id})
            _refused_decision_rows(
                conn, st03_ingest._decision_row(correction), st03_ingest._decision_row(later)
            )


@pytest.mark.traces("RC-13", "RC-26", "ST03-N3")
@pytest.mark.traces("SC03-V1")
def test_st03c1_dispute_requires_membership_and_keeps_finding_fk() -> None:
    """OBS_ST03_1_IMPLEMENTATION_DETAIL: both native relationships survive."""
    from gpauto.governance import DisputeResolutionDecision
    from gpauto.identity import FindingId

    with populated_store() as (store, built), st03_ingest.external_connection(store.path) as conn:
        base = next(
            d for d in _bundle_decisions(built) if isinstance(d.act, DisputeResolutionDecision)
        )
        st03_ingest.ingest(store.path, (base,))
        assert store.read(OwnerDecision, base.identity) == base
        finding = built.one_of(FindingRecord)
        assert isinstance(finding, FindingRecord)
        nonmember = finding.model_copy(
            update={
                "finding": finding.finding.model_copy(
                    update={"identity": FindingId(value=minting.mint_value())}
                )
            }
        )
        # RC-25's membership FK is deferred: the finding can exist within this
        # transaction before membership, but F-4 must reject it immediately.
        conn.execute("BEGIN IMMEDIATE")
        layout = store_schema.build_catalogue().by_record[FindingRecord]
        finding_row, children = store_schema.flatten(layout, nonmember)
        assert not any(children.values())
        st03_ingest._insert(conn, layout.name, finding_row)
        row = st03_ingest._decision_row(base)
        _refused_decision_rows(
            conn,
            {
                **row,
                "identity": "nonmember-dispute",
                "act__DisputeResolutionDecision__member": nonmember.finding.identity.value,
            },
        )
        conn.execute("ROLLBACK")
        foreign = _foreign_keys(conn, RC13)
        assert (
            ("act__DisputeResolutionDecision__member",),
            "rc25_finding",
            ("finding__identity",),
        ) in foreign
        assert (
            ("act__DisputeResolutionDecision__member",),
            "rc26_frozen_finding_set__members",
            ("element",),
        ) in foreign


def _refused_record(store: store_module.CoordinationStore, record: BaseModel) -> None:
    with st03_ingest.external_connection(store.path) as conn:
        before = tuple(conn.iterdump())
        with pytest.raises(WriteRefused):
            store.create(record)  # type: ignore[arg-type]
        assert tuple(conn.iterdump()) == before


@pytest.mark.traces("RC-13", "RC-32", "RC-35", "RC-36", "ST03-N3")
@pytest.mark.traces("SC03-V1", "SC03-V8", "SC03-V9", "SC03-V10")
def test_st03c1_context_outcome_resolution_and_instance_agreement() -> None:
    from gpauto.authorization import RevokedDisposition, SuspendedDisposition
    from gpauto.coordination_identity import HaltOccurrenceId
    from gpauto.coordination_records import (
        EnvelopeViolationRecord,
        GovernanceEventResolution,
        HaltOccurrence,
    )
    from gpauto.governance import RevocationDecision
    from gpauto.identity import GovernedStageId
    from gpauto.repository import ClassificationContext

    with populated_store() as (store, built), st03_ingest.external_connection(store.path) as conn:
        decisions = _bundle_decisions(built)
        st03_ingest.ingest(store.path, decisions)
        first, second, consumed = _second_epoch(store, built)
        store.create(second)
        store.create(consumed)
        boundary = built.handles["boundary"]
        assert isinstance(boundary, EntryStateBoundaryRecord)
        outcome_decision = next(d for d in decisions if isinstance(d.act, StageOutcomeDecision))
        mismatch = outcome_decision.model_copy(
            update={
                "identity": OwnerDecisionId(value="bad-pair"),
                "act": outcome_decision.act.model_copy(
                    update={
                        "context": ClassificationContext(
                            authorization=consumed.identity.authorization,
                            entry_boundary=boundary.boundary.identity,
                        )
                    }
                ),
            }
        )
        _refused_decision_rows(conn, st03_ingest._decision_row(mismatch))
        _refused_record(
            store,
            consumed.model_copy(
                update={
                    "identity": DispositionRecordId(
                        authorization=boundary.resolved_root, discriminator=minting.mint_value()
                    )
                }
            ),
        )
        for index, value in enumerate(StageOutcomeDisposition):
            decision = outcome_decision.model_copy(
                update={
                    "identity": OwnerDecisionId(value=f"outcome-{index}"),
                    "act": outcome_decision.act.model_copy(update={"outcome": value}),
                }
            )
            st03_ingest.ingest(store.path, (decision,))
            assert store.read(OwnerDecision, decision.identity) == decision
            outcome = first.model_copy(
                update={
                    "identity": StageOutcomeId(
                        parent_stage=first.identity.parent_stage,
                        local_discriminator=f"all-values-{index}",
                    ),
                    "established_by": decision.identity,
                    "disposition": value,
                }
            )
            store.create(outcome)
            assert store.read(StageOutcome, outcome.identity) == outcome
            for wrong in StageOutcomeDisposition:
                if wrong != value:
                    _refused_record(
                        store,
                        outcome.model_copy(
                            update={
                                "identity": StageOutcomeId(
                                    parent_stage=first.identity.parent_stage,
                                    local_discriminator="wrong-value",
                                ),
                                "disposition": wrong,
                            }
                        ),
                    )
        other_stage = GovernedStageId(value="another-stage")
        stage = next(r for r in built.ingest if isinstance(r, GovernedStage))
        st03_ingest.ingest(store.path, (stage.model_copy(update={"identity": other_stage}),))
        _refused_record(
            store,
            first.model_copy(
                update={
                    "identity": StageOutcomeId(
                        parent_stage=other_stage, local_discriminator="wrong-stage"
                    )
                }
            ),
        )
        nonoutcome = next(d for d in decisions if isinstance(d.act, RevocationDecision))
        _refused_record(
            store,
            first.model_copy(
                update={
                    "identity": StageOutcomeId(
                        parent_stage=first.identity.parent_stage, local_discriminator="wrong-kind"
                    ),
                    "established_by": nonoutcome.identity,
                }
            ),
        )
        revoked = DispositionEstablishingRecord(
            identity=DispositionRecordId(
                authorization=boundary.resolved_root, discriminator=minting.mint_value()
            ),
            disposition=RevokedDisposition(established_by_decision=nonoutcome.identity),
        )
        store.create(revoked)
        _refused_record(
            store,
            revoked.model_copy(
                update={
                    "identity": DispositionRecordId(
                        authorization=consumed.identity.authorization,
                        discriminator=minting.mint_value(),
                    )
                }
            ),
        )
        _refused_record(
            store,
            revoked.model_copy(
                update={
                    "identity": DispositionRecordId(
                        authorization=boundary.resolved_root, discriminator=minting.mint_value()
                    ),
                    "disposition": RevokedDisposition(
                        established_by_decision=outcome_decision.identity
                    ),
                }
            ),
        )
        resolution = built.one_of(GovernanceEventResolution)
        halt = built.handles["halt"]
        assert isinstance(resolution, GovernanceEventResolution)
        assert isinstance(halt, HaltOccurrence)
        other_halt = halt.model_copy(
            update={"identity": HaltOccurrenceId(value=minting.mint_value())}
        )
        store.create(other_halt)
        for changes in (
            {"halt_occurrence": other_halt.identity},
            {"decision": nonoutcome.identity},
        ):
            _refused_record(
                store,
                resolution.model_copy(
                    update={
                        **changes,
                        "identity": type(resolution.identity)(value=minting.mint_value()),
                    }
                ),
            )
        violation = built.one_of(EnvelopeViolationRecord)
        mutation = built.handles["mutation"]
        assert isinstance(violation, EnvelopeViolationRecord)
        assert isinstance(mutation, UnaccountedMutation)
        for event in (halt.event, violation.violation.identity, mutation.identity):
            suspension = DispositionEstablishingRecord(
                identity=DispositionRecordId(
                    authorization=boundary.resolved_root, discriminator=minting.mint_value()
                ),
                disposition=SuspendedDisposition(established_by_event=event),
            )
            store.create(suspension)
            assert store.read(DispositionEstablishingRecord, suspension.identity) == suspension
        # Accepted act and outcome remain separate immutable records.
        assert store.read(OwnerDecision, first.established_by) is not None
        assert store.read(StageOutcome, first.identity) == first


@pytest.mark.traces("RC-13", "RC-17", "RC-31", "ST03-T1")
@pytest.mark.traces("SC03-V1")
def test_st03c1_world_inserts_decisions_after_authoritative_referents() -> None:
    """OBS_ST03_2_IMPLEMENTATION_DETAIL: same world facts, referential insertion order."""
    from gpauto.coordination_records import HaltOccurrence
    from gpauto.governance import RefusalResolutionDecision

    built = st03_world.world()
    seen: list[BaseModel] = list(built.ingest)
    with fresh_store() as store:
        st03_ingest.ingest(store.path, built.ingest)
        for index, unit in enumerate(built.units):
            for decision in built.deferred_ingest.get(index, ()):
                act = decision.act
                if isinstance(act, RefusalResolutionDecision):
                    assert any(
                        isinstance(r, HaltOccurrence) and r.identity == act.halt_occurrence
                        for r in seen
                    )
                elif isinstance(act, StageOutcomeDecision):
                    assert any(
                        isinstance(r, EntryStateBoundaryRecord)
                        and r.resolved_root == act.context.authorization
                        and r.boundary.identity == act.context.entry_boundary
                        for r in seen
                    )
                else:
                    pytest.fail("unexpected deferred decision")
                st03_ingest.ingest(store.path, (decision,))
                seen.append(decision)
            store.create_unit(unit)  # type: ignore[arg-type]
            seen.extend(unit)
        for record in seen:
            layout = store_schema.build_catalogue().by_record[type(record)]
            # Read-back equality for every fact, with the existing every-class test.
            assert record in store.enumerate(layout.spec.record)


@pytest.mark.traces("RC-13", "ST03-T1", "ST03-N3")
@pytest.mark.traces("SC03-V7")
def test_st03c1_exceptional_production_and_non_authorizing_absence() -> None:
    from gpauto.governance import ExceptionalRecoveryDecision

    with populated_store() as (store, built), st03_ingest.external_connection(store.path) as conn:
        decisions = _bundle_decisions(built)
        base = next(d for d in decisions if isinstance(d.act, ExceptionalRecoveryDecision))
        boundary = built.handles["boundary"]
        assert isinstance(boundary, EntryStateBoundaryRecord)
        for suffix, production in (
            ("absent", ABSENT),
            ("present", Present(value=boundary.resolved_root)),
        ):
            decision = base.model_copy(
                update={
                    "identity": OwnerDecisionId(value=suffix),
                    "act": base.act.model_copy(update={"produced_authorization": production}),
                }
            )
            st03_ingest.ingest(store.path, (decision,))
            assert store.read(OwnerDecision, decision.identity) == decision
        row = st03_ingest._decision_row(decision)
        _refused_decision_rows(
            conn,
            {
                **row,
                "identity": "missing-instance",
                (
                    "act__ExceptionalRecoveryDecision__produced_authorization__Present__value"
                ): "missing",
            },
        )
        for decision in decisions:
            if decision.act.produced_authorization == ABSENT:
                continue
            row = st03_ingest._decision_row(decision)
            for column in row:
                if (
                    column.endswith("produced_authorization__state")
                    and row[column] == "KNOWN_ABSENT"
                ):
                    _refused_decision_rows(
                        conn, {**row, "identity": "false-production", column: "PRESENT"}
                    )
