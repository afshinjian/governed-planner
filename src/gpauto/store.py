"""The authoritative coordination store: create-only, fail-closed, at a supplied location.

Design basis: AP-11 ST-03 store-realization amendment §7 (`SRB11-10`, `SRB11-11`), §8
(`SRB11-12`…`SRB11-17`), §9 (`SRB11-18`…`SRB11-24`), §10 (`SRB11-25`, `SRB11-26`); AP-07
§6 (`WP-1`, `WP-4`, `WP-11`, `WP-12`), §7 (`IM-1`…`IM-4`), §17 (`NP-4`, `NP-11`…`NP-13`),
§22.1 (`EB-1`…`EB-11`, `EB-2a`, `EB-3a`, `EB-13`), §23 (`VM-5`…`VM-8`, `VM-12`); AP-10 §5
(`PB-3`, `PB-5`, `PB-8`).

**The frozen `governance.sqlite` pattern, as a primitive** (`EB-13`): stdlib `sqlite3`, no
ORM, WAL, `synchronous=FULL`, `foreign_keys=ON`, a bounded `busy_timeout` (the spike's
10000 ms), STRICT tables, and refuse-on-stale-schema with no migration path. It is a
**separate database** from GP-SPK-001's `governance.sqlite` and from any engine database
(`EB-14`); this module imports no engine (`EB-6`) and no `gplanner` module.

**No default location** (`SRB11-26`, `PB-5`). A store is created or opened only at a path
its caller supplies; this module holds no path, directory or file name. Placement is
verified in tests against the governed repository boundary; it is not a runtime check,
and nothing here refuses a location for being where it is (`SRB11-25`).

**Creating and opening are two acts, and neither stands in for the other.** `create_store`
lays down the complete schema of `SCHEMA_VERSION` at a location where nothing exists, in
one transaction. `open_store` opens an existing store and **refuses** — `StaleSchemaRefused`,
a `StoreUnavailable` — unless its storage marker and its entire schema (every table,
column, constraint, index and trigger) are exactly this definition's. A missing file is
unavailable, never a new store; an older, newer or altered store is refused, never
migrated, upgraded, partially read, replaced or re-created (`SRB11-14`, `VM-5`, `VM-8`).
The refused file is not written to.

**The write surface is create-only** (`WP-4`, `EB-5`). `create` and `create_unit` insert,
and there is no update, replace, re-key, re-parent or delete operation for any class. A
unit is one `BEGIN IMMEDIATE` … `COMMIT`: every record in it becomes visible together, or
— on any refusal, error or interruption — none does (`SRB11-11`, `WP-12`, `EB-3a`). The
store decides nothing about what a unit *is*; that is the owning stage's (`WP-15`).
Contention is refused after the bounded wait, never waited out indefinitely and never
proceeded through (`WP-11`, `EB-8`).

**Only coordination records can be written.** The ingest domain — `RC-10`, `RC-11`
contents, `RC-12`, `RC-13` — lives in the same file and is readable here, but no operation
in GP-AUTO writes it (`SRB11-20`, `AP11-I70`): a record of an ingest class is refused, not
because a check fails but because no write layout exists for it.

**Reads surface everything, resolve nothing** (`EB-4`, `NP-12`, `NP-13`, `VM-6`). Every
stored record is returned — every record sharing one authorization identity individually —
and a record this definition cannot interpret is returned as `UnreadableRecord`, with its
reason, never dropped. Enumeration order is the key's collation, fixed only so a repeated
read is identical; it carries no governance meaning (`EQ-8`, `VM-10`).

**The store never mints** (`AP03-I27`). Identities arrive already minted (`minting.py`)
and are checked only for shape (`ID-4`).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Final

from pydantic import BaseModel, ValidationError

from gpauto import codec
from gpauto import store_schema as schema
from gpauto.authorization import AuthorityAmbiguity
from gpauto.content_identity import IdentifiedArtifactContent, IdentifiedStageContract
from gpauto.coordination_records import (
    ActivationEffectRecord,
    ArtifactProductionRecord,
    AuditEntry,
    AuthorityEnvelopeRecord,
    CandidateExclusionRecord,
    ClosureAssessmentRecord,
    ConformanceDetermination,
    CycleOccurrence,
    DispatchRecord,
    DispositionEstablishingRecord,
    EntryStateBoundaryRecord,
    EnvelopeViolationRecord,
    ExecutionObservation,
    FindingRecord,
    GovernanceEventResolution,
    HaltOccurrence,
    InputPackageRecord,
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
    OutcomeIngestionRecord,
    PostFreezeCandidateRecord,
    RefusalRecord,
    RootResolutionRecord,
    SessionRecord,
    WorkerActivationRecord,
)
from gpauto.governance import StageOutcome
from gpauto.repository import UnaccountedMutation
from gpauto.review import FrozenFindingSet, RemediationObligation
from gpauto.store_schema import (
    COVERED_RECORD_FORMATS,
    FORMAT_COLUMN,
    SCHEMA_VERSION,
    SLOT_COLUMN,
    STORAGE_VERSION,
    Catalogue,
    Layout,
    Row,
    Unreadable,
)

BUSY_TIMEOUT_MS: Final[int] = 10000
"""The frozen `governance.sqlite` value (`EB-13`): a bounded wait, then refusal."""

PRAGMAS: Final[tuple[tuple[str, str, str | int], ...]] = (
    ("journal_mode", "WAL", "wal"),
    ("synchronous", "FULL", 2),
    ("foreign_keys", "ON", 1),
    ("busy_timeout", str(BUSY_TIMEOUT_MS), BUSY_TIMEOUT_MS),
    ("recursive_triggers", "ON", 1),
)
"""`(pragma, set to, reads back as)`, set and verified on every GP-AUTO connection.
`recursive_triggers` makes a conflict-resolving `REPLACE` fire the delete triggers, so on a
connection so configured no statement form replaces a stored row. A connection opened
without it is outside that claim: the file is not an access-control boundary."""

type CoordinationRecord = (
    IdentifiedStageContract
    | RootResolutionRecord
    | CandidateExclusionRecord
    | AuthorityAmbiguity
    | EntryStateBoundaryRecord
    | AuthorityEnvelopeRecord
    | WorkerActivationRecord
    | InputPackageRecord
    | IdentifiedArtifactContent
    | ArtifactProductionRecord
    | ActivationEffectRecord
    | UnaccountedMutation
    | FindingRecord
    | FrozenFindingSet
    | RemediationObligation
    | ClosureAssessmentRecord
    | PostFreezeCandidateRecord
    | RefusalRecord
    | EnvelopeViolationRecord
    | HaltOccurrence
    | GovernanceEventResolution
    | CycleOccurrence
    | M1PositionEntry
    | M2PositionEntry
    | M3PositionEntry
    | M4PositionEntry
    | DispositionEstablishingRecord
    | StageOutcome
    | DispatchRecord
    | OutcomeIngestionRecord
    | ExecutionObservation
    | ConformanceDetermination
    | AuditEntry
    | SessionRecord
)
"""Every record class GP-AUTO may create — the coordination domain, and nothing else."""


class StoreError(Exception):
    """The bounded GP-AUTO store error model's root. Its classes are refusals, not bugs."""


class StoreUnavailable(StoreError):
    """The store cannot be used: absent, locked out, unreadable or misconfigured (`WP-11`,
    `EB-8`). The stage halts; nothing proceeds on a partial or assumed store."""


class StaleSchemaRefused(StoreUnavailable):
    """The store's schema is not exactly `SCHEMA_VERSION`'s. Refused, never migrated,
    upgraded, partially read or re-created (`VM-5`, `VM-8`, `SRB11-14`)."""


class WriteRefused(StoreError):
    """A create the store cannot perform: a record of a class it has no write operation
    for, or one its constraints refuse — a second write-once record, a duplicate key,
    a dangling reference, an illegal combination. Nothing of the unit was committed."""


@dataclass(frozen=True)
class UnreadableRecord:
    """A stored record this definition cannot interpret — surfaced, never dropped (`VM-6`)."""

    table: str
    key: tuple[tuple[str, Any], ...]
    reason: str


def _connect(path: Path, *, must_exist: bool) -> sqlite3.Connection:
    mode = "rw" if must_exist else "rwc"
    try:
        connection = sqlite3.connect(
            f"{path.resolve().as_uri()}?mode={mode}", uri=True, isolation_level=None
        )
    except sqlite3.Error as exc:
        raise StoreUnavailable(f"coordination store at {path}: cannot open: {exc}") from exc
    connection.row_factory = sqlite3.Row
    return connection


def _apply_pragmas(connection: sqlite3.Connection, path: Path) -> None:
    for name, value, expected in PRAGMAS:
        connection.execute(f"PRAGMA {name} = {value}")
        effective = connection.execute(f"PRAGMA {name}").fetchone()[0]
        if effective != expected:
            connection.close()
            raise StoreUnavailable(
                f"coordination store at {path}: PRAGMA {name} is {effective!r}, not {expected!r}"
            )


def expected_schema(catalogue: Catalogue) -> frozenset[tuple[str, str, str, str | None]]:
    """`sqlite_schema` exactly as `SCHEMA_VERSION`'s DDL produces it."""
    scratch = sqlite3.connect(":memory:")
    try:
        for statement in schema.schema_statements(catalogue):
            scratch.execute(statement)
        return _schema_rows(scratch)
    finally:
        scratch.close()


def _schema_rows(
    connection: sqlite3.Connection,
) -> frozenset[tuple[str, str, str, str | None]]:
    rows = connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_schema").fetchall()
    return frozenset((str(r[0]), str(r[1]), str(r[2]), r[3]) for r in rows)


def schema_incompatibility(connection: sqlite3.Connection, catalogue: Catalogue) -> str:
    """Why this definition cannot interpret the store, or `""` when it can.

    Version first, then the **entire** schema, compared exactly: a table, column, type,
    constraint, index or trigger added, removed or altered is a different schema, and a
    store under a different schema is not partially read (`SRB11-13`, `VM-5`).
    """
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != STORAGE_VERSION:  # guard:ga_store_stale_schema
        return (
            f"storage version {version} is not {STORAGE_VERSION} (schema {SCHEMA_VERSION}); "
            f"there is no migration path"
        )
    actual, expected = _schema_rows(connection), expected_schema(catalogue)
    if actual != expected:  # guard:ga_store_stale_schema
        missing = sorted(name for _, name, _, _ in expected - actual)
        extra = sorted(name for _, name, _, _ in actual - expected)
        return (
            f"schema is not {SCHEMA_VERSION}: absent or altered {missing[:5]}, "
            f"unexpected {extra[:5]}; there is no migration path"
        )
    return ""


def create_store(path: str | Path) -> CoordinationStore:
    """Lay down a new store of `SCHEMA_VERSION` at `path`, where nothing may yet exist."""
    location = Path(path)
    if location.exists():
        raise StoreUnavailable(f"coordination store at {location}: already exists; not created")
    catalogue = schema.build_catalogue()
    connection = _connect(location, must_exist=False)
    _apply_pragmas(connection, location)
    try:
        connection.execute("BEGIN IMMEDIATE")
        for statement in schema.schema_statements(catalogue):
            connection.execute(statement)
        connection.execute(f"PRAGMA user_version = {STORAGE_VERSION}")
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        connection.close()
        raise StoreUnavailable(f"coordination store at {location}: create failed: {exc}") from exc
    connection.close()
    return open_store(location)


def open_store(path: str | Path) -> CoordinationStore:
    """Open the existing store at `path`, or refuse it."""
    location = Path(path)
    if not location.is_file():
        raise StoreUnavailable(f"coordination store at {location}: no store exists there")
    catalogue = schema.build_catalogue()
    connection = _connect(location, must_exist=True)
    try:
        reason = schema_incompatibility(connection, catalogue)
    except sqlite3.Error as exc:
        connection.close()
        raise StaleSchemaRefused(f"coordination store at {location}: unreadable: {exc}") from exc
    if reason:  # guard:ga_store_stale_schema
        connection.close()
        raise StaleSchemaRefused(f"coordination store at {location}: {reason}")
    _apply_pragmas(connection, location)
    return CoordinationStore(location, connection, catalogue)


class CoordinationStore:
    """One open store. Construct it through `create_store` or `open_store` only."""

    def __init__(self, path: Path, connection: sqlite3.Connection, catalogue: Catalogue) -> None:
        self._path = path
        self._connection = connection
        self._catalogue = catalogue
        self._writable = schema.writable_layouts(catalogue)

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> CoordinationStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def effective_pragmas(self) -> dict[str, str | int]:
        """The frozen settings, read back from the live connection."""
        return {
            name: self._connection.execute(f"PRAGMA {name}").fetchone()[0] for name, _, _ in PRAGMAS
        }

    # --- the write surface: create only ------------------------------------------------

    def create(self, record: CoordinationRecord) -> None:
        """Create one record, as a unit of one."""
        self.create_unit((record,))

    def create_unit(self, records: Iterable[CoordinationRecord]) -> None:
        """Create every record in `records` indivisibly — all visible, or none (`SRB11-11`).

        Records are inserted in the order given, so a referent must precede what refers to
        it; the one frozen cycle — a finding and its set membership (`WP-19`) — is checked
        at commit instead.
        """
        with self._transaction("BEGIN IMMEDIATE"):
            for record in records:
                layout = self._writable.get(type(record))
                if layout is None:
                    raise WriteRefused(f"no write operation exists for {type(record).__name__}")
                self._insert(layout, record)

    def _insert(self, layout: Layout, record: BaseModel) -> None:
        row, children = schema.flatten(layout, record)
        self._insert_row(layout, row)
        for child in layout.children:
            parent_key = schema.child_key(child)[:-1]
            for member in children.get(child.name, []):
                self._insert_row(child, {**{c: row[c] for c in parent_key}, **member})

    def _insert_row(self, layout: Layout, row: Row) -> None:
        names = [column.name for column in schema.table_columns(layout)]
        placeholders = ", ".join("?" for _ in names)
        self._execute(
            f"INSERT INTO {layout.name} ({', '.join(names)}) VALUES ({placeholders})",
            [row.get(name) for name in names],
        )

    # --- reads ----------------------------------------------------------------------------

    def read(
        self, record_type: type[BaseModel], key: BaseModel
    ) -> BaseModel | UnreadableRecord | None:
        """The record of `record_type` under `key`, `UnreadableRecord`, or `None` if not held."""
        layout = self._layout(record_type)
        match = schema.key_values(layout, key)
        where = " AND ".join(f"{column} = ?" for column in match)
        with self._transaction("BEGIN"):
            rows = self._query(f"SELECT * FROM {layout.name} WHERE {where}", list(match.values()))
            return self._decode(layout, rows[0]) if rows else None

    def enumerate(self, record_type: type[BaseModel]) -> tuple[BaseModel | UnreadableRecord, ...]:
        """Every stored record of `record_type`, unreadable ones included (`VM-6`, `NP-13`)."""
        layout = self._layout(record_type)
        order = ", ".join(c for _, columns in schema.key_groups(layout) for c in columns)
        with self._transaction("BEGIN"):
            rows = self._query(f"SELECT * FROM {layout.name} ORDER BY {order}", [])
            return tuple(self._decode(layout, row) for row in rows)

    def _decode(self, layout: Layout, row: Row) -> BaseModel | UnreadableRecord:
        key = tuple(
            (column, row[column]) for _, columns in schema.key_groups(layout) for column in columns
        )
        try:
            if layout.spec.json_payload:
                return self._decode_json(row)
            children: dict[str, list[Row]] = {}
            for child in layout.children:
                parent = schema.child_key(child)[:-1]
                children[child.name] = self._query(
                    f"SELECT * FROM {child.name} WHERE "
                    + " AND ".join(f"{column} = ?" for column in parent)
                    + f" ORDER BY {SLOT_COLUMN}",
                    [row[column] for column in parent],
                )
            return schema.unflatten(layout, row, children, self._production)
        except Unreadable as exc:
            return UnreadableRecord(layout.name, key, exc.reason)
        except ValidationError as exc:
            return UnreadableRecord(layout.name, key, f"refused by the record schema: {exc}")

    @staticmethod
    def _decode_json(row: Row) -> BaseModel:
        if row[FORMAT_COLUMN] not in COVERED_RECORD_FORMATS:
            raise Unreadable(f"record format {row[FORMAT_COLUMN]!r} is not covered")
        record = codec.decode_authorization_record(row["payload"])
        if (
            record.identity.value != row["identity"]
            or record.authorization_identity.value != row["authorization_identity"]
        ):
            raise Unreadable("stored key columns disagree with the stored record")
        return record

    def _production(self, identity: str) -> BaseModel | None:
        """The stored production an embedded reference names, re-read — never copied."""
        layout = self._layout(ArtifactProductionRecord)
        rows = self._query(
            f"SELECT * FROM {layout.name} WHERE production__identity = ?", [identity]
        )
        found = self._decode(layout, rows[0]) if rows else None
        return found.production if isinstance(found, ArtifactProductionRecord) else None

    def _layout(self, record_type: type[BaseModel]) -> Layout:
        layout = self._catalogue.by_record.get(record_type)
        if layout is None:
            raise StoreError(f"{record_type.__name__} is not a stored record class")
        return layout

    # --- the vendor boundary -----------------------------------------------------------------

    @contextmanager
    def _transaction(self, begin: str) -> Iterator[None]:
        if self._connection.in_transaction:
            yield
            return
        self._execute(begin)
        try:
            yield
            self._execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def _execute(self, sql: str, parameters: list[Any] | None = None) -> None:
        try:
            self._connection.execute(sql, parameters or [])
        except sqlite3.IntegrityError as exc:
            raise WriteRefused(f"{self._path}: refused: {exc}") from exc
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"{self._path}: {exc}") from exc

    def _query(self, sql: str, parameters: list[Any]) -> list[Row]:
        try:
            return [dict(row) for row in self._connection.execute(sql, parameters).fetchall()]
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"{self._path}: {exc}") from exc
