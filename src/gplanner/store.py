"""The governance store — `governance.sqlite`, and nothing DBOS can see.

Design basis: design/GP-SPK-001-governance-kernel.md §12, §6, §9.

Two databases, never joined (§12). DBOS's `dbos_sys.sqlite` is **opaque**: this module
never reads, writes or queries it, and imports no engine at all. `governance.sqlite` is
ours -- stdlib `sqlite3`, no ORM, no migration framework.

**This module stores; it does not decide.** It persists governance facts, re-derives
identity from the bytes it actually holds, and enforces uniqueness and compare-and-set
structurally. It never decides whether a transition is legal, whether a `HUMAN` label
suffices, whether an approval is stale, whether a replay is valid, or whether an
approval should be consumed. Those are `policy.py`'s declarative table and `kernel.py`'s
§10 ordering, and a second opinion here would mean two authority models. `store.py`
therefore imports neither `policy` nor `approvals`, and GP-08 asserts it: the store will
advance a case along an edge `LEGAL_TRANSITIONS` does not contain, because refusing it
is not the store's job.

Transactions
------------
`isolation_level=None`, so `sqlite3` adds no implicit transaction of its own and every
`BEGIN` in this file is one we wrote. `transaction()` issues an explicit
`BEGIN IMMEDIATE`, an explicit `COMMIT`, and `except BaseException: ROLLBACK; raise`
around the whole block -- `BaseException` and not `Exception`, so a `KeyboardInterrupt`
between two writes cannot leave half of them committed.

`BEGIN IMMEDIATE` rather than the deferred default, because §10 depends on it: the write
lock is taken at `BEGIN`, so two concurrent writers serialize and the second reads state
the first has committed. With `busy_timeout=10000` a collision is a wait, not a
`SQLITE_BUSY` error. This is the mechanism single-use rests on, and it depends on DBOS in
no way.

`transaction()` is **reentrant, and the inner scope is a pass-through**. §10 requires
every step of an approval application to sit inside *one* `BEGIN IMMEDIATE`; the kernel
opens that transaction and then calls several store methods, each of which would
otherwise try to open its own and hit "cannot start a transaction within a transaction".
Nesting is decided from `sqlite3.Connection.in_transaction` rather than from a counter
this module maintains, so the two cannot come to disagree. A pass-through inner scope is
the correct semantics here and not a weakening: no inner block can commit independently,
so a failure anywhere rolls the whole application back.

Pass-through is correct **inside** one owner and wrong **across** two (ST8-R01). It is
what lets the kernel compose several store writes into its own transaction; it is also
what would let a *caller* wrap a kernel entry point, so that the kernel's scope issued
no `BEGIN` and no `COMMIT` and its committed-result contract became unanswerable. The
store does not police that -- it stores and does not decide -- but a caller that must
own its transaction has to be able to ask, so :attr:`Store.in_transaction` states
whether one is active. It is the store's only opinion on the subject: a fact reported,
with the decision left where §10 puts it.

Schema compatibility
--------------------
Two versions with two different jobs, kept separate as §12 freezes them.
:data:`SCHEMA_VERSION` is the **domain** identity of the schema this build implements --
it names the contract, and appears in refusals so an operator is told which build's
schema was expected. :data:`STORAGE_VERSION` is the **physical** marker, and is the one
that is persisted, in `PRAGMA user_version`.

The domain version is deliberately not written into the database: §12 freezes exactly
four tables, and persisting it would need a fifth. The physical marker plus the
structural check below is what decides compatibility.

A version check alone is not sufficient, because `user_version` **defaults to 0**: a
database written before the marker existed would read as "brand new" and be silently
re-created over. Compatibility is therefore decided structurally as well, through
`PRAGMA table_info` and `PRAGMA table_list` -- every frozen table present, STRICT, and
carrying exactly its frozen columns in order. Anything else is refused with
:class:`StoreSchemaTooOld` and **no migration path**, matching the sibling
`governed-runtime` while both are pre-release.

A refusal closes the connection before raising. A store that refused but kept its handle
would hold a WAL lock for the life of the process, so the operator's second attempt
would fail for a different reason than the first.

Identity
--------
`put_artifact` verifies `digest_of_preimage_bytes(blob) == digest` on the way in and
`get_artifact` re-derives it on the way out (`guard:gp_digest_rehash`, GK-INV-1). The
read-path check is the load-bearing one: it proves identity from the bytes on disk
rather than from what a caller asserts about them, which is the property §10 step 5.5
relies on.

`byte_len` is computed from the blob at both ends and is never accepted from a caller.
The column exists so an external reader can size a row without loading it; the bytes
remain the authority, so a tampered column cannot change what `get_artifact` reports.

Absence and refusal are different answers
-----------------------------------------
`get_artifact`, `load_case` and `find_consumption` return `None` when there is no row.
Absence is a *fact* for the caller to interpret -- §10 step 3 reads "no consumption row"
as permission to proceed, while a missing artifact would be an integrity failure -- and
the store must not make that call. `errors.py` is frozen and has no missing-row class;
ST-7 may not grow one, and using a governance refusal to mean "not found" would make the
two indistinguishable at the call site that has to tell them apart.

Vendor errors never escape. `sqlite3` failures are translated at the site that can name
what they mean, following `errors.py`'s rule that a refusal reads as a statement about
the authority model rather than about the library that noticed it.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Final

from gplanner.artifacts import ArtifactRef
from gplanner.digest import digest_of_preimage_bytes
from gplanner.errors import (
    ApprovalReplay,
    ConcurrentModification,
    DigestMismatch,
    GovernedPlannerError,
    StoreSchemaTooOld,
)
from gplanner.require import require
from gplanner.states import ScopeState

#: The **domain** schema identity of this build. Names the contract; not persisted.
SCHEMA_VERSION: Final[str] = "gplanner.governance/0.1.0"

#: The **physical** storage marker, persisted in `PRAGMA user_version`.
STORAGE_VERSION: Final[int] = 1

#: `PRAGMA user_version` on a database nothing has stamped. Called out by name because
#: the whole reason the structural check exists is that this value is indistinguishable
#: from "written by a build that predates the marker".
UNSTAMPED_STORAGE_VERSION: Final[int] = 0

#: Frozen by §12. Applied to every connection in this order. `journal_mode` is a
#: property of the file and persists; the other three are per-connection and are
#: re-applied on every open -- `foreign_keys` in particular defaults to OFF, so a
#: declared foreign key is not an enforced one until this runs.
PRAGMAS: Final[tuple[tuple[str, str], ...]] = (
    ("journal_mode", "WAL"),
    ("synchronous", "FULL"),
    ("foreign_keys", "ON"),
    ("busy_timeout", "10000"),
)

#: A case's revision immediately after creation. One committed write has happened to the
#: row, so the counter reads 1; §12 fixes the CAS mechanism but not this starting value,
#: and it is named here rather than spelled `1` at four call sites so the compare-and-set
#: and the creation cannot drift apart.
INITIAL_REVISION: Final[int] = 1

#: §12's DDL, verbatim in content and order. Declared as data rather than built from the
#: expectation table below, so the thing that is created and the thing that is verified
#: are two independent statements that GP-08 pins against each other.
SCHEMA_SQL: Final[tuple[str, ...]] = (
    """CREATE TABLE artifacts (
    digest TEXT PRIMARY KEY,
    media_type TEXT NOT NULL,
    canonical_preimage BLOB NOT NULL,
    byte_len INTEGER NOT NULL
) STRICT""",
    """CREATE TABLE cases (
    workflow_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    subject_digest TEXT NOT NULL REFERENCES artifacts(digest),
    revision INTEGER NOT NULL
) STRICT""",
    """CREATE TABLE approval_consumptions (
    approval_id TEXT PRIMARY KEY,
    approval_digest TEXT NOT NULL,
    subject_digest TEXT NOT NULL,
    workflow_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    consumed_at TEXT NOT NULL
) STRICT""",
    """CREATE TABLE audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    at TEXT NOT NULL,
    event TEXT NOT NULL,
    detail_json BLOB NOT NULL
) STRICT""",
)

#: What `PRAGMA table_info` must report, as `(name, declared type, notnull, pk position)`
#: in column order (ST7-R01).
#:
#: Column *order* is compared, not just membership: a schema whose columns were rebuilt
#: in a different order is a different schema, and positional access anywhere would read
#: the wrong value from it.
#:
#: `notnull` and `pk` are compared because §11's DDL makes them part of the storage
#: contract rather than decoration. `approval_consumptions.approval_id`'s PRIMARY KEY
#: **is** the single-use guarantee; a required column that became nullable admits rows
#: the contract says cannot exist. `audit_events.seq` reports `notnull = 0` because an
#: `INTEGER PRIMARY KEY` is the rowid alias and is assigned on insert -- that is the
#: frozen shape, recorded here rather than corrected.
EXPECTED_COLUMNS: Final[Mapping[str, tuple[tuple[str, str, int, int], ...]]] = {
    "artifacts": (
        ("digest", "TEXT", 1, 1),
        ("media_type", "TEXT", 1, 0),
        ("canonical_preimage", "BLOB", 1, 0),
        ("byte_len", "INTEGER", 1, 0),
    ),
    "cases": (
        ("workflow_id", "TEXT", 1, 1),
        ("state", "TEXT", 1, 0),
        ("subject_digest", "TEXT", 1, 0),
        ("revision", "INTEGER", 1, 0),
    ),
    "approval_consumptions": (
        ("approval_id", "TEXT", 1, 1),
        ("approval_digest", "TEXT", 1, 0),
        ("subject_digest", "TEXT", 1, 0),
        ("workflow_id", "TEXT", 1, 0),
        ("from_state", "TEXT", 1, 0),
        ("to_state", "TEXT", 1, 0),
        ("consumed_at", "TEXT", 1, 0),
    ),
    "audit_events": (
        ("seq", "INTEGER", 0, 1),
        ("workflow_id", "TEXT", 1, 0),
        ("at", "TEXT", 1, 0),
        ("event", "TEXT", 1, 0),
        ("detail_json", "BLOB", 1, 0),
    ),
}

#: What `PRAGMA foreign_key_list` must report, as `(referenced table, local column,
#: referenced column)` (ST7-R01). Declared for **every** frozen table, the three empty
#: ones included, so an added key is as incompatible as a missing one.
#:
#: `foreign_keys = ON` enforces the keys a schema declares; it cannot supply one the
#: schema omits. A `cases` table without this key accepts a case referencing content the
#: store does not hold, on a connection whose pragma reads `1`.
EXPECTED_FOREIGN_KEYS: Final[Mapping[str, tuple[tuple[str, str, str], ...]]] = {
    "artifacts": (),
    "cases": (("artifacts", "subject_digest", "digest"),),
    "approval_consumptions": (),
    "audit_events": (),
}

#: Which frozen tables declare `AUTOINCREMENT` (ST7-R01).
#:
#: Checked against the stored `CREATE TABLE` text because **no pragma reports it**:
#: `PRAGMA table_info` renders `INTEGER PRIMARY KEY AUTOINCREMENT` and a bare
#: `INTEGER PRIMARY KEY` identically. Without it SQLite reuses the rowid of a deleted
#: last row, so two distinct audit events could be filed under one sequence number --
#: which is the property `read_audit`'s ordering rests on.
#:
#: The check is textual and is therefore a check on the declaration, not on a parse of
#: it; it is exact for schemas this module created, which is the only authorized
#: producer of these tables.
AUTOINCREMENT_TABLES: Final[frozenset[str]] = frozenset({"audit_events"})

#: SQLite reserves this prefix for its own tables -- `sqlite_sequence`, created
#: implicitly by `AUTOINCREMENT`, is the one this schema causes. Excluded from the
#: application-table set so it is never mistaken for an unauthorized fifth governance
#: table (ST7-R01).
_SQLITE_INTERNAL_PREFIX: Final[str] = "sqlite_"


@dataclass(frozen=True)
class _Result:
    """One statement's outcome, fully read before the vendor cursor is let go.

    Private, and never returned from a public method: a `sqlite3.Cursor` escaping the
    store is precisely how a fetch could happen outside the translating boundary.
    """

    rows: tuple[Any, ...]
    rowcount: int
    lastrowid: int | None


@dataclass(frozen=True)
class StoredArtifact:
    """A row of `artifacts`: the authoritative bytes, plus the reference describing them.

    `canonical_preimage` is the artifact. `ref` is a description of it, and every field
    of that description is re-derived from the bytes on read rather than read out of the
    row, so no stored column can contradict the content it describes.
    """

    ref: ArtifactRef
    canonical_preimage: bytes


@dataclass(frozen=True)
class CaseRecord:
    """A row of `cases`. Carries state, never authority over it."""

    workflow_id: str
    state: ScopeState
    subject_digest: str
    revision: int


@dataclass(frozen=True)
class ConsumptionRecord:
    """A row of `approval_consumptions`: that an `approval_id` was claimed, and for what.

    A record of a claim, not a verdict about one. Whether a claim that already exists
    means a legitimate replay or a refused reuse is §10 step 4's comparison, made in the
    kernel against the statement in hand.
    """

    approval_id: str
    approval_digest: str
    subject_digest: str
    workflow_id: str
    from_state: ScopeState
    to_state: ScopeState
    consumed_at: str


@dataclass(frozen=True)
class AuditRecord:
    """A row of `audit_events`.

    `detail_json` is opaque bytes here. This module holds no JSON decoder -- `codec.py`
    is the single JSON → domain boundary (§7) -- so the detail is written and returned
    exactly as handed over, and is never parsed, re-encoded or interpreted.

    Append-only **by convention**: there is no hash chaining and no tamper detection in
    GP-SPK-001, and nothing in this module claims otherwise (CLAUDE.md, known gaps).
    """

    seq: int
    workflow_id: str
    at: str
    event: str
    detail_json: bytes


class Store:
    """An open `governance.sqlite`. One connection, owned for the object's lifetime.

    A context manager, so `with store.open(path) as st:` closes the handle on every
    path including an exceptional one. Not thread-safe as a single object -- `sqlite3`
    connections are not shared across threads by default; concurrent writers each open
    their own `Store`, which is exactly the arrangement `BEGIN IMMEDIATE` serializes.
    """

    def __init__(self, connection: sqlite3.Connection, path: Path) -> None:
        self._connection = connection
        self._path = path

    # -- lifetime ------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        """Release the handle. Idempotent, as `sqlite3.Connection.close` is."""
        try:
            self._connection.close()
        except sqlite3.Error as exc:
            raise self._store_failure("close", exc) from exc

    def _close_quietly(self) -> None:
        """Release the handle on a path where a failure is already in flight.

        Distinct from `close`, deliberately: `close` is an assertion about cleanup and
        reports when it cannot keep its promise, while this runs where raising would
        replace the original failure with a complaint about tidying up after it.
        """
        try:
            self._connection.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def effective_pragmas(self) -> dict[str, str | int]:
        """The four frozen settings, read back from the live connection.

        Read-only, and one of the store's two non-governance accessors -- the other is
        :attr:`in_transaction`. A configuration that is an obligation (§12) but cannot
        be observed is an obligation nothing can verify, and `journal_mode` /
        `foreign_keys` in particular fail *silently* when they do not take effect.
        """
        return {
            name: self._run(f"PRAGMA {name}").rows[0][0] for name, _ in PRAGMAS
        }

    # -- the vendor boundary -------------------------------------------------

    def _store_failure(self, what: str, exc: sqlite3.Error) -> GovernedPlannerError:
        """Translate a `sqlite3` failure into this package's vocabulary (ST7-R03).

        `errors.py` states the rule: a refusal reads as a statement about the authority
        model, never about the library that noticed it. `GovernedPlannerError` is used
        because no *frozen* class names "the database could not do this", and ST-7 may
        not grow the hierarchy -- `require()`'s own default is the same class.

        Nothing is hidden. The SQLite class name is in the message and the original is
        the `__cause__`, so a store defect stays as diagnosable as it was while no
        longer reaching a caller as a vendor type.
        """
        return GovernedPlannerError(
            f"governance store at {self._path}: {what} failed: "
            f"{type(exc).__name__}: {exc}"
        )

    def _run(self, sql: str, parameters: Sequence[Any] = ()) -> _Result:
        """Every statement this module runs, **submitted and read** inside the boundary.

        Returns a materialized :class:`_Result` rather than the cursor. That is the
        load-bearing part (ST7-R03 closure): SQLite steps rows lazily, so
        `Connection.execute` compiles the statement and returns, and the rows are
        produced later during `fetchall`. A boundary around the `execute` call alone
        therefore covers submission and not retrieval -- an interrupt during stepping
        escaped from `read_audit` as a raw `sqlite3.OperationalError`. `rowcount` and
        `lastrowid` are read here too, for the same reason: they are attribute accesses
        on a vendor object, and a vendor object must not outlive this method.

        Only `sqlite3.Error` is caught. A `TypeError` or `ValueError` raised inside the
        store is a defect in *this* module and must reach the caller as itself:
        relabelling it would dress a bug up as a governance refusal. `BaseException`
        likewise passes through untouched, so an interrupt is never translated into a
        refusal of any kind.
        """
        try:
            cursor = self._connection.execute(sql, parameters)
            return _Result(
                rows=tuple(cursor.fetchall()),
                rowcount=cursor.rowcount,
                lastrowid=cursor.lastrowid,
            )
        except sqlite3.Error as exc:
            raise self._store_failure(f"{sql.split()[0].lower()} statement", exc) from exc

    def _in_transaction(self) -> bool:
        """Is a transaction active? Asked across the boundary, because it can fail.

        `Connection.in_transaction` is an attribute access, never a statement, so a
        statement-level boundary never saw it -- and on a closed connection it raises
        `sqlite3.ProgrammingError`. After a cleanup failure closed the handle (see
        `_abort`), the next call entered `transaction()` and that raw error escaped
        (ST7-R03 closure). The store's vendor surface is submission, retrieval **and**
        connection-state inspection; all three are translated.
        """
        try:
            return self._connection.in_transaction
        except sqlite3.Error as exc:
            raise self._store_failure("transaction-state inspection", exc) from exc

    # -- transactions --------------------------------------------------------

    @property
    def in_transaction(self) -> bool:
        """Is a transaction active on this connection right now? (ST8-R01.)

        A fact, not a decision. The store composes freely into whatever transaction it
        is given, so it has no use for this itself; it is published because a caller
        whose contract is *"this call committed"* cannot keep that promise inside a
        transaction somebody else will commit or roll back, and must be able to tell.

        Read through the same translating boundary as every other vendor access, so a
        closed or broken handle is reported as a governance-layer refusal rather than
        as a `sqlite3.ProgrammingError` escaping from an attribute lookup.
        """
        return self._in_transaction()

    def _abort(self, failure: BaseException) -> None:
        """Undo an unfinished transaction without ever displacing `failure` (ST7-R02).

        Three rules, each answering an observed defect:

        **Roll back only while a transaction is actually active.** SQLite rolls back by
        itself on some errors -- `SQLITE_FULL` among them -- and an unconditional
        `ROLLBACK` then fails with "cannot rollback - no transaction is active" and
        *replaces* "database or disk is full". The operator is then told about the
        cleanup instead of about the disk.

        **Never raise.** This runs with a failure already in flight, and the caller
        re-raises it immediately afterwards. A cleanup error that propagated would
        become the reported cause of something it did not cause.

        **Never leave a silently usable dirty handle.** If the rollback itself fails,
        the transaction state is unknown, so the connection is closed and a note is
        attached to the original failure. Closing is not silence: it makes the next use
        fail loudly rather than run inside a transaction nobody intended.
        """
        try:
            active = self._connection.in_transaction
        except sqlite3.Error:
            # The handle is already unusable, so there is no transaction to undo and
            # nothing this method could do about it. Reported through the primary
            # failure by the caller, never raised from cleanup.
            return
        if not active:
            return
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error as cleanup_failure:
            failure.add_note(
                f"governance store rollback also failed "
                f"({type(cleanup_failure).__name__}: {cleanup_failure}); the connection "
                f"at {self._path} was closed because its transaction state is unknown"
            )
            self._close_quietly()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """One explicit `BEGIN IMMEDIATE` ... `COMMIT`, or a rollback of everything.

        **`COMMIT` is inside the protected block** (ST7-R02). It was outside it in the
        first ST-7 implementation, so a refused commit left the transaction open: the
        next standalone write then took the reentrant pass-through branch below,
        committed nothing, and *returned success*. The promise a transaction boundary
        makes is worthless if the commit is not part of what it covers.

        `except BaseException`, not `except Exception`, so a `KeyboardInterrupt`
        arriving between two writes -- or during the commit itself -- cannot leave half
        of them committed.

        Reentrant: a scope opened while a transaction is already active is a
        pass-through, because §10 requires every step of an approval application to sit
        inside *one* `BEGIN IMMEDIATE`. Nesting is decided from
        `sqlite3.Connection.in_transaction` rather than from a counter this module
        maintains, so the two cannot come to disagree -- and, with the fix above, that
        flag can no longer be left set by a failure.
        """
        if self._in_transaction():
            yield
            return
        self._run("BEGIN IMMEDIATE")
        try:
            yield
            self._run("COMMIT")
        except BaseException as failure:
            self._abort(failure)
            raise

    # -- artifacts -----------------------------------------------------------

    def put_artifact(
        self, *, digest: str, media_type: str, canonical_preimage: bytes
    ) -> ArtifactRef:
        """Store the authoritative bytes under the digest they actually hash to.

        The claim is verified, never trusted: a caller that asserts the wrong digest is
        refused rather than filed under it. Idempotent, because identity is the key --
        storing the same content twice is the same fact stated twice, and `open_case`
        re-run by an at-least-once step must not explode.

        `byte_len` is computed here. Accepting it would let a caller describe the bytes
        as something other than what they are.
        """
        require(
            digest_of_preimage_bytes(canonical_preimage) == digest,
            f"preimage does not hash to its claimed digest {digest!r} "
            f"(actual {digest_of_preimage_bytes(canonical_preimage)!r})",
            error=DigestMismatch,
        )  # guard:gp_digest_rehash
        ref = ArtifactRef(
            media_type=media_type, digest=digest, byte_len=len(canonical_preimage)
        )
        with self.transaction():
            self._run(
                "INSERT INTO artifacts (digest, media_type, canonical_preimage, byte_len) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(digest) DO NOTHING",
                (digest, media_type, canonical_preimage, len(canonical_preimage)),
            )
        return ref

    def get_artifact(self, digest: str) -> StoredArtifact | None:
        """Return the stored bytes, re-proving they are what they are filed under.

        The read-path half of GK-INV-1. `sha256` is recomputed over the bytes on disk
        with no re-serialization of anything, so a tampered row is caught here rather
        than being handed to a caller that would go on to trust it.
        """
        rows = self._run(
            "SELECT media_type, canonical_preimage FROM artifacts WHERE digest = ?",
            (digest,),
        ).rows
        if not rows:
            return None
        media_type, blob = str(rows[0][0]), bytes(rows[0][1])
        require(
            digest_of_preimage_bytes(blob) == digest,
            f"stored preimage for {digest!r} rehashes to "
            f"{digest_of_preimage_bytes(blob)!r} (GK-INV-1)",
            error=DigestMismatch,
        )  # guard:gp_digest_rehash
        return StoredArtifact(
            ref=ArtifactRef(media_type=media_type, digest=digest, byte_len=len(blob)),
            canonical_preimage=blob,
        )

    # -- cases ---------------------------------------------------------------

    def create_case(
        self, *, workflow_id: str, state: ScopeState, subject_digest: str
    ) -> CaseRecord:
        """File a new case against a stored artifact.

        `subject_digest` is a foreign key into `artifacts`, so a case cannot reference
        content the store does not hold. Whether `state` is a sensible state to open in
        is not asked here.
        """
        record = CaseRecord(
            workflow_id=workflow_id,
            state=state,
            subject_digest=subject_digest,
            revision=INITIAL_REVISION,
        )
        with self.transaction():
            try:
                self._connection.execute(
                    "INSERT INTO cases (workflow_id, state, subject_digest, revision) "
                    "VALUES (?, ?, ?, ?)",
                    (workflow_id, str(state), subject_digest, INITIAL_REVISION),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernedPlannerError(
                    f"cannot create case {workflow_id!r} against subject "
                    f"{subject_digest!r}: {exc}"
                ) from exc
            except sqlite3.Error as exc:
                raise self._store_failure("creating a case", exc) from exc
        return record

    def load_case(self, workflow_id: str) -> CaseRecord | None:
        rows = self._run(
            "SELECT state, subject_digest, revision FROM cases WHERE workflow_id = ?",
            (workflow_id,),
        ).rows
        if not rows:
            return None
        return CaseRecord(
            workflow_id=workflow_id,
            state=ScopeState(rows[0][0]),
            subject_digest=str(rows[0][1]),
            revision=int(rows[0][2]),
        )

    def advance_case(
        self, *, workflow_id: str, to_state: ScopeState, expected_revision: int
    ) -> CaseRecord:
        """Compare-and-set the case forward, or refuse.

        Optimistic concurrency, per §12's `UPDATE ... WHERE workflow_id = ? AND
        revision = ?`. Zero rows changed means the row the caller read is no longer the
        row on disk, and the caller must re-read rather than overwrite.

        A **missing** case and a **stale** revision are one fact at this level: the row
        the caller expected is not there. They are not separated, because §10 loads the
        case as step 1 inside the same transaction, so by the time this runs a missing
        case is unreachable -- and inventing a second refusal for an unreachable state
        would put a distinction in the error vocabulary that nothing can produce.

        The store performs no legality check. `to_state` is written as given, including
        along an edge `LEGAL_TRANSITIONS` does not contain; refusing it is `policy.py`'s
        single declarative answer, and a second one here is exactly what §4 forbids.
        """
        with self.transaction():
            updated = self._run(
                "UPDATE cases SET state = ?, revision = revision + 1 "
                "WHERE workflow_id = ? AND revision = ?",
                (str(to_state), workflow_id, expected_revision),
            )
            require(
                updated.rowcount == 1,
                f"case {workflow_id!r} is not at revision {expected_revision} "
                f"(rows updated: {updated.rowcount})",
                error=ConcurrentModification,
            )  # guard:gp_case_revision_cas
            row = self._run(
                "SELECT subject_digest, revision FROM cases WHERE workflow_id = ?",
                (workflow_id,),
            ).rows[0]
        return CaseRecord(
            workflow_id=workflow_id,
            state=to_state,
            subject_digest=str(row[0]),
            revision=int(row[1]),
        )

    # -- approval consumptions -----------------------------------------------

    def record_consumption(
        self,
        *,
        approval_id: str,
        approval_digest: str,
        subject_digest: str,
        workflow_id: str,
        from_state: ScopeState,
        to_state: ScopeState,
        consumed_at: str,
    ) -> ConsumptionRecord:
        """Claim an `approval_id`. The PRIMARY KEY is what makes the claim exclusive.

        The single-use guarantee is structural (§12): one row per `approval_id`, for all
        workflows and all content, so a second claim cannot be written whatever it says.

        The `IntegrityError` translation is §12's **structural backstop**, not a decision
        about replay. Under `BEGIN IMMEDIATE` it is unreachable from the kernel, whose
        step 3 `SELECT` has already seen any committed row; it survives as the last line
        of defence and is reported as :class:`ApprovalReplay` because that is what a
        duplicate key here means. It is deliberately **not** the registered
        `guard:gp_approval_replay` site -- that is `kernel._consumption_branch` (ST-8),
        which compares content and decides whether a replay is legitimate. This line
        decides nothing; `approval_consumptions` carries no foreign key, so a duplicate
        primary key is the only integrity failure this insert can produce.
        """
        record = ConsumptionRecord(
            approval_id=approval_id,
            approval_digest=approval_digest,
            subject_digest=subject_digest,
            workflow_id=workflow_id,
            from_state=from_state,
            to_state=to_state,
            consumed_at=consumed_at,
        )
        with self.transaction():
            try:
                self._connection.execute(
                    "INSERT INTO approval_consumptions (approval_id, approval_digest, "
                    "subject_digest, workflow_id, from_state, to_state, consumed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        approval_id,
                        approval_digest,
                        subject_digest,
                        workflow_id,
                        str(from_state),
                        str(to_state),
                        consumed_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalReplay(
                    f"approval_id {approval_id!r} is already recorded as consumed: {exc}"
                ) from exc
            except sqlite3.Error as exc:
                raise self._store_failure("recording an approval consumption", exc) from exc
        return record

    def find_consumption(self, approval_id: str) -> ConsumptionRecord | None:
        """Report whether an `approval_id` has been claimed, and for what. No verdict."""
        rows = self._run(
            "SELECT approval_digest, subject_digest, workflow_id, from_state, to_state, "
            "consumed_at FROM approval_consumptions WHERE approval_id = ?",
            (approval_id,),
        ).rows
        if not rows:
            return None
        row = rows[0]
        return ConsumptionRecord(
            approval_id=approval_id,
            approval_digest=str(row[0]),
            subject_digest=str(row[1]),
            workflow_id=str(row[2]),
            from_state=ScopeState(row[3]),
            to_state=ScopeState(row[4]),
            consumed_at=str(row[5]),
        )

    # -- audit ---------------------------------------------------------------

    def append_audit(
        self, *, workflow_id: str, at: str, event: str, detail_json: bytes
    ) -> AuditRecord:
        """Append one audit row and return it, `seq` included.

        `at` is supplied by the caller. This module reads no clock: §12 records that
        there is no trusted time source in GP-SPK-001, and a store that stamped its own
        timestamps would be asserting one.
        """
        with self.transaction():
            seq = self._run(
                "INSERT INTO audit_events (workflow_id, at, event, detail_json) "
                "VALUES (?, ?, ?, ?)",
                (workflow_id, at, event, detail_json),
            ).lastrowid
        return AuditRecord(
            seq=int(seq if seq is not None else 0),
            workflow_id=workflow_id,
            at=at,
            event=event,
            detail_json=detail_json,
        )

    def read_audit(self, workflow_id: str | None = None) -> tuple[AuditRecord, ...]:
        """Every audit row, or one workflow's, in `seq` order.

        Ordered by `seq` explicitly rather than relying on insertion order: SQLite makes
        no guarantee about the order of an unordered `SELECT`, and an audit trail whose
        order depends on the query planner is not one.
        """
        if workflow_id is None:
            rows = self._run(
                "SELECT seq, workflow_id, at, event, detail_json FROM audit_events "
                "ORDER BY seq"
            ).rows
        else:
            rows = self._run(
                "SELECT seq, workflow_id, at, event, detail_json FROM audit_events "
                "WHERE workflow_id = ? ORDER BY seq",
                (workflow_id,),
            ).rows
        return tuple(
            AuditRecord(
                seq=int(row[0]),
                workflow_id=str(row[1]),
                at=str(row[2]),
                event=str(row[3]),
                detail_json=bytes(row[4]),
            )
            for row in rows
        )


# -- opening -----------------------------------------------------------------


def _apply_pragmas(connection: sqlite3.Connection) -> None:
    """Apply §12's four settings. Outside any transaction, where they take effect."""
    for name, value in PRAGMAS:
        connection.execute(f"PRAGMA {name} = {value}")


def _table_names(connection: sqlite3.Connection) -> set[str]:
    """Every table in the file, SQLite's own included."""
    return {
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _application_tables(connection: sqlite3.Connection) -> set[str]:
    """The tables an application put there -- SQLite's internal ones excluded.

    `sqlite_sequence` exists in every store this module creates, because
    `audit_events.seq` is `AUTOINCREMENT`. It is SQLite's, not ours, and counting it as
    a governance table would make every store refuse to reopen (ST7-R01).
    """
    return {
        name for name in _table_names(connection)
        if not name.startswith(_SQLITE_INTERNAL_PREFIX)
    }


def _strict_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[1])
        for row in connection.execute("PRAGMA table_list")
        if row[0] == "main" and row[2] == "table" and row[5]
    }


def _declared_sql(connection: sqlite3.Connection, table: str) -> str:
    """The stored `CREATE TABLE` text, uppercased. The only place AUTOINCREMENT shows."""
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return str(row[0]).upper() if row and row[0] else ""


def _is_pristine(connection: sqlite3.Connection) -> bool:
    """Is this a genuinely untouched database -- unstamped **and** empty (ST7-R01)?

    The emptiness test is over *every* application table, not over the four this module
    would create. Keying it on "none of our names are present" classified a version-0
    database holding some unrelated table as brand new: `open` then added the governance
    tables beside the stranger and stamped it, producing a database the contract never
    describes. Creation is for an empty file; anything else is verified, and refused if
    it does not match.
    """
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    return version == UNSTAMPED_STORAGE_VERSION and not _application_tables(connection)


def _create_schema(connection: sqlite3.Connection) -> None:
    """Create the four frozen tables and stamp the storage version, atomically.

    The stamp is written inside the same transaction as the DDL, so a database can never
    exist with the tables present and the marker missing -- the state the structural
    check exists to catch, and one nothing here is allowed to produce.
    """
    for statement in SCHEMA_SQL:
        connection.execute(statement)
    connection.execute(f"PRAGMA user_version = {STORAGE_VERSION}")


def _schema_incompatibility(connection: sqlite3.Connection) -> str:
    """Why this build cannot read this database, or `""` when it can.

    A helper returning a reason rather than raising, so the refusal at the call site
    stays **one deletable line** (D-2): GP-SPK-002's mutation harness proves a guard is
    tested by deleting its line and requiring the suite to go red, and a check spread
    over several `raise` branches deletes into a syntax error, which is reported as an
    error rather than a kill and proves nothing. Same arrangement as
    `policy.resolve` / `policy.refuse_unless_allowed` and `approvals`'s date-time
    helper.

    **Every guarantee §11's DDL makes is checked, not only the column names** (ST7-R01).
    Version, the exact application-table set, STRICT, column order with declared types,
    nullability and primary keys, the declared foreign keys, and `AUTOINCREMENT`. The
    first implementation compared version, table presence, STRICT and `(name, type)`
    only, and so accepted databases that had lost the `approval_id` primary key -- the
    single-use guarantee itself -- or the `cases` foreign key, while reporting
    `foreign_keys = 1`.

    Version first, then structure. The version says which build wrote the database; the
    structure says whether it is the one this build expects, and is checked as well
    because `user_version` defaults to 0 and so cannot distinguish "new" from "old".

    Deterministic: the frozen tables are examined in `EXPECTED_COLUMNS` order, the
    properties of each in a fixed order, and the first incompatibility found is the one
    reported -- so repeating a refused open produces the identical message rather than
    whichever mismatch the iteration order happened to surface.

    Indexes and triggers are **not** compared: neither appears in the frozen DDL, and
    neither can weaken a constraint that is checked above.
    """
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != STORAGE_VERSION:
        return (
            f"governance storage version {version} is not {STORAGE_VERSION} "
            f"(schema {SCHEMA_VERSION}); there is no migration path"
        )
    application = _application_tables(connection)
    for table in EXPECTED_COLUMNS:
        if table not in application:
            return (
                f"governance schema {SCHEMA_VERSION} requires table {table!r}, "
                f"which is absent; there is no migration path"
            )
    unexpected = sorted(application - EXPECTED_COLUMNS.keys())
    if unexpected:
        return (
            f"governance schema {SCHEMA_VERSION} defines exactly "
            f"{sorted(EXPECTED_COLUMNS)}; this database also carries {unexpected}; "
            f"there is no migration path"
        )
    strict = _strict_tables(connection)
    for table, columns in EXPECTED_COLUMNS.items():
        if table not in strict:
            return (
                f"governance table {table!r} is not STRICT, as schema "
                f"{SCHEMA_VERSION} requires; there is no migration path"
            )
        actual = tuple(
            (str(row[1]), str(row[2]), int(row[3]), int(row[5]))
            for row in connection.execute(f"PRAGMA table_info({table})")
        )
        if actual != columns:
            return (
                f"governance table {table!r} has columns (name, type, notnull, pk) "
                f"{actual}, not {columns} as schema {SCHEMA_VERSION} requires; "
                f"there is no migration path"
            )
        keys = tuple(
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute(f"PRAGMA foreign_key_list({table})")
        )
        if keys != EXPECTED_FOREIGN_KEYS[table]:
            return (
                f"governance table {table!r} declares foreign keys {keys}, not "
                f"{EXPECTED_FOREIGN_KEYS[table]} as schema {SCHEMA_VERSION} requires; "
                f"there is no migration path"
            )
        autoincrement = "AUTOINCREMENT" in _declared_sql(connection, table)
        if autoincrement != (table in AUTOINCREMENT_TABLES):
            return (
                f"governance table {table!r} "
                f"{'declares' if autoincrement else 'does not declare'} AUTOINCREMENT, "
                f"contrary to schema {SCHEMA_VERSION}; there is no migration path"
            )
    return ""


def open(path: str | Path) -> Store:  # noqa: A001 - the frozen name in §10's guard registry
    """Open `governance.sqlite`, creating the frozen schema if the file is untouched.

    Creation happens only for a database that is **unstamped and holds no application
    table at all**; anything else is verified and, if it does not match every guarantee
    §11's DDL makes, refused. The emptiness test is repeated under `BEGIN IMMEDIATE` so
    two processes opening a fresh store concurrently cannot both create it -- the loser
    waits, then verifies what the winner committed.

    Opening an existing, valid store takes **no write lock**: creation is the only path
    that begins a transaction, so an open never blocks behind a live writer.

    On refusal the connection is closed before the error leaves this function, and
    `sqlite3` failures -- a missing parent directory, a file that is not a database, a
    DDL failure -- are translated at this boundary (ST7-R03). `open` either returns a
    usable store or leaves nothing behind; there is no third outcome in which a handle
    survives a failure, and no outcome in which a vendor exception reaches the caller.
    """
    database = Path(path)
    try:
        connection = sqlite3.connect(database, isolation_level=None)
    except sqlite3.Error as exc:
        raise GovernedPlannerError(
            f"governance store at {database}: connect failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    opened = Store(connection, database)
    try:
        _apply_pragmas(connection)
        if _is_pristine(connection):
            with opened.transaction():
                if _is_pristine(connection):
                    _create_schema(connection)
        problem = _schema_incompatibility(connection)
        require(not problem, problem, error=StoreSchemaTooOld)  # guard:gp_store_schema_version
    except sqlite3.Error as exc:
        opened._close_quietly()
        raise opened._store_failure("open", exc) from exc
    except BaseException:
        opened._close_quietly()
        raise
    return opened
