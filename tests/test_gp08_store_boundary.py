"""GP-08 — the governance store persists and re-verifies; it never decides.

Design basis: design/GP-SPK-001-governance-kernel.md §12, §6, §9.

The plan of record's GP-08 row (revision 5 §14) reads:

    Schema-version refusal by version *and* by missing column, twice with identical
    messages and no leaked handle; a failed policy check leaves **zero** rows in
    `approval_consumptions`; `guard:gp_digest_rehash` fires on a tampered
    `canonical_preimage`; `put_artifact` refuses a blob whose hash != the claimed
    digest; concurrent `BEGIN IMMEDIATE` consumption resolves per §12

Two of those clauses name a *policy* check and a *consumption* decision, which live in
`kernel.py` (§12) and are built at ST-8. ST-7 implements `store.py` only, so this file
proves the storage half of each: that an operation failing inside a store transaction
leaves **zero** rows behind whatever raised it, and that two concurrent writers under
`BEGIN IMMEDIATE` serialize deterministically with exactly one consumption row
surviving. The kernel-level halves — that the thing which raised was a policy refusal,
and that the loser returns `applied=False` rather than an error — are ST-8's obligation
and are not claimed here.

What this file deliberately does **not** assert, because the store must not decide it:
whether a transition is legal, whether `HUMAN` authority suffices, whether an approval
is stale, whether a replay is valid, or whether an approval should be consumed. Those
are §10's ordering and the kernel's alone. The store is interrogated only as storage:
it writes what it is told, refuses what it structurally cannot hold, and re-derives
identity from the bytes it actually has rather than from what a caller asserts.
"""

from __future__ import annotations

import ast
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from conftest import Harness
from gplanner import store
from gplanner.artifacts import ArtifactRef, ScopeSpec
from gplanner.digest import (
    SCOPE_MEDIA_TYPE,
    canonical_preimage,
    compute_digest,
    digest_of_preimage_bytes,
)
from gplanner.errors import (
    ApprovalReplay,
    ConcurrentModification,
    DigestMismatch,
    GovernedPlannerError,
    StoreSchemaTooOld,
)
from gplanner.states import ScopeState
from gplanner.store import Store

SRC = Path(__file__).resolve().parents[1] / "src" / "gplanner"

WORKFLOW_ID = "gp-spk-001-case-0001"
OTHER_WORKFLOW_ID = "gp-spk-001-case-0002"
APPROVAL_ID = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a88"
OTHER_APPROVAL_ID = "0123456789abcdef0123456789abcdef"
ISSUED_AT = "2026-09-17T11:22:33Z"

# --- fixtures and builders -------------------------------------------------------


def spec(title: str = "Governance kernel feasibility") -> ScopeSpec:
    return ScopeSpec(
        title=title,
        problem_statement="Prove the authority model with no LLM in the loop.",
        in_scope=("digest-bound approvals",),
        out_of_scope=("signing",),
        acceptance_criteria=("the approval binds one digest",),
    )


def artifact_of(model: ScopeSpec) -> tuple[str, bytes]:
    """The digest and THE authoritative bytes, produced by the one §5 pipeline."""
    return compute_digest(model, SCOPE_MEDIA_TYPE), canonical_preimage(model, SCOPE_MEDIA_TYPE)


@pytest.fixture
def st(h: Harness) -> Iterator[Store]:
    with store.open(h.governance_db) as opened:
        yield opened


@pytest.fixture
def seeded(st: Store) -> tuple[Store, str, bytes]:
    """A store holding one artifact and one case in `SCOPE_REVIEW_PENDING`."""
    digest, blob = artifact_of(spec())
    st.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
    st.create_case(
        workflow_id=WORKFLOW_ID,
        state=ScopeState.SCOPE_REVIEW_PENDING,
        subject_digest=digest,
    )
    return st, digest, blob


def raw(path: Path) -> sqlite3.Connection:
    """A connection that bypasses the store entirely, for tamper and audit reads."""
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# =================================================================================
# Section 1 — schema creation and open on the current version
# =================================================================================


def test_open_creates_the_schema_and_stamps_the_storage_version(h: Harness) -> None:
    assert not h.governance_db.exists()
    with store.open(h.governance_db) as opened:
        assert isinstance(opened, Store)
    assert h.governance_db.exists()

    conn = raw(h.governance_db)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == store.STORAGE_VERSION
        names = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    finally:
        conn.close()
    assert {"artifacts", "cases", "approval_consumptions", "audit_events"} <= names


def test_the_domain_and_physical_versions_are_separate_statements() -> None:
    """§11 freezes two versions with two jobs; neither may stand in for the other."""
    assert store.SCHEMA_VERSION == "gplanner.governance/0.1.0"
    assert isinstance(store.SCHEMA_VERSION, str)
    assert store.STORAGE_VERSION == 1
    assert isinstance(store.STORAGE_VERSION, int)
    assert not isinstance(store.STORAGE_VERSION, bool)


def test_reopening_an_existing_store_verifies_rather_than_recreates(h: Harness) -> None:
    digest, blob = artifact_of(spec())
    with store.open(h.governance_db) as first:
        first.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
    with store.open(h.governance_db) as second:
        stored = second.get_artifact(digest)
    assert stored is not None
    assert stored.canonical_preimage == blob


def test_the_four_frozen_tables_carry_exactly_the_frozen_columns(h: Harness) -> None:
    """§11's DDL, column for column. A drift here changes what identity is stored in."""
    expected = {
        "artifacts": ["digest", "media_type", "canonical_preimage", "byte_len"],
        "cases": ["workflow_id", "state", "subject_digest", "revision"],
        "approval_consumptions": [
            "approval_id",
            "approval_digest",
            "subject_digest",
            "workflow_id",
            "from_state",
            "to_state",
            "consumed_at",
        ],
        "audit_events": ["seq", "workflow_id", "at", "event", "detail_json"],
    }
    with store.open(h.governance_db):
        pass
    conn = raw(h.governance_db)
    try:
        for table, columns in expected.items():
            info = list(conn.execute(f"PRAGMA table_info({table})"))
            assert [row[1] for row in info] == columns, table
    finally:
        conn.close()


def test_every_governance_table_is_strict(h: Harness) -> None:
    """STRICT is frozen by §11: a TEXT column may not silently hold an integer."""
    with store.open(h.governance_db):
        pass
    conn = raw(h.governance_db)
    try:
        strict = {
            row[1]: row[5]
            for row in conn.execute("PRAGMA table_list")
            if row[0] == "main" and row[2] == "table"
        }
        for table in ("artifacts", "cases", "approval_consumptions", "audit_events"):
            assert strict[table] == 1, table
    finally:
        conn.close()


def test_the_frozen_pragmas_are_actually_in_force(h: Harness) -> None:
    with store.open(h.governance_db) as opened:
        effective = opened.effective_pragmas()
    assert effective["journal_mode"] == "wal"
    assert effective["synchronous"] == 2  # FULL
    assert effective["foreign_keys"] == 1
    assert effective["busy_timeout"] == 10000


def test_the_pragma_table_is_the_one_frozen_by_the_plan() -> None:
    assert store.PRAGMAS == (
        ("journal_mode", "WAL"),
        ("synchronous", "FULL"),
        ("foreign_keys", "ON"),
        ("busy_timeout", "10000"),
    )


# =================================================================================
# Section 2 — schema refusal: by version, by structure, twice, with no leaked handle
# =================================================================================


def _prepared(path: Path, *, sql: list[str], user_version: int) -> None:
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        for statement in sql:
            conn.execute(statement)
        conn.execute(f"PRAGMA user_version = {user_version}")
    finally:
        conn.close()


def _current_ddl() -> list[str]:
    return list(store.SCHEMA_SQL)


def test_a_newer_storage_version_is_refused(h: Harness) -> None:
    _prepared(h.governance_db, sql=_current_ddl(), user_version=store.STORAGE_VERSION + 1)
    with pytest.raises(StoreSchemaTooOld) as caught:
        store.open(h.governance_db)
    assert str(store.STORAGE_VERSION) in str(caught.value)


def test_a_stale_unstamped_database_that_already_has_tables_is_refused(h: Harness) -> None:
    """`user_version` defaults to 0, so structure alone cannot be read as "new"."""
    _prepared(h.governance_db, sql=_current_ddl(), user_version=0)
    with pytest.raises(StoreSchemaTooOld):
        store.open(h.governance_db)


def test_a_missing_column_is_refused_even_at_the_current_version(h: Harness) -> None:
    """§11: refused structurally via `PRAGMA table_info`, not only by `user_version`."""
    ddl = [
        sql.replace("byte_len INTEGER NOT NULL", "byte_len_renamed INTEGER NOT NULL")
        if "CREATE TABLE artifacts" in sql
        else sql
        for sql in _current_ddl()
    ]
    _prepared(h.governance_db, sql=ddl, user_version=store.STORAGE_VERSION)
    with pytest.raises(StoreSchemaTooOld) as caught:
        store.open(h.governance_db)
    assert "artifacts" in str(caught.value)


def test_a_missing_table_is_refused_even_at_the_current_version(h: Harness) -> None:
    ddl = [sql for sql in _current_ddl() if "CREATE TABLE audit_events" not in sql]
    _prepared(h.governance_db, sql=ddl, user_version=store.STORAGE_VERSION)
    with pytest.raises(StoreSchemaTooOld) as caught:
        store.open(h.governance_db)
    assert "audit_events" in str(caught.value)


def test_a_non_strict_table_is_refused_even_with_the_right_columns(h: Harness) -> None:
    ddl = [sql.replace(") STRICT", ")") for sql in _current_ddl()]
    _prepared(h.governance_db, sql=ddl, user_version=store.STORAGE_VERSION)
    with pytest.raises(StoreSchemaTooOld) as caught:
        store.open(h.governance_db)
    assert "STRICT" in str(caught.value)


@pytest.mark.parametrize(
    ("label", "prepare"),
    [
        (
            "version",
            lambda p: _prepared(p, sql=_current_ddl(), user_version=store.STORAGE_VERSION + 1),
        ),
        (
            "missing-column",
            lambda p: _prepared(
                p,
                sql=[
                    sql.replace("byte_len INTEGER NOT NULL", "byte_len_renamed INTEGER NOT NULL")
                    if "CREATE TABLE artifacts" in sql
                    else sql
                    for sql in _current_ddl()
                ],
                user_version=store.STORAGE_VERSION,
            ),
        ),
    ],
    ids=["version", "missing-column"],
)
def test_repeated_refusal_is_deterministic_and_leaks_no_handle(
    h: Harness,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    prepare: Callable[[Path], None],
) -> None:
    """Twice, identical message, and every connection the store opened is closed.

    A store that refuses but keeps the handle would hold a WAL lock for the life of
    the process, so the second operator attempt fails for a different reason than the
    first. The refusal is only useful if it leaves nothing behind.
    """
    prepare(h.governance_db)

    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def recording_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        conn = real_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", recording_connect)

    messages: list[str] = []
    for _ in range(2):
        with pytest.raises(StoreSchemaTooOld) as caught:
            store.open(h.governance_db)
        messages.append(str(caught.value))

    assert messages[0] == messages[1], f"{label} refusal is not deterministic"
    assert len(opened) == 2, "expected exactly one connection per refused open"
    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


# =================================================================================
# Section 3 — artifacts: the stored bytes are the identity, on write and on read
# =================================================================================


def test_put_artifact_verifies_the_blob_against_the_claimed_digest(st: Store) -> None:
    digest, blob = artifact_of(spec())
    ref = st.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
    assert isinstance(ref, ArtifactRef)
    assert ref.digest == digest
    assert ref.media_type == SCOPE_MEDIA_TYPE
    assert ref.byte_len == len(blob)


def test_put_artifact_refuses_a_blob_whose_hash_is_not_the_claimed_digest(st: Store) -> None:
    """`guard:gp_digest_rehash` on the write path — the claim is never taken on trust."""
    digest, blob = artifact_of(spec())
    other_digest, _ = artifact_of(spec(title="A different scope"))
    assert other_digest != digest
    with pytest.raises(DigestMismatch):
        st.put_artifact(
            digest=other_digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob
        )
    assert st.get_artifact(other_digest) is None
    assert st.get_artifact(digest) is None


def test_a_refused_put_writes_no_row(st: Store, h: Harness) -> None:
    digest, blob = artifact_of(spec())
    other_digest, _ = artifact_of(spec(title="A different scope"))
    with pytest.raises(DigestMismatch):
        st.put_artifact(
            digest=other_digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob
        )
    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 0
    finally:
        conn.close()


def test_get_artifact_returns_the_authoritative_bytes_verbatim(st: Store) -> None:
    digest, blob = artifact_of(spec())
    st.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
    stored = st.get_artifact(digest)
    assert stored is not None
    assert stored.canonical_preimage == blob
    assert digest_of_preimage_bytes(stored.canonical_preimage) == digest
    assert stored.ref.digest == digest
    assert stored.ref.byte_len == len(blob)


def test_get_artifact_re_verifies_and_refuses_a_tampered_preimage(st: Store, h: Harness) -> None:
    """`guard:gp_digest_rehash` on the read path (GK-INV-1)."""
    digest, blob = artifact_of(spec())
    st.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)

    tampered = blob.replace(b"feasibility", b"feasibilitY")
    assert tampered != blob and len(tampered) == len(blob)
    conn = raw(h.governance_db)
    try:
        conn.execute(
            "UPDATE artifacts SET canonical_preimage = ? WHERE digest = ?", (tampered, digest)
        )
    finally:
        conn.close()

    with pytest.raises(DigestMismatch) as caught:
        st.get_artifact(digest)
    assert digest in str(caught.value)


def test_byte_len_is_derived_from_the_bytes_and_never_taken_from_the_caller(
    st: Store, h: Harness
) -> None:
    """The column is a convenience for external readers; the blob is the authority."""
    digest, blob = artifact_of(spec())
    st.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
    conn = raw(h.governance_db)
    try:
        stored_len, actual_len = conn.execute(
            "SELECT byte_len, length(canonical_preimage) FROM artifacts WHERE digest = ?",
            (digest,),
        ).fetchone()
    finally:
        conn.close()
    assert stored_len == actual_len == len(blob)

    stored = st.get_artifact(digest)
    assert stored is not None
    assert stored.ref.byte_len == len(stored.canonical_preimage)


def test_a_zero_length_preimage_cannot_be_stored(st: Store) -> None:
    """`ArtifactRef.byte_len >= 1`: a stored artifact has content, by model constraint."""
    with pytest.raises(ValidationError):
        st.put_artifact(
            digest=digest_of_preimage_bytes(b""),
            media_type=SCOPE_MEDIA_TYPE,
            canonical_preimage=b"",
        )


def test_putting_the_same_artifact_twice_is_idempotent(st: Store, h: Harness) -> None:
    digest, blob = artifact_of(spec())
    first = st.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
    second = st.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
    assert first == second
    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 1
    finally:
        conn.close()


def test_an_absent_artifact_is_reported_as_absent_not_as_a_refusal(st: Store) -> None:
    """Absence is a fact for the caller to interpret, never a governance verdict."""
    absent, _ = artifact_of(spec(title="never stored"))
    assert st.get_artifact(absent) is None


# =================================================================================
# Section 4 — transactions: one BEGIN IMMEDIATE, and rollback on BaseException
# =================================================================================


def test_a_failure_inside_a_transaction_rolls_every_write_back(
    seeded: tuple[Store, str, bytes], h: Harness
) -> None:
    st, digest, _ = seeded

    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        with st.transaction():
            st.record_consumption(
                approval_id=APPROVAL_ID,
                approval_digest=digest,
                subject_digest=digest,
                workflow_id=WORKFLOW_ID,
                from_state=ScopeState.SCOPE_REVIEW_PENDING,
                to_state=ScopeState.SCOPE_APPROVED,
                consumed_at=ISSUED_AT,
            )
            st.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.approved", detail_json=b"{}"
            )
            raise Boom("whatever raised, the transaction leaves nothing behind")

    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
    finally:
        conn.close()
    assert st.find_consumption(APPROVAL_ID) is None


def test_rollback_covers_baseexception_not_only_exception(
    seeded: tuple[Store, str, bytes],
) -> None:
    """`except BaseException: ROLLBACK; raise` — a KeyboardInterrupt must not commit."""
    st, digest, _ = seeded
    with pytest.raises(KeyboardInterrupt):
        with st.transaction():
            st.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.submitted", detail_json=b"{}"
            )
            raise KeyboardInterrupt
    assert st.read_audit(WORKFLOW_ID) == ()


def test_a_transaction_that_completes_commits_and_the_store_is_usable_after(
    seeded: tuple[Store, str, bytes],
) -> None:
    st, digest, _ = seeded
    with st.transaction():
        st.append_audit(
            workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.submitted", detail_json=b"{}"
        )
    assert len(st.read_audit(WORKFLOW_ID)) == 1
    with st.transaction():
        st.append_audit(
            workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.approved", detail_json=b"{}"
        )
    assert len(st.read_audit(WORKFLOW_ID)) == 2


def test_nested_transactions_are_one_transaction_so_the_kernel_can_compose(
    seeded: tuple[Store, str, bytes], h: Harness
) -> None:
    """§10 runs every step inside ONE `BEGIN IMMEDIATE`; store calls nest into it."""
    st, digest, _ = seeded

    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        with st.transaction():
            st.record_consumption(
                approval_id=APPROVAL_ID,
                approval_digest=digest,
                subject_digest=digest,
                workflow_id=WORKFLOW_ID,
                from_state=ScopeState.SCOPE_REVIEW_PENDING,
                to_state=ScopeState.SCOPE_APPROVED,
                consumed_at=ISSUED_AT,
            )
            st.advance_case(
                workflow_id=WORKFLOW_ID,
                to_state=ScopeState.SCOPE_APPROVED,
                expected_revision=store.INITIAL_REVISION,
            )
            raise Boom("the inner writes belong to the outer transaction")

    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0] == 0
        state = conn.execute(
            "SELECT state FROM cases WHERE workflow_id = ?", (WORKFLOW_ID,)
        ).fetchone()[0]
        assert state == ScopeState.SCOPE_REVIEW_PENDING
    finally:
        conn.close()


def test_a_standalone_write_is_durable_without_an_explicit_transaction(
    seeded: tuple[Store, str, bytes], h: Harness
) -> None:
    st, digest, _ = seeded
    st.append_audit(
        workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.submitted", detail_json=b"{}"
    )
    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
    finally:
        conn.close()


# =================================================================================
# Section 5 — cases and the revision compare-and-set
# =================================================================================


def test_create_case_starts_at_the_initial_revision(seeded: tuple[Store, str, bytes]) -> None:
    st, digest, _ = seeded
    case = st.load_case(WORKFLOW_ID)
    assert case is not None
    assert case.workflow_id == WORKFLOW_ID
    assert case.state is ScopeState.SCOPE_REVIEW_PENDING
    assert case.subject_digest == digest
    assert case.revision == store.INITIAL_REVISION


def test_an_absent_case_is_reported_as_absent(st: Store) -> None:
    assert st.load_case("gp-spk-001-no-such-case") is None


def test_the_case_state_round_trips_as_a_scope_state(seeded: tuple[Store, str, bytes]) -> None:
    st, _, _ = seeded
    case = st.load_case(WORKFLOW_ID)
    assert case is not None
    assert isinstance(case.state, ScopeState)


def test_advance_case_succeeds_only_for_the_expected_revision(
    seeded: tuple[Store, str, bytes],
) -> None:
    st, _, _ = seeded
    advanced = st.advance_case(
        workflow_id=WORKFLOW_ID,
        to_state=ScopeState.SCOPE_APPROVED,
        expected_revision=store.INITIAL_REVISION,
    )
    assert advanced.state is ScopeState.SCOPE_APPROVED
    assert advanced.revision == store.INITIAL_REVISION + 1
    reloaded = st.load_case(WORKFLOW_ID)
    assert reloaded == advanced


def test_a_stale_revision_raises_concurrent_modification(
    seeded: tuple[Store, str, bytes],
) -> None:
    """`guard:gp_case_revision_cas`."""
    st, _, _ = seeded
    st.advance_case(
        workflow_id=WORKFLOW_ID,
        to_state=ScopeState.SCOPE_APPROVED,
        expected_revision=store.INITIAL_REVISION,
    )
    with pytest.raises(ConcurrentModification):
        st.advance_case(
            workflow_id=WORKFLOW_ID,
            to_state=ScopeState.SCOPE_APPROVED,
            expected_revision=store.INITIAL_REVISION,
        )


def test_a_lost_cas_changes_nothing(seeded: tuple[Store, str, bytes]) -> None:
    st, _, _ = seeded
    with pytest.raises(ConcurrentModification):
        st.advance_case(
            workflow_id=WORKFLOW_ID,
            to_state=ScopeState.SCOPE_APPROVED,
            expected_revision=store.INITIAL_REVISION + 7,
        )
    case = st.load_case(WORKFLOW_ID)
    assert case is not None
    assert case.state is ScopeState.SCOPE_REVIEW_PENDING
    assert case.revision == store.INITIAL_REVISION


def test_advancing_an_absent_case_is_a_lost_cas(st: Store) -> None:
    """A missing row and a stale revision are one fact at the SQL level: not there."""
    with pytest.raises(ConcurrentModification):
        st.advance_case(
            workflow_id="gp-spk-001-no-such-case",
            to_state=ScopeState.SCOPE_APPROVED,
            expected_revision=store.INITIAL_REVISION,
        )


def test_the_store_advances_a_case_along_an_edge_policy_would_refuse(
    seeded: tuple[Store, str, bytes],
) -> None:
    """The store holds NO policy (§4, §11). Legality is `policy.py`'s alone.

    Asserted rather than left implicit: if the store ever started refusing edges, there
    would be two authority models, and the declarative table would no longer be the
    only one.
    """
    st, _, _ = seeded
    advanced = st.advance_case(
        workflow_id=WORKFLOW_ID,
        to_state=ScopeState.SCOPE_DRAFTING,  # backward: absent from LEGAL_TRANSITIONS
        expected_revision=store.INITIAL_REVISION,
    )
    assert advanced.state is ScopeState.SCOPE_DRAFTING


# =================================================================================
# Section 6 — approval consumptions: uniqueness is structural
# =================================================================================


def _consume(st: Store, digest: str, *, approval_id: str = APPROVAL_ID, wfid: str = WORKFLOW_ID):
    return st.record_consumption(
        approval_id=approval_id,
        approval_digest=digest,
        subject_digest=digest,
        workflow_id=wfid,
        from_state=ScopeState.SCOPE_REVIEW_PENDING,
        to_state=ScopeState.SCOPE_APPROVED,
        consumed_at=ISSUED_AT,
    )


def test_a_consumption_row_round_trips(seeded: tuple[Store, str, bytes]) -> None:
    st, digest, _ = seeded
    written = _consume(st, digest)
    found = st.find_consumption(APPROVAL_ID)
    assert found == written
    assert found is not None
    assert found.approval_id == APPROVAL_ID
    assert found.workflow_id == WORKFLOW_ID
    assert found.from_state is ScopeState.SCOPE_REVIEW_PENDING
    assert found.to_state is ScopeState.SCOPE_APPROVED
    assert found.consumed_at == ISSUED_AT


def test_an_unconsumed_approval_id_is_reported_as_absent(
    seeded: tuple[Store, str, bytes],
) -> None:
    """The store reports the fact; §10 step 4 decides what it means."""
    st, _, _ = seeded
    assert st.find_consumption(OTHER_APPROVAL_ID) is None


def test_approval_id_uniqueness_is_enforced_by_the_primary_key(
    seeded: tuple[Store, str, bytes], h: Harness
) -> None:
    st, digest, _ = seeded
    _consume(st, digest)
    with pytest.raises(ApprovalReplay):
        _consume(st, digest)
    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0] == 1
    finally:
        conn.close()


def test_the_same_approval_id_under_a_different_workflow_is_still_refused(
    seeded: tuple[Store, str, bytes],
) -> None:
    """Structural single use: the PRIMARY KEY is on `approval_id` and nothing else."""
    st, digest, _ = seeded
    _consume(st, digest)
    with pytest.raises(ApprovalReplay):
        _consume(st, digest, wfid=OTHER_WORKFLOW_ID)


def test_the_primary_key_is_on_approval_id_alone(h: Harness) -> None:
    with store.open(h.governance_db):
        pass
    conn = raw(h.governance_db)
    try:
        info = list(conn.execute("PRAGMA table_info(approval_consumptions)"))
    finally:
        conn.close()
    assert [row[1] for row in info if row[5]] == ["approval_id"]


def test_a_different_approval_id_is_recorded_independently(
    seeded: tuple[Store, str, bytes],
) -> None:
    st, digest, _ = seeded
    _consume(st, digest)
    _consume(st, digest, approval_id=OTHER_APPROVAL_ID)
    assert st.find_consumption(APPROVAL_ID) is not None
    assert st.find_consumption(OTHER_APPROVAL_ID) is not None


# =================================================================================
# Section 7 — audit events: append-only, deterministic order
# =================================================================================


def test_audit_append_returns_a_strictly_increasing_sequence(
    seeded: tuple[Store, str, bytes],
) -> None:
    st, _, _ = seeded
    first = st.append_audit(
        workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.opened", detail_json=b'{"n":1}'
    )
    second = st.append_audit(
        workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.submitted", detail_json=b'{"n":2}'
    )
    third = st.append_audit(
        workflow_id=OTHER_WORKFLOW_ID, at=ISSUED_AT, event="scope.opened", detail_json=b'{"n":3}'
    )
    assert first.seq < second.seq < third.seq


def test_audit_read_is_ordered_by_sequence_and_filtered_by_workflow(
    seeded: tuple[Store, str, bytes],
) -> None:
    st, _, _ = seeded
    st.append_audit(
        workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.opened", detail_json=b'{"n":1}'
    )
    st.append_audit(
        workflow_id=OTHER_WORKFLOW_ID, at=ISSUED_AT, event="scope.opened", detail_json=b'{"n":2}'
    )
    st.append_audit(
        workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.submitted", detail_json=b'{"n":3}'
    )

    mine = st.read_audit(WORKFLOW_ID)
    assert [record.event for record in mine] == ["scope.opened", "scope.submitted"]
    assert [record.seq for record in mine] == sorted(record.seq for record in mine)
    assert all(record.workflow_id == WORKFLOW_ID for record in mine)

    everything = st.read_audit()
    assert [record.seq for record in everything] == sorted(r.seq for r in everything)
    assert len(everything) == 3


def test_audit_detail_is_stored_as_opaque_bytes(seeded: tuple[Store, str, bytes]) -> None:
    """`detail_json` is a BLOB the store never parses: it holds no JSON decoder (§7)."""
    st, _, _ = seeded
    detail = b'{"row":"SPK1-2","note":"\xc2\xa7"}'
    written = st.append_audit(
        workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.approved", detail_json=detail
    )
    assert written.detail_json == detail
    read_back = st.read_audit(WORKFLOW_ID)
    assert read_back[0].detail_json == detail
    assert isinstance(read_back[0].detail_json, bytes)


def test_audit_is_append_only_by_convention_and_nothing_here_deletes(
    seeded: tuple[Store, str, bytes],
) -> None:
    """Recorded as a known gap: there is no chaining and no tamper detection yet."""
    st, _, _ = seeded
    assert not hasattr(st, "delete_audit")
    assert not hasattr(st, "truncate_audit")


# =================================================================================
# Section 8 — foreign keys are actually enforced
# =================================================================================


def test_a_case_cannot_reference_an_artifact_that_was_never_stored(st: Store) -> None:
    absent, _ = artifact_of(spec(title="never stored"))
    with pytest.raises(GovernedPlannerError):
        st.create_case(
            workflow_id=WORKFLOW_ID,
            state=ScopeState.SCOPE_DRAFTING,
            subject_digest=absent,
        )
    assert st.load_case(WORKFLOW_ID) is None


def test_the_foreign_key_is_declared_on_cases_subject_digest(h: Harness) -> None:
    with store.open(h.governance_db):
        pass
    conn = raw(h.governance_db)
    try:
        keys = list(conn.execute("PRAGMA foreign_key_list(cases)"))
    finally:
        conn.close()
    assert [(row[2], row[3], row[4]) for row in keys] == [
        ("artifacts", "subject_digest", "digest")
    ]


def test_foreign_keys_are_enforced_on_the_stores_own_connection(
    seeded: tuple[Store, str, bytes], h: Harness
) -> None:
    """`foreign_keys` is per-connection, so declaring the key is not enough."""
    st, digest, _ = seeded
    conn = raw(h.governance_db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM artifacts WHERE digest = ?", (digest,))
    finally:
        conn.close()
    assert st.effective_pragmas()["foreign_keys"] == 1


def test_creating_the_same_case_twice_is_refused(seeded: tuple[Store, str, bytes]) -> None:
    st, digest, _ = seeded
    with pytest.raises(GovernedPlannerError):
        st.create_case(
            workflow_id=WORKFLOW_ID,
            state=ScopeState.SCOPE_DRAFTING,
            subject_digest=digest,
        )
    case = st.load_case(WORKFLOW_ID)
    assert case is not None
    assert case.state is ScopeState.SCOPE_REVIEW_PENDING


def test_no_vendor_exception_escapes_the_store(seeded: tuple[Store, str, bytes]) -> None:
    """Adapters translate their own failures (errors.py); `sqlite3` never escapes."""
    st, digest, _ = seeded
    _consume(st, digest)
    for call in (
        lambda: _consume(st, digest),
        lambda: st.create_case(
            workflow_id=WORKFLOW_ID, state=ScopeState.SCOPE_DRAFTING, subject_digest=digest
        ),
    ):
        with pytest.raises(GovernedPlannerError):
            call()


# =================================================================================
# Section 9 — BEGIN IMMEDIATE serializes concurrent writers
# =================================================================================

HOLD_SECONDS = 0.5


def test_begin_immediate_serializes_two_concurrent_writers(h: Harness) -> None:
    """The second writer waits for the first to commit; it does not see SQLITE_BUSY.

    `busy_timeout=10000` plus `BEGIN IMMEDIATE` is what turns a lock collision into a
    wait rather than an error. The assertion is on the *order of committed effects*,
    not on elapsed time alone: the second writer's transaction begins only after the
    first has committed.
    """
    digest, blob = artifact_of(spec())
    with store.open(h.governance_db) as setup:
        setup.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)

    holder_has_lock = threading.Event()
    marks: dict[str, float] = {}
    failures: list[BaseException] = []

    def holder() -> None:
        try:
            with store.open(h.governance_db) as first:
                with first.transaction():
                    first.append_audit(
                        workflow_id=WORKFLOW_ID,
                        at=ISSUED_AT,
                        event="holder",
                        detail_json=b"{}",
                    )
                    holder_has_lock.set()
                    time.sleep(HOLD_SECONDS)
                marks["holder_committed"] = time.monotonic()
        except BaseException as exc:  # noqa: BLE001 - recorded and re-raised by the assert
            failures.append(exc)

    def waiter() -> None:
        try:
            assert holder_has_lock.wait(timeout=30.0)
            marks["waiter_started"] = time.monotonic()
            with store.open(h.governance_db) as second:
                with second.transaction():
                    second.append_audit(
                        workflow_id=WORKFLOW_ID,
                        at=ISSUED_AT,
                        event="waiter",
                        detail_json=b"{}",
                    )
                marks["waiter_committed"] = time.monotonic()
        except BaseException as exc:  # noqa: BLE001
            failures.append(exc)

    threads = [threading.Thread(target=holder), threading.Thread(target=waiter)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60.0)
        assert not thread.is_alive()

    assert not failures, failures
    assert marks["waiter_started"] < marks["holder_committed"] < marks["waiter_committed"]

    with store.open(h.governance_db) as reader:
        events = [record.event for record in reader.read_audit(WORKFLOW_ID)]
    assert events == ["holder", "waiter"]


def test_concurrent_consumption_of_one_approval_id_leaves_exactly_one_row(
    h: Harness,
) -> None:
    """The storage half of §12's concurrency clause.

    Two writers claim the same `approval_id` at the same time. `BEGIN IMMEDIATE`
    serializes them, so exactly one row exists and the loser is refused structurally
    rather than racing. What the loser should *return* — §12's `applied=False` replay
    branch — is the kernel's decision and is proven by GP-07 at ST-8, not here.
    """
    digest, blob = artifact_of(spec())
    with store.open(h.governance_db) as setup:
        setup.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
        setup.create_case(
            workflow_id=WORKFLOW_ID,
            state=ScopeState.SCOPE_REVIEW_PENDING,
            subject_digest=digest,
        )

    start = threading.Barrier(2, timeout=30.0)
    outcomes: list[str] = []
    lock = threading.Lock()

    def claim() -> None:
        with store.open(h.governance_db) as worker:
            start.wait()
            try:
                with worker.transaction():
                    _consume(worker, digest)
                    worker.advance_case(
                        workflow_id=WORKFLOW_ID,
                        to_state=ScopeState.SCOPE_APPROVED,
                        expected_revision=store.INITIAL_REVISION,
                    )
                result = "claimed"
            except ApprovalReplay:
                result = "refused-replay"
            except ConcurrentModification:
                result = "refused-cas"
            with lock:
                outcomes.append(result)

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60.0)
        assert not thread.is_alive()

    assert sorted(outcomes) == ["claimed", "refused-replay"]

    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0] == 1
        state = conn.execute(
            "SELECT state FROM cases WHERE workflow_id = ?", (WORKFLOW_ID,)
        ).fetchone()[0]
        assert state == ScopeState.SCOPE_APPROVED
        assert conn.execute("SELECT revision FROM cases").fetchone()[0] == (
            store.INITIAL_REVISION + 1
        )
    finally:
        conn.close()


# =================================================================================
# Section 10 — the boundary itself
# =================================================================================


def test_store_imports_neither_dbos_nor_json() -> None:
    """§4: the governance layer is provable with the engine absent; §7: one decode path."""
    tree = ast.parse((SRC / "store.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "dbos" not in imported
    assert "json" not in imported
    assert not {"anthropic", "openai"} & imported


def test_store_imports_no_policy_module() -> None:
    """`store.py` never consults `policy.py`: legality is not a storage question."""
    source = (SRC / "store.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "gplanner.policy" not in modules
    assert "gplanner.approvals" not in modules


def test_the_module_docstring_cites_its_design_basis() -> None:
    docstring = ast.get_docstring(ast.parse((SRC / "store.py").read_text(encoding="utf-8")))
    assert docstring is not None
    assert "Design basis: design/GP-SPK-001-governance-kernel.md §" in docstring


def test_exactly_the_three_gp08_guard_ids_are_marked_in_the_store() -> None:
    """The frozen registry (plan §10) owns these IDs; ST-7 implements its three.

    Keyed on the **marker comment** -- `# guard:<id>` -- because that is the form
    GP-SPK-002's mutation harness reads, and because prose elsewhere in the module
    legitimately names a guard in order to say where it does *not* live.
    """
    source = (SRC / "store.py").read_text(encoding="utf-8")
    marked = set(re.findall(r"#\s*(guard:[a-z_]+)", source))
    assert marked == {
        "guard:gp_digest_rehash",
        "guard:gp_case_revision_cas",
        "guard:gp_store_schema_version",
    }
    assert "# guard:gp_approval_replay" not in source, (
        "the replay guard is registered at kernel._consumption_branch (ST-8), not here"
    )


def test_the_rehash_guard_is_marked_on_both_the_write_and_the_read_path() -> None:
    """Plan §10 registers `gp_digest_rehash` at `put_artifact` *and* `get_artifact`."""
    source = (SRC / "store.py").read_text(encoding="utf-8")
    assert source.count("# guard:gp_digest_rehash") == 2


# =================================================================================
# Section 11 — ST-7 remediation regressions (ST7-R01, ST7-R02, ST7-R03)
#
# Each case below was independently reproduced against the pre-remediation store and
# recorded in `.coord/st7_remediation_evidence/before_remediation.json`. They are kept
# in one section so the frozen finding each answers stays legible.
# =================================================================================

# --- ST7-R01: incompatible schemas must be refused, not accepted -----------------

#: Each variant keeps `user_version = 1`, the frozen column names and types, and STRICT,
#: and breaks exactly one other property of §11's DDL. Every one of them opened cleanly
#: before remediation.
INCOMPATIBLE_SCHEMAS: dict[str, Callable[[tuple[str, ...]], list[str]]] = {
    "consumption_without_pk": lambda ddl: [
        s.replace("approval_id TEXT PRIMARY KEY", "approval_id TEXT NOT NULL") for s in ddl
    ],
    "cases_without_fk": lambda ddl: [
        s.replace(" REFERENCES artifacts(digest)", "") for s in ddl
    ],
    "nullable_required_column": lambda ddl: [
        s.replace("consumed_at TEXT NOT NULL", "consumed_at TEXT") for s in ddl
    ],
    "audit_without_autoincrement": lambda ddl: [
        s.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INTEGER PRIMARY KEY") for s in ddl
    ],
    "extra_governance_table": lambda ddl: [
        *ddl,
        "CREATE TABLE schema_meta (version TEXT) STRICT",
    ],
}


@pytest.mark.parametrize("variant", sorted(INCOMPATIBLE_SCHEMAS))
def test_r01_an_incompatible_schema_is_refused_even_when_columns_and_strict_match(
    h: Harness, variant: str
) -> None:
    """The frozen DDL's guarantees are part of the contract, not decoration.

    A primary key, a foreign key, a NOT NULL and an AUTOINCREMENT each carry a
    governance property: single use, referential integrity, required facts, and
    non-reused audit sequence numbers. A database that has the right column names and
    types but has lost one of them is not this schema.
    """
    _prepared(
        h.governance_db,
        sql=INCOMPATIBLE_SCHEMAS[variant](store.SCHEMA_SQL),
        user_version=store.STORAGE_VERSION,
    )
    with pytest.raises(StoreSchemaTooOld):
        store.open(h.governance_db)


def test_r01_a_schema_without_the_approval_id_primary_key_cannot_be_used_at_all(
    h: Harness,
) -> None:
    """The observed consequence, asserted directly: two rows for one `approval_id`.

    Refusing the schema is what makes `test_approval_id_uniqueness_is_enforced_by_the
    _primary_key` a property of every store this module will open, rather than only of
    ones it created itself.
    """
    _prepared(
        h.governance_db,
        sql=INCOMPATIBLE_SCHEMAS["consumption_without_pk"](store.SCHEMA_SQL),
        user_version=store.STORAGE_VERSION,
    )
    with pytest.raises(StoreSchemaTooOld):
        store.open(h.governance_db)
    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0] == 0
    finally:
        conn.close()


def test_r01_a_schema_without_the_subject_foreign_key_is_refused(h: Harness) -> None:
    """`foreign_keys = ON` enforces a key that is declared; it cannot supply a missing one."""
    _prepared(
        h.governance_db,
        sql=INCOMPATIBLE_SCHEMAS["cases_without_fk"](store.SCHEMA_SQL),
        user_version=store.STORAGE_VERSION,
    )
    with pytest.raises(StoreSchemaTooOld) as caught:
        store.open(h.governance_db)
    assert "cases" in str(caught.value)


def test_r01_an_unstamped_database_holding_an_unrelated_table_is_refused_not_augmented(
    h: Harness,
) -> None:
    """Initialization is for a genuinely empty file, not for "none of *our* tables".

    Before remediation this classified as untouched: `open` added the four governance
    tables beside the stranger and stamped version 1, producing a five-table database
    the contract never describes.
    """
    conn = raw(h.governance_db)
    try:
        conn.execute("CREATE TABLE unrelated (v TEXT) STRICT")
    finally:
        conn.close()

    with pytest.raises(StoreSchemaTooOld):
        store.open(h.governance_db)

    conn = raw(h.governance_db)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        names = sorted(
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        )
    finally:
        conn.close()
    assert names == ["unrelated"], "the refused database must not be augmented"


def test_r01_the_implicit_sqlite_sequence_table_is_not_an_unauthorized_table(
    h: Harness,
) -> None:
    """`AUTOINCREMENT` makes SQLite create `sqlite_sequence`. It is SQLite's, not ours.

    The exact-table-set check must not mistake it for a fifth governance table, or
    every store this module creates would refuse to reopen.
    """
    with store.open(h.governance_db) as first:
        first.append_audit(
            workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="scope.opened", detail_json=b"{}"
        )
    conn = raw(h.governance_db)
    try:
        names = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    finally:
        conn.close()
    assert "sqlite_sequence" in names
    with store.open(h.governance_db) as second:
        assert len(second.read_audit(WORKFLOW_ID)) == 1


def test_r01_incompatible_schema_refusal_is_deterministic_and_leaks_no_handle(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The §4 obligation extends to the structural cases R01 added."""
    _prepared(
        h.governance_db,
        sql=INCOMPATIBLE_SCHEMAS["cases_without_fk"](store.SCHEMA_SQL),
        user_version=store.STORAGE_VERSION,
    )
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def recording_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        conn = real_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", recording_connect)

    messages: list[str] = []
    for _ in range(2):
        with pytest.raises(StoreSchemaTooOld) as caught:
            store.open(h.governance_db)
        messages.append(str(caught.value))

    assert messages[0] == messages[1]
    assert len(opened) == 2
    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


# --- ST7-R02: COMMIT belongs inside the protected lifecycle ----------------------


def _deny_commit(action: int, arg1: str | None, arg2: str | None, db: str | None,
                 source: str | None) -> int:
    """A real SQLite authorizer refusal of COMMIT: no SQL is replaced, no schema changed."""
    if action == sqlite3.SQLITE_TRANSACTION and arg1 == "COMMIT":
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


class _InterruptAtCommit:
    """A connection proxy that raises `KeyboardInterrupt` when COMMIT is executed.

    Fault injection for the one path an authorizer cannot express: a `BaseException`
    arriving *during* commit rather than a SQLite refusal of it. Everything else is
    delegated to the real connection unchanged.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
        if sql == "COMMIT":
            raise KeyboardInterrupt
        return self._connection.execute(sql, *args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


def test_r02_a_refused_commit_does_not_report_success(h: Harness) -> None:
    with store.open(h.governance_db) as st:
        st._connection.set_authorizer(_deny_commit)
        with pytest.raises(GovernedPlannerError):
            st.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="denied", detail_json=b"{}"
            )
        st._connection.set_authorizer(None)


def test_r02_a_refused_commit_leaves_no_active_transaction_and_no_write_lock(
    h: Harness,
) -> None:
    """The write lock must be released, or every later writer blocks behind a ghost."""
    with store.open(h.governance_db) as st:
        st._connection.set_authorizer(_deny_commit)
        with pytest.raises(GovernedPlannerError):
            st.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="denied", detail_json=b"{}"
            )
        st._connection.set_authorizer(None)
        assert not st._connection.in_transaction

    with store.open(h.governance_db) as other:
        other.append_audit(
            workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="unblocked", detail_json=b"{}"
        )
        assert [record.event for record in other.read_audit(WORKFLOW_ID)] == ["unblocked"]


def test_r02_the_operation_after_a_refused_commit_is_actually_durable(h: Harness) -> None:
    """The exact pre-remediation defect: the next call *returned success* and committed nothing.

    A failed commit left the transaction open, so the following standalone write took
    the reentrant pass-through branch, never committed, and reported success anyway.
    """
    with store.open(h.governance_db) as st:
        st._connection.set_authorizer(_deny_commit)
        with pytest.raises(GovernedPlannerError):
            st.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="denied", detail_json=b"{}"
            )
        st._connection.set_authorizer(None)
        st.append_audit(
            workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="recovered", detail_json=b"{}"
        )

    conn = raw(h.governance_db)
    try:
        rows = conn.execute("SELECT event FROM audit_events ORDER BY seq").fetchall()
    finally:
        conn.close()
    assert [row[0] for row in rows] == ["recovered"]


def test_r02_an_interrupt_during_commit_leaves_nothing_pending(h: Harness) -> None:
    with store.open(h.governance_db) as st:
        real = st._connection
        st._connection = _InterruptAtCommit(real)  # type: ignore[assignment]
        with pytest.raises(KeyboardInterrupt):
            st.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="interrupted", detail_json=b"{}"
            )
        st._connection = real
        assert not real.in_transaction

    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
    finally:
        conn.close()


def test_r02_an_automatic_sqlite_rollback_does_not_mask_the_original_cause(
    h: Harness,
) -> None:
    """`SQLITE_FULL` rolls the transaction back itself.

    An unconditional `ROLLBACK` then fails with "cannot rollback - no transaction is
    active" and *replaces* "database or disk is full" -- the operator is told about the
    cleanup instead of about the disk. The real cause must survive.
    """
    with store.open(h.governance_db) as st:
        pages = st._connection.execute("PRAGMA page_count").fetchone()[0]
        st._connection.execute(f"PRAGMA max_page_count = {pages}")
        with pytest.raises(GovernedPlannerError) as caught:
            st.append_audit(
                workflow_id=WORKFLOW_ID,
                at=ISSUED_AT,
                event="resource_limit",
                detail_json=b'{"payload":"' + b"x" * 200_000 + b'"}',
            )
        rendered = str(caught.value)
        chain = f"{rendered} | {caught.value.__cause__}"
        assert "full" in chain, chain
        assert "cannot rollback" not in rendered, rendered
        assert isinstance(caught.value.__cause__, sqlite3.Error)


# --- ST7-R03: vendor exceptions must not escape the boundary ---------------------


def test_r03_opening_beneath_a_missing_directory_is_a_governance_refusal(
    h: Harness,
) -> None:
    missing = h.root / "no-such-directory" / "governance.sqlite"
    messages: list[str] = []
    for _ in range(2):
        with pytest.raises(GovernedPlannerError) as caught:
            store.open(missing)
        assert not isinstance(caught.value, sqlite3.Error)
        assert isinstance(caught.value.__cause__, sqlite3.Error)
        messages.append(str(caught.value))
    assert messages[0] == messages[1]


def test_r03_opening_a_file_that_is_not_a_database_is_a_governance_refusal(
    h: Harness,
) -> None:
    h.governance_db.write_bytes(b"not a sqlite database at all")
    messages: list[str] = []
    for _ in range(2):
        with pytest.raises(GovernedPlannerError) as caught:
            store.open(h.governance_db)
        assert isinstance(caught.value.__cause__, sqlite3.Error)
        messages.append(str(caught.value))
    assert messages[0] == messages[1]


def test_r03_a_failure_while_creating_the_schema_is_translated_and_leaves_nothing(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Creation is the one path that writes DDL; its failure is a store failure."""

    def failing_create(connection: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("injected DDL failure")

    monkeypatch.setattr(store, "_create_schema", failing_create)
    with pytest.raises(GovernedPlannerError) as caught:
        store.open(h.governance_db)
    assert isinstance(caught.value.__cause__, sqlite3.Error)

    monkeypatch.undo()
    conn = raw(h.governance_db)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'"
        ).fetchone()[0] == 0
    finally:
        conn.close()


def test_r03_the_real_bounded_busy_timeout_surfaces_as_a_governance_refusal(
    h: Harness,
) -> None:
    """The frozen `busy_timeout = 10000` expiring is a store failure, not a SQLite one.

    Deliberately the **real** frozen timeout, single-threaded: the holder keeps the
    write lock for the whole wait, so the waiter's `BEGIN IMMEDIATE` is guaranteed to
    exhaust it. Slow by design -- the reviewer asked for the real bounded path -- and
    deterministic: nothing here depends on scheduling.
    """
    digest, blob = artifact_of(spec())
    with store.open(h.governance_db) as setup:
        setup.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)

    with store.open(h.governance_db) as holder, store.open(h.governance_db) as waiter:
        assert waiter.effective_pragmas()["busy_timeout"] == 10000
        holder._connection.execute("BEGIN IMMEDIATE")
        holder._connection.execute(
            "INSERT INTO audit_events (workflow_id, at, event, detail_json) VALUES (?, ?, ?, ?)",
            (WORKFLOW_ID, ISSUED_AT, "holder", b"{}"),
        )
        started = time.monotonic()
        with pytest.raises(GovernedPlannerError) as caught:
            waiter.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="waiter", detail_json=b"{}"
            )
        waited = time.monotonic() - started
        assert not isinstance(caught.value, sqlite3.Error)
        assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
        assert waited >= 9.0, f"the timeout was not the frozen one: waited {waited:.3f}s"
        holder._connection.execute("ROLLBACK")

    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
    finally:
        conn.close()


def test_r03_a_governance_refusal_is_never_rewrapped_as_a_generic_store_failure(
    seeded: tuple[Store, str, bytes],
) -> None:
    """Translation must not swallow the invariant-specific refusals.

    `DigestMismatch`, `ConcurrentModification`, `ApprovalReplay` and `StoreSchemaTooOld`
    each name a governance failure class; a boundary that relabelled them would destroy
    exactly the distinction `errors.py` exists to make.
    """
    st, digest, blob = seeded
    other_digest, _ = artifact_of(spec(title="A different scope"))

    with pytest.raises(DigestMismatch):
        st.put_artifact(
            digest=other_digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob
        )
    with pytest.raises(ConcurrentModification):
        st.advance_case(
            workflow_id=WORKFLOW_ID,
            to_state=ScopeState.SCOPE_APPROVED,
            expected_revision=store.INITIAL_REVISION + 7,
        )
    _consume(st, digest)
    with pytest.raises(ApprovalReplay):
        _consume(st, digest)


def test_r03_a_python_programming_error_is_not_relabelled_as_a_governance_failure(
    seeded: tuple[Store, str, bytes],
) -> None:
    """The boundary translates `sqlite3` failures, never Python-level bugs.

    A `TypeError` raised inside a store transaction must reach the caller as a
    `TypeError`: relabelling it would turn a defect in this module into something that
    reads like a governance refusal.
    """
    st, _, _ = seeded
    with pytest.raises(TypeError):
        with st.transaction():
            raise TypeError("a bug in the caller, not a store failure")


# =================================================================================
# Section 12 — ST7-R03 closure regressions (R03-A, R03-B)
#
# The first R03 correction drew the vendor boundary around one call --
# `sqlite3.Connection.execute` -- rather than around every point at which store code
# touches the sqlite3 object. Two of those points were left outside it, and the closure
# verifier reproduced both. They are one defect expressed twice, not two.
# =================================================================================


def test_r03a_a_failure_while_fetching_rows_is_a_store_exception(h: Harness) -> None:
    """SQLite steps rows lazily, so a read can fail *after* `execute` returned.

    `execute` compiles the statement and returns a cursor; the rows are produced during
    `fetchall`. A boundary that wraps only the `execute` call therefore covers
    submission and not retrieval, and an interrupt during stepping escapes as a raw
    `sqlite3.OperationalError`.

    The interrupt is SQLite's own progress handler -- a real mechanism on a real
    connection, with no SQL replaced and no schema changed.
    """
    with store.open(h.governance_db) as st:
        with st.transaction():
            for index in range(100):
                st.append_audit(
                    workflow_id=WORKFLOW_ID,
                    at=ISSUED_AT,
                    event=f"seed-{index}",
                    detail_json=b"{}",
                )
        assert len(st.read_audit()) == 100

        st._connection.set_progress_handler(lambda: 1, 100)
        try:
            messages: list[str] = []
            for _ in range(2):
                with pytest.raises(GovernedPlannerError) as caught:
                    st.read_audit()
                assert not isinstance(caught.value, sqlite3.Error)
                assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
                messages.append(str(caught.value))
            assert messages[0] == messages[1]
        finally:
            st._connection.set_progress_handler(None, 0)

        assert len(st.read_audit()) == 100


def test_r03b_a_write_after_failed_cleanup_is_a_store_exception(h: Harness) -> None:
    """Reading `in_transaction` is a vendor call too, and it can fail.

    When both COMMIT and ROLLBACK are refused, R02's cleanup closes the connection --
    correctly, because its transaction state is then unknown. The *next* call enters
    `transaction()`, which inspects `self._connection.in_transaction`: an attribute
    access on the sqlite3 object, never a statement, and so never covered by a
    statement-level boundary. On a closed connection that raises
    `sqlite3.ProgrammingError`.
    """

    def deny_commit_and_rollback(
        action: int, arg1: str | None, arg2: str | None, db: str | None, source: str | None
    ) -> int:
        if action == sqlite3.SQLITE_TRANSACTION and arg1 in ("COMMIT", "ROLLBACK"):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    with store.open(h.governance_db) as st:
        st._connection.set_authorizer(deny_commit_and_rollback)

        with pytest.raises(GovernedPlannerError) as initial:
            st.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="failed_commit", detail_json=b"{}"
            )
        # R02's guarantees are unchanged: the commit failure is still the reported
        # cause, and the cleanup failure still travels beside it as a note.
        assert "commit statement failed" in str(initial.value)
        assert isinstance(initial.value.__cause__, sqlite3.DatabaseError)
        assert any("rollback also failed" in note for note in initial.value.__notes__)

        messages: list[str] = []
        for _ in range(2):
            with pytest.raises(GovernedPlannerError) as subsequent:
                st.append_audit(
                    workflow_id=WORKFLOW_ID,
                    at=ISSUED_AT,
                    event="following_write",
                    detail_json=b"{}",
                )
            assert not isinstance(subsequent.value, sqlite3.Error)
            assert isinstance(subsequent.value.__cause__, sqlite3.ProgrammingError)
            messages.append(str(subsequent.value))
        assert messages[0] == messages[1]

    # The write refused; it must not have reported success and left rows behind.
    conn = raw(h.governance_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
    finally:
        conn.close()


def test_r03_no_raw_sqlite_object_crosses_the_public_boundary(h: Harness) -> None:
    """The structural form of the invariant, so a later refactor cannot undo it.

    No public method may hand back a `sqlite3.Cursor` or `sqlite3.Connection`: a caller
    holding either could fetch, iterate or inspect outside the translating boundary,
    which is exactly how both closure failures arose.
    """
    digest, blob = artifact_of(spec())
    with store.open(h.governance_db) as st:
        returned = [
            st.effective_pragmas(),
            st.put_artifact(
                digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob
            ),
            st.get_artifact(digest),
            st.create_case(
                workflow_id=WORKFLOW_ID,
                state=ScopeState.SCOPE_REVIEW_PENDING,
                subject_digest=digest,
            ),
            st.load_case(WORKFLOW_ID),
            st.find_consumption(APPROVAL_ID),
            st.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="e", detail_json=b"{}"
            ),
            st.read_audit(),
        ]
    for value in returned:
        assert not isinstance(value, sqlite3.Cursor | sqlite3.Connection)
