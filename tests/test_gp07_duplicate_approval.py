"""GP-07 — an `approval_id` authorizes at most one committed transition.

Design basis: design/GP-SPK-001-governance-kernel.md §13.1 requirement 10, §10, §9.

Requirement 10 is accepted only when **all five modes plus the concurrency case** are
green (plan §15). The five are kept as five numbered sections here, in the plan's
order, because they are not five spellings of one property: they exercise three
different guards and two different outcomes, and collapsing any two would lose the
distinction the design draws between a *legitimate replay* and a *refused reuse*.

| Mode | Submitted | Outcome |
|---|---|---|
| 1 | the same statement, twice, same workflow | `applied=True` then `applied=False` |
| 2 | the same `approval_id`, a different workflow | `ApprovalReplay` |
| 3 | the same `approval_id`, same workflow, different content | `ApprovalReplay` |
| 4 | a matching row, the case no longer in `to_state` | `ApprovalReplay`, not silence |
| 5 | a different `approval_id` against an approved case | `IllegalTransition` |

**Replay-first ordering is the property under test, not a detail of it.** §10 looks the
`approval_id` up *before* evaluating transition legality, and mode 1's second call is
what proves the ordering is really in force: the case is `SCOPE_APPROVED` by then, so
an implementation that evaluated legality first would refuse
`SCOPE_APPROVED → SCOPE_APPROVED` with `IllegalTransition` and never reach the
idempotency branch. That was revision 1's defect, and DBOS steps are at-least-once, so
it is not hypothetical.

**Mode 5 is why neither guard alone is load-bearing.** A second, differently-identified
approval finds no consumption row, reaches the transition evaluation, and is refused by
`policy.py` — so two independent guards stand between a second approval and a second
transition.

What "writes nothing" means, asserted rather than assumed: every replay path is
compared against a full row-count and state snapshot taken before it, so a second
consumption row, a second audit event, a state change or a revision bump would all
fail. The counts are read on a connection outside the store, so nothing in the store's
own bookkeeping can flatter them.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import re
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from conftest import Harness
from gplanner import codec, kernel, store
from gplanner.approvals import (
    ISSUED_AT_PATTERN,
    PREDICATE_VERSION,
    SCOPE_APPROVAL_PREDICATE_TYPE,
    STATEMENT_TYPE,
    ApprovalStatement,
)
from gplanner.artifacts import ScopeSpec
from gplanner.digest import (
    APPROVAL_MEDIA_TYPE,
    SCOPE_MEDIA_TYPE,
    canonical_preimage,
    compute_digest,
    to_intoto_hex,
)
from gplanner.errors import (
    ApprovalReplay,
    AuthorityDenied,
    GovernedPlannerError,
    IllegalTransition,
)
from gplanner.states import ActorKind, ScopeState
from gplanner.store import Store

SRC = Path(__file__).resolve().parents[1] / "src" / "gplanner"

WORKFLOW_ID = "gp-spk-001-case-0001"
OTHER_WORKFLOW_ID = "gp-spk-001-case-0002"
APPROVAL_ID = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a88"
OTHER_APPROVAL_ID = "0123456789abcdef0123456789abcdef"
APPROVER_ID = "owner@example.invalid"
ISSUED_AT = "2026-09-17T11:22:33Z"
LATER_ISSUED_AT = "2026-09-17T11:22:34Z"

# --- builders --------------------------------------------------------------------


def spec(title: str = "Governance kernel feasibility") -> ScopeSpec:
    return ScopeSpec(
        title=title,
        problem_statement="Prove the authority model with no LLM in the loop.",
        in_scope=("digest-bound approvals",),
        out_of_scope=("signing",),
        acceptance_criteria=("the approval is consumable exactly once",),
    )


def artifact_of(model: ScopeSpec) -> tuple[str, bytes]:
    return (
        compute_digest(model, SCOPE_MEDIA_TYPE),
        canonical_preimage(model, SCOPE_MEDIA_TYPE),
    )


def wire(
    subject_digest: str,
    *,
    approval_id: str = APPROVAL_ID,
    workflow_id: str = WORKFLOW_ID,
    issued_at: str = ISSUED_AT,
    approver_id: str = APPROVER_ID,
) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": "gplanner.scope/v1", "digest": {"sha256": to_intoto_hex(subject_digest)}}
        ],
        "predicateType": SCOPE_APPROVAL_PREDICATE_TYPE,
        "predicate": {
            "predicate_version": PREDICATE_VERSION,
            "approval_id": approval_id,
            "workflow_id": workflow_id,
            "from_state": str(ScopeState.SCOPE_REVIEW_PENDING),
            "to_state": str(ScopeState.SCOPE_APPROVED),
            "approver_id": approver_id,
            "approver_kind": str(ActorKind.HUMAN),
            "decision": "APPROVE",
            "issued_at": issued_at,
        },
    }


def mint(subject_digest: str, **overrides: Any) -> ApprovalStatement:
    """A valid statement, built through `codec.decode_approval` — the one decode path."""
    return codec.decode_approval(json.dumps(wire(subject_digest, **overrides)))


def raw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


class Snapshot(NamedTuple):
    """Everything a replay must leave untouched, read outside the store."""

    consumptions: int
    audits: int
    states: tuple[tuple[str, str, int], ...]
    consumption_rows: tuple[tuple[Any, ...], ...]
    audit_rows: tuple[tuple[Any, ...], ...]


def snapshot(path: Path) -> Snapshot:
    conn = raw(path)
    try:
        consumption_rows = tuple(
            tuple(row)
            for row in conn.execute(
                "SELECT approval_id, approval_digest, subject_digest, workflow_id, "
                "from_state, to_state, consumed_at FROM approval_consumptions "
                "ORDER BY approval_id"
            )
        )
        audit_rows = tuple(
            tuple(row)
            for row in conn.execute(
                "SELECT seq, workflow_id, at, event, detail_json FROM audit_events ORDER BY seq"
            )
        )
        states = tuple(
            (str(row[0]), str(row[1]), int(row[2]))
            for row in conn.execute(
                "SELECT workflow_id, state, revision FROM cases ORDER BY workflow_id"
            )
        )
        return Snapshot(
            consumptions=len(consumption_rows),
            audits=len(audit_rows),
            states=states,
            consumption_rows=consumption_rows,
            audit_rows=audit_rows,
        )
    finally:
        conn.close()


@pytest.fixture
def st(h: Harness) -> Iterator[Store]:
    with store.open(h.governance_db) as opened:
        yield opened


@pytest.fixture
def pending(st: Store) -> tuple[Store, str]:
    """One case at `SCOPE_REVIEW_PENDING`, opened and submitted through the kernel."""
    ref = kernel.open_case(st, WORKFLOW_ID, spec())
    state = kernel.submit_for_review(st, WORKFLOW_ID, ActorKind.SYSTEM)
    assert state is ScopeState.SCOPE_REVIEW_PENDING
    return st, ref.digest


@pytest.fixture
def approved(pending: tuple[Store, str]) -> tuple[Store, str, ApprovalStatement]:
    """The same case, already advanced by one committed approval."""
    opened, digest = pending
    statement = mint(digest)
    outcome = kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert (outcome.applied, outcome.state) == (True, ScopeState.SCOPE_APPROVED)
    return opened, digest, statement


# =================================================================================
# Mode 1 — the same statement, twice, against the same workflow
# =================================================================================


def test_mode1_the_second_submission_of_the_same_statement_is_an_idempotent_replay(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """One transition, one row, one event — and the replay says so rather than lying.

    `applied=False` is a *report*, not a silent success: the caller can tell that this
    call did not commit the transition, which is what an at-least-once step needs to
    know.
    """
    opened, _, statement = approved
    before = snapshot(h.governance_db)
    assert (before.consumptions, before.audits) == (1, 1)

    replay = kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert replay.applied is False
    assert replay.state is ScopeState.SCOPE_APPROVED

    assert snapshot(h.governance_db) == before, "an exact replay must write nothing at all"


def test_mode1_replaying_many_times_never_writes_and_never_changes_the_verdict(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """At-least-once means "one or more", not "exactly twice"."""
    opened, _, statement = approved
    before = snapshot(h.governance_db)
    for _ in range(5):
        assert kernel.apply_scope_approval(opened, WORKFLOW_ID, statement).applied is False
    assert snapshot(h.governance_db) == before


def test_mode1_a_reencoded_resend_is_the_same_approval_not_a_different_one(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """§13: the digest is computed from the **validated model**, not the received bytes.

    The resend travels as `encode_approval`'s output and arrives with different bytes
    from the original wire text (field order, `_type` spelling, separators). It must be
    recognized as a replay of the same approval, not mistaken for different content.
    """
    opened, digest, statement = approved
    original_text = json.dumps(wire(digest))
    resent_text = codec.encode_approval(statement)
    assert resent_text != original_text, "the resend must genuinely differ byte-wise"

    before = snapshot(h.governance_db)
    replay = kernel.apply_scope_approval(opened, WORKFLOW_ID, codec.decode_approval(resent_text))
    assert replay.applied is False
    assert snapshot(h.governance_db) == before


# =================================================================================
# Mode 2 — the same `approval_id`, a different workflow
# =================================================================================


def test_mode2_the_same_approval_id_cannot_authorize_a_second_case(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """One approval, one case (`GK-INV-2`). The second case is legitimately pending and
    carries the same subject digest, so nothing but the reused id is wrong."""
    opened, digest, _ = approved
    kernel.open_case(opened, OTHER_WORKFLOW_ID, spec())
    kernel.submit_for_review(opened, OTHER_WORKFLOW_ID, ActorKind.SYSTEM)
    before = snapshot(h.governance_db)

    reused = mint(digest, workflow_id=OTHER_WORKFLOW_ID)
    with pytest.raises(ApprovalReplay) as refusal:
        kernel.apply_scope_approval(opened, OTHER_WORKFLOW_ID, reused)
    assert APPROVAL_ID in str(refusal.value)

    assert snapshot(h.governance_db) == before
    after = dict((workflow, state) for workflow, state, _ in snapshot(h.governance_db).states)
    assert after[OTHER_WORKFLOW_ID] == ScopeState.SCOPE_REVIEW_PENDING
    assert after[WORKFLOW_ID] == ScopeState.SCOPE_APPROVED


# =================================================================================
# Mode 3 — the same `approval_id`, same workflow, different content
# =================================================================================


def test_mode3_the_same_id_carrying_a_different_subject_is_refused_as_a_replay(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """The mode that proves step 4 compares **content**, not just the id.

    It also pins the ordering a second way: the substituted subject digest does not
    match the case, so an implementation that checked staleness first would raise
    `StaleApproval`. Replay-first means a reused id is reported as a reused id.
    """
    opened, _, _ = approved
    before = snapshot(h.governance_db)
    other_digest, other_blob = artifact_of(spec("A different scope entirely"))
    opened.put_artifact(
        digest=other_digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=other_blob
    )

    with pytest.raises(ApprovalReplay):
        kernel.apply_scope_approval(opened, WORKFLOW_ID, mint(other_digest))
    assert snapshot(h.governance_db) == before


def test_mode3_the_same_id_differing_only_in_issued_at_is_refused_as_a_replay(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """The comparison is on the whole statement's digest, not on the binding fields.

    Every field §10 step 4 names individually still matches; only a field outside that
    list differs. A comparison that ignored it would accept a re-minted approval as a
    replay of a different one.
    """
    opened, digest, _ = approved
    before = snapshot(h.governance_db)
    with pytest.raises(ApprovalReplay):
        kernel.apply_scope_approval(
            opened, WORKFLOW_ID, mint(digest, issued_at=LATER_ISSUED_AT)
        )
    assert snapshot(h.governance_db) == before


def test_mode3_the_same_id_differing_only_in_approver_is_refused_as_a_replay(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """A different claimed approver under a used id is a reuse, not a replay."""
    opened, digest, _ = approved
    before = snapshot(h.governance_db)
    with pytest.raises(ApprovalReplay):
        kernel.apply_scope_approval(
            opened, WORKFLOW_ID, mint(digest, approver_id="someone-else@example.invalid")
        )
    assert snapshot(h.governance_db) == before


# =================================================================================
# Mode 4 — a matching row, but the case is no longer in `to_state`
# =================================================================================


def test_mode4_a_matching_row_with_the_case_moved_away_is_a_replay_refusal(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """Refused, **not** a silent `applied=False`.

    The consumption row matches the statement in every recorded field, but the case is
    not where that row says the approval left it. Reporting an idempotent replay would
    claim a state the case does not hold; re-applying would consume the approval twice.
    The only honest answer is to refuse.

    The case is moved directly, outside the kernel, because no legal edge leaves
    `SCOPE_APPROVED` (§3) — the situation is a corrupted or externally edited store,
    which is exactly the condition the check has to survive.
    """
    opened, _, statement = approved
    conn = raw(h.governance_db)
    try:
        conn.execute(
            "UPDATE cases SET state = ? WHERE workflow_id = ?",
            (str(ScopeState.SCOPE_REVIEW_PENDING), WORKFLOW_ID),
        )
    finally:
        conn.close()
    before = snapshot(h.governance_db)

    with pytest.raises(ApprovalReplay) as refusal:
        kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert str(ScopeState.SCOPE_APPROVED) in str(refusal.value)

    assert snapshot(h.governance_db) == before
    assert before.consumptions == 1 and before.audits == 1


# =================================================================================
# Mode 5 — a different `approval_id` against an already approved case
# =================================================================================


def test_mode5_a_second_approval_of_an_approved_case_is_an_illegal_transition(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """Two independent guards stand between a second approval and a second transition.

    This one has a genuinely fresh `approval_id`, so the replay branch does not apply
    at all; control reaches the transition evaluation and `policy.py` refuses
    `SCOPE_APPROVED → SCOPE_APPROVED`, which is absent from `LEGAL_TRANSITIONS`.
    """
    opened, digest, _ = approved
    before = snapshot(h.governance_db)

    second = mint(digest, approval_id=OTHER_APPROVAL_ID)
    with pytest.raises(IllegalTransition):
        kernel.apply_scope_approval(opened, WORKFLOW_ID, second)

    assert snapshot(h.governance_db) == before
    assert before.consumptions == 1, "the refused approval must not be burnt"


def test_mode5_the_refused_second_approval_id_was_never_recorded(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """A refusal leaves the fresh id unclaimed, so it is still usable elsewhere."""
    opened, digest, _ = approved
    second = mint(digest, approval_id=OTHER_APPROVAL_ID)
    with pytest.raises(IllegalTransition):
        kernel.apply_scope_approval(opened, WORKFLOW_ID, second)
    assert opened.find_consumption(OTHER_APPROVAL_ID) is None


# =================================================================================
# Concurrency — one deterministic outcome, not a tolerated race
# =================================================================================

CONCURRENCY_TIMEOUT_SECONDS = 60.0


def test_two_concurrent_threads_submitting_one_statement_resolve_deterministically(
    pending: tuple[Store, str], h: Harness
) -> None:
    """`BEGIN IMMEDIATE` takes the write lock at `BEGIN`, so the two serialize.

    Each worker opens its **own** `Store`, so the serialization proven here is SQLite's
    across connections and not a lock this test shares. A `Barrier` makes the overlap
    real rather than incidental.
    """
    _, digest = pending
    statement = mint(digest)
    start = threading.Barrier(2, timeout=30.0)
    outcomes: list[kernel.ApplyOutcome] = []
    failures: list[BaseException] = []
    lock = threading.Lock()

    def submit() -> None:
        try:
            with store.open(h.governance_db) as worker:
                start.wait()
                outcome = kernel.apply_scope_approval(worker, WORKFLOW_ID, statement)
            with lock:
                outcomes.append(outcome)
        except BaseException as exc:  # noqa: BLE001 - recorded, then asserted on below
            with lock:
                failures.append(exc)

    threads = [threading.Thread(target=submit) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=CONCURRENCY_TIMEOUT_SECONDS)
        assert not thread.is_alive()

    assert not failures, failures
    assert sorted(outcome.applied for outcome in outcomes) == [False, True]
    assert {outcome.state for outcome in outcomes} == {ScopeState.SCOPE_APPROVED}

    final = snapshot(h.governance_db)
    assert (final.consumptions, final.audits) == (1, 1)
    assert final.states == ((WORKFLOW_ID, str(ScopeState.SCOPE_APPROVED), 3),)


CHILD_PROGRAM = """
import pathlib, sys, time
from gplanner import codec, kernel, store

gov, ready, go, payload, workflow_id = sys.argv[1:6]
statement = codec.decode_approval(pathlib.Path(payload).read_text(encoding="utf-8"))
with store.open(gov) as opened:
    pathlib.Path(ready).write_text("ready", encoding="utf-8")
    while not pathlib.Path(go).exists():
        time.sleep(0.005)
    try:
        outcome = kernel.apply_scope_approval(opened, workflow_id, statement)
        print(f"RESULT applied={outcome.applied} state={outcome.state}", flush=True)
    except BaseException as exc:
        print(f"RESULT error={type(exc).__name__}", flush=True)
"""


def test_two_concurrent_processes_submitting_one_statement_resolve_deterministically(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The plan's §15 clause literally: two **processes**, one statement, one workflow.

    Separate processes share nothing but the two files, so the guarantee exercised is
    SQLite's own locking under `BEGIN IMMEDIATE` plus `busy_timeout`, with no shared
    interpreter state that could serialize them for the wrong reason. Both children
    publish readiness and then spin on a `go` file the parent creates once both are
    holding an open store, so the submissions genuinely overlap.
    """
    _, digest = pending
    payload = h.root / "statement.json"
    payload.write_text(codec.encode_approval(mint(digest)), encoding="utf-8")
    go = h.root / "go"

    children = [
        h.spawn(
            "-c",
            CHILD_PROGRAM,
            str(h.governance_db),
            str(h.ready_dir / f"child{index}.ready"),
            str(go),
            str(payload),
            WORKFLOW_ID,
        )
        for index in range(2)
    ]
    for index, child in enumerate(children):
        h.wait_for_ready(f"child{index}", child)

    go.write_text("go", encoding="utf-8")
    results: list[str] = []
    for child in children:
        stdout, _ = child.communicate(timeout=CONCURRENCY_TIMEOUT_SECONDS)
        text = stdout.decode("utf-8", errors="replace")
        assert child.returncode == 0, f"child exited {child.returncode}:\n{text}"
        lines = [line for line in text.splitlines() if line.startswith("RESULT ")]
        assert len(lines) == 1, text
        results.append(lines[0])

    assert sorted(results) == [
        f"RESULT applied=False state={ScopeState.SCOPE_APPROVED}",
        f"RESULT applied=True state={ScopeState.SCOPE_APPROVED}",
    ], results

    final = snapshot(h.governance_db)
    assert (final.consumptions, final.audits) == (1, 1)
    assert final.states == ((WORKFLOW_ID, str(ScopeState.SCOPE_APPROVED), 3),)


# =================================================================================
# The committed transition, and what exactly one audit event records
# =================================================================================


def test_a_successful_approval_writes_exactly_one_row_and_exactly_one_event(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """§10 step 5: one consumption, one audit event, one CAS advance. Nothing doubled."""
    opened, digest, statement = approved
    final = snapshot(h.governance_db)
    assert (final.consumptions, final.audits) == (1, 1)

    consumption = opened.find_consumption(APPROVAL_ID)
    assert consumption is not None
    assert consumption.approval_digest == compute_digest(statement, APPROVAL_MEDIA_TYPE)
    assert consumption.subject_digest == digest
    assert consumption.workflow_id == WORKFLOW_ID
    assert consumption.from_state is ScopeState.SCOPE_REVIEW_PENDING
    assert consumption.to_state is ScopeState.SCOPE_APPROVED

    events = opened.read_audit(WORKFLOW_ID)
    assert len(events) == 1
    assert events[0].event == kernel.SCOPE_APPROVED_EVENT
    detail = events[0].detail_json.decode("utf-8")
    for expected in (APPROVAL_ID, digest, consumption.approval_digest, "SPK1-2"):
        assert expected in detail


def test_the_consumption_and_audit_timestamps_are_rfc3339_with_an_offset(
    approved: tuple[Store, str, ApprovalStatement], h: Harness
) -> None:
    """The kernel stamps its own observation of local time and says so.

    There is no trusted clock in GP-SPK-001 (§8), so these timestamps are records of
    when this process believed it committed — never evidence of when the approver
    acted, which is the statement's own untrusted `issued_at`. The syntax is pinned to
    the same frozen pattern `issued_at` is validated against, so one shape is stored
    throughout.
    """
    opened, _, _ = approved
    pattern = re.compile(ISSUED_AT_PATTERN)
    consumption = opened.find_consumption(APPROVAL_ID)
    assert consumption is not None
    assert pattern.fullmatch(consumption.consumed_at)
    assert pattern.fullmatch(opened.read_audit(WORKFLOW_ID)[0].at)
    assert consumption.consumed_at != ISSUED_AT


def test_the_approval_digest_is_domain_separated_from_the_scope_digest() -> None:
    """§6 property 1: `media_type` is inside the hashed preimage, so an approval digest
    can never collide with a scope digest, and the two media types are distinct."""
    assert APPROVAL_MEDIA_TYPE != SCOPE_MEDIA_TYPE
    statement = mint(compute_digest(spec(), SCOPE_MEDIA_TYPE))
    assert compute_digest(statement, APPROVAL_MEDIA_TYPE) != compute_digest(
        statement, SCOPE_MEDIA_TYPE
    )


# =================================================================================
# The kernel decides, and composes rather than duplicates
# =================================================================================


def test_the_kernel_routes_authority_through_policy_rather_than_deciding_again(
    st: Store
) -> None:
    """`submit_for_review` refuses a non-`SYSTEM` actor because the table says so.

    Proven by asking for the transition with the wrong authority: the refusal is
    `AuthorityDenied` from `policy.py`, which is only reachable if the kernel consults
    the table instead of carrying its own copy of the rule (`GK-INV-6`).
    """
    kernel.open_case(st, WORKFLOW_ID, spec())
    for kind in (ActorKind.HUMAN, ActorKind.LLM):
        with pytest.raises(AuthorityDenied):
            kernel.submit_for_review(st, WORKFLOW_ID, kind)
    case = st.load_case(WORKFLOW_ID)
    assert case is not None and case.state is ScopeState.SCOPE_DRAFTING


def test_opening_the_same_case_again_with_the_same_content_changes_nothing(
    st: Store, h: Harness
) -> None:
    """`open_case` is idempotent for identical content, which is what plan §16 asserts
    when it says the step is safe to re-run; it mutates no state, so repeating it
    contradicts no row of §3's table."""
    first = kernel.open_case(st, WORKFLOW_ID, spec())
    kernel.submit_for_review(st, WORKFLOW_ID, ActorKind.SYSTEM)
    again = kernel.open_case(st, WORKFLOW_ID, spec())
    assert again == first
    case = st.load_case(WORKFLOW_ID)
    assert case is not None
    assert case.state is ScopeState.SCOPE_REVIEW_PENDING
    assert snapshot(h.governance_db).audits == 0


def test_reopening_a_case_with_different_content_is_refused(st: Store) -> None:
    """Idempotence is for the *same* content only: a case is not silently repointed."""
    kernel.open_case(st, WORKFLOW_ID, spec())
    with pytest.raises(GovernedPlannerError):
        kernel.open_case(st, WORKFLOW_ID, spec("A different scope entirely"))
    case = st.load_case(WORKFLOW_ID)
    assert case is not None
    assert case.subject_digest == compute_digest(spec(), SCOPE_MEDIA_TYPE)


def test_apply_outcome_is_frozen_and_carries_exactly_the_two_frozen_fields() -> None:
    """§12's contract: `state` and `applied`, and nothing that could drift beside them."""
    fields = {field.name: field.type for field in dataclasses.fields(kernel.ApplyOutcome)}
    assert set(fields) == {"state", "applied"}
    outcome = kernel.ApplyOutcome(state=ScopeState.SCOPE_APPROVED, applied=True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.applied = False  # type: ignore[misc]


# =================================================================================
# Boundaries and the frozen guard registry
# =================================================================================


def guarded_statement(source: str, marker: str) -> str:
    """The one `require(...)` statement carrying `# guard:<id>`, as a single string."""
    lines = source.splitlines()
    marked = [index for index, line in enumerate(lines) if f"# {marker}" in line]
    assert len(marked) == 1, f"{marker} must be marked exactly once, found {len(marked)}"
    assert lines[marked[0]].rstrip().endswith(f"# {marker}")
    start = marked[0]
    while "require(" not in lines[start]:
        start -= 1
        assert start >= 0, f"{marker} is not attached to a require() call"
    return "\n".join(lines[start : marked[0] + 1])


def test_the_kernel_marks_exactly_the_four_guard_ids_it_owns() -> None:
    """Plan §10's registry assigns these four to the kernel and no others.

    `gp_transition_legal` and `gp_transition_authority` are registered at
    `policy.refuse_unless_allowed` and are reached by calling it. Re-marking them here
    would give the mutation harness two sites for one guard, and would mean the kernel
    had grown its own opinion about legality.
    """
    source = (SRC / "kernel.py").read_text(encoding="utf-8")
    assert set(re.findall(r"#\s*(guard:[a-z_]+)", source)) == {
        "guard:gp_approval_replay",
        "guard:gp_approval_workflow_binding",
        "guard:gp_approval_from_state",
        "guard:gp_approval_subject_digest",
    }


def test_each_kernel_guard_refuses_with_the_class_the_registry_names() -> None:
    """The guard ID and its refusal class are bound together, not merely co-present."""
    source = (SRC / "kernel.py").read_text(encoding="utf-8")
    expected = {
        "guard:gp_approval_replay": "ApprovalReplay",
        "guard:gp_approval_workflow_binding": "ApprovalBindingError",
        "guard:gp_approval_from_state": "ApprovalBindingError",
        "guard:gp_approval_subject_digest": "StaleApproval",
    }
    for marker, error in expected.items():
        assert error in guarded_statement(source, marker), marker


def test_the_replay_guard_sits_in_the_registered_consumption_branch() -> None:
    """Plan §10 registers `guard:gp_approval_replay` at `kernel._consumption_branch`."""
    source = (SRC / "kernel.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    branch = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_consumption_branch"
    ]
    assert len(branch) == 1, "the registered site must exist under its registered name"
    body = ast.get_source_segment(source, branch[0]) or ""
    assert "# guard:gp_approval_replay" in body


def test_the_replay_lookup_precedes_the_transition_evaluation_in_the_source() -> None:
    """The ordering §10 makes load-bearing, read off the syntax tree.

    Mode 1's second call proves the ordering behaviourally. This asserts it
    structurally as well, so a refactor that reordered the two calls while some future
    behaviour happened to mask it would still fail.
    """
    source = (SRC / "kernel.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    apply_fn = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "apply_scope_approval"
    ]
    assert len(apply_fn) == 1
    called: list[tuple[int, str]] = []
    for node in ast.walk(apply_fn[0]):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            called.append((node.lineno, node.func.attr))
        elif isinstance(node.func, ast.Name):
            called.append((node.lineno, node.func.id))
    ordered = [name for _, name in sorted(called)]
    for required in ("find_consumption", "_consumption_branch", "refuse_unless_allowed"):
        assert required in ordered, required
    assert ordered.index("find_consumption") < ordered.index("refuse_unless_allowed")
    assert ordered.index("find_consumption") < ordered.index("_consumption_branch")
    assert ordered.index("refuse_unless_allowed") < ordered.index("record_consumption")


def test_the_kernel_imports_no_engine_no_json_and_no_llm_sdk() -> None:
    """§4: the authority model is provable with the engine absent; §7: one decode path."""
    tree = ast.parse((SRC / "kernel.py").read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    assert "dbos" not in roots
    assert "json" not in roots
    assert not {"anthropic", "openai"} & roots


def test_importing_the_kernel_pulls_in_no_engine_and_no_llm_sdk() -> None:
    import sys

    assert kernel is not None
    assert "dbos" not in sys.modules
    assert not {"anthropic", "openai"} & sys.modules.keys()


def test_the_kernel_module_docstring_cites_its_design_basis() -> None:
    docstring = ast.get_docstring(ast.parse((SRC / "kernel.py").read_text(encoding="utf-8")))
    assert docstring is not None
    assert "Design basis: design/GP-SPK-001-governance-kernel.md §" in docstring


def test_the_kernel_exposes_exactly_the_three_frozen_entry_points() -> None:
    """§12: three entry points, no others.

    Counted over the functions `kernel.py` itself defines, so a re-exported helper it
    imported from another layer is not mistaken for a fourth way into case state --
    and a genuinely new public mutator cannot be added unnoticed.
    """
    defined = {
        name
        for name, value in vars(kernel).items()
        if not name.startswith("_")
        and callable(value)
        and getattr(value, "__module__", "") == "gplanner.kernel"
    }
    assert defined == {"open_case", "submit_for_review", "apply_scope_approval", "ApplyOutcome"}


# =================================================================================
# ST8-R01 — the kernel owns the outer transaction its contract promises
# =================================================================================
#
# `Store.transaction()` is reentrant and its inner scope is a pass-through, which is
# what lets §10 run every step of an approval inside ONE `BEGIN IMMEDIATE`. That
# property is correct *inside* the kernel and wrong at its boundary: when the caller
# has already opened the transaction, the kernel's own `with store.transaction():`
# issues neither `BEGIN IMMEDIATE` nor `COMMIT`, so
#
#   * `applied=True` was returned with nothing committed (the traced sequence was
#     `BEGIN IMMEDIATE`, kernel returns, ... `COMMIT`, in that order);
#   * a second identical call read the caller's *uncommitted* consumption row through
#     its own connection and reported it as a committed replay (`applied=False`);
#   * an outer rollback erased both reported outcomes;
#   * a failure escaping the kernel rolled nothing back, because the pass-through
#     scope has no `COMMIT` to protect -- so a caller that caught it could then commit
#     `SCOPE_APPROVED` + one consumption + **zero** audit rows.
#
# The frozen contract says `applied=True` means *this call committed the transition*
# and `applied=False` means *a previously committed transition was recognized*. A
# kernel that cannot tell whether it committed cannot say either. So every mutating
# entry point refuses, before doing any work, a `Store` whose transaction it does not
# own. The refusal is a structural precondition -- a plain `if ... raise`, no guard ID
# -- and it raises the frozen `GovernedPlannerError`, the class this module already
# uses for "a caller has not met the precondition this entry point needs".


class Exploded(RuntimeError):
    """Raised by a probe that must never be reached, or that forces a failure."""


def committed_state(path: Path) -> tuple[str | None, int]:
    """The case's state and revision as a *separate connection* can see them."""
    conn = raw(path)
    try:
        row = conn.execute(
            "SELECT state, revision FROM cases WHERE workflow_id = ?", (WORKFLOW_ID,)
        ).fetchone()
        return (None, 0) if row is None else (str(row[0]), int(row[1]))
    finally:
        conn.close()


# The ownership refusal's stable discriminators. `_require_transaction_ownership` is the
# only place in `kernel.py` that raises them -- pinned off the source by
# `test_r01_the_ownership_check_runs_first_in_each_entry_point` -- so a message carrying
# them can only have come from the transaction-ownership precondition.
#
# The message is the discriminator the frozen contract leaves available: `errors.py` is
# frozen, so no ownership-specific exception class may be added, and the check carries no
# guard ID because it decides nothing about governance. Asserting `GovernedPlannerError`
# alone is not evidence of anything: every governed refusal is one. Substituting
# `IllegalTransition("apply_scope_approval: illegal transaction")` for the ownership
# refusal satisfies that assertion while also naming the entry point and the word
# "transaction", which is exactly the hole these phrases close.
OWNERSHIP_REFUSAL_PHRASES = (
    "requires the governance transaction it opens itself",
    "already inside a transaction owned by the caller",
    "can neither commit nor roll back",
)


def assert_ownership_refusal(exc: BaseException, entry_point: str) -> None:
    """Assert `exc` is *the* ST8-R01 ownership refusal, raised by `entry_point`.

    Both halves are load-bearing. The **exact** type -- `GovernedPlannerError` itself,
    never a subclass -- rejects every refusal the kernel raises for a governance reason
    (`IllegalTransition`, `ApprovalReplay`, `AuthorityDenied`, `StaleApproval`, ...). The
    phrases then reject what is left: a bare `GovernedPlannerError` raised elsewhere in
    the same entry point, such as the missing-case or requires-approval preconditions.
    Naming the entry point in the opening clause also pins *which* mutator refused.
    """
    assert type(exc) is GovernedPlannerError, (
        f"{entry_point}: the refusal must be GovernedPlannerError itself, not "
        f"{type(exc).__name__}; a governed error of some other kind is not evidence "
        f"that the transaction-ownership precondition is what refused"
    )
    message = str(exc)
    assert message.startswith(f"{entry_point} requires the governance transaction"), (
        f"{entry_point}: refusal does not open with this entry point's ownership "
        f"precondition: {message!r}"
    )
    for phrase in OWNERSHIP_REFUSAL_PHRASES:
        assert phrase in message, f"{entry_point}: {phrase!r} missing from {message!r}"


# --- A. premature success refused ------------------------------------------------


def test_r01_apply_inside_a_caller_owned_transaction_is_refused(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The reported defect, directly: no `applied=True` without a kernel-owned commit.

    The refusal is raised from inside the caller's own transaction, which is exactly
    where the old code returned `ApplyOutcome(applied=True)` with nothing committed.
    """
    opened, digest = pending
    statement = mint(digest)
    before = snapshot(h.governance_db)

    with pytest.raises(GovernedPlannerError) as refusal:
        with opened.transaction():
            kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert_ownership_refusal(refusal.value, "apply_scope_approval")

    assert snapshot(h.governance_db) == before
    assert (before.consumptions, before.audits) == (0, 0)
    assert committed_state(h.governance_db)[0] == ScopeState.SCOPE_REVIEW_PENDING


def test_r01_the_refusal_precedes_every_read_and_write_of_approval_work(
    pending: tuple[Store, str], h: Harness
) -> None:
    """"Before approval work" asserted, not assumed.

    Both the replay lookup (§10 step 3) and the claim (§10 step 5f) are replaced with
    probes that raise. Neither fires, so the refusal happens before the kernel has so
    much as *looked* at the consumption table.
    """
    opened, digest = pending
    statement = mint(digest)

    def never(*_args: Any, **_kwargs: Any) -> Any:
        raise Exploded("approval work ran despite the caller owning the transaction")

    original_find = opened.find_consumption
    original_record = opened.record_consumption
    original_load = opened.load_case
    opened.find_consumption = never  # type: ignore[method-assign]
    opened.record_consumption = never  # type: ignore[method-assign]
    opened.load_case = never  # type: ignore[method-assign]
    try:
        with pytest.raises(GovernedPlannerError) as refusal:
            with opened.transaction():
                kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    finally:
        opened.find_consumption = original_find  # type: ignore[method-assign]
        opened.record_consumption = original_record  # type: ignore[method-assign]
        opened.load_case = original_load  # type: ignore[method-assign]
    assert not isinstance(refusal.value, Exploded)
    assert_ownership_refusal(refusal.value, "apply_scope_approval")


def test_r01_every_mutating_entry_point_refuses_a_caller_owned_transaction(
    st: Store, h: Harness
) -> None:
    """All three §10 entry points, not just the one the finding was found through.

    Each of them returns a value describing persisted state -- a stored artifact's
    reference, the state a transition left behind, an `ApplyOutcome` -- and none of
    those answers is true if the transaction that would make it true belongs to
    somebody else. One rule for the three is also one rule to remember.
    """
    kernel.open_case(st, WORKFLOW_ID, spec())
    before = snapshot(h.governance_db)
    statement = mint(compute_digest(spec(), SCOPE_MEDIA_TYPE))

    calls = (
        ("open_case", lambda: kernel.open_case(st, OTHER_WORKFLOW_ID, spec())),
        ("submit_for_review", lambda: kernel.submit_for_review(st, WORKFLOW_ID, ActorKind.SYSTEM)),
        ("apply_scope_approval", lambda: kernel.apply_scope_approval(st, WORKFLOW_ID, statement)),
    )
    for name, call in calls:
        with pytest.raises(GovernedPlannerError) as refusal:
            with st.transaction():
                call()
        assert_ownership_refusal(refusal.value, name)

    assert snapshot(h.governance_db) == before


def test_r01_the_refusal_class_is_frozen_and_errors_py_grew_nothing(st: Store) -> None:
    """No new public exception was invented for this boundary (`errors.py` is frozen).

    `GovernedPlannerError` is the class this module already raises for a caller that
    has not met a structural precondition -- a missing case, an approval-requiring edge
    handed to `submit_for_review` -- and "you are holding the transaction I must own"
    is the same kind of statement.
    """
    frozen = {
        "GovernedPlannerError", "CanonicalizationError", "PayloadProfileViolation",
        "DigestMismatch", "IllegalTransition", "AuthorityDenied", "ApprovalBindingError",
        "StaleApproval", "ApprovalReplay", "ConcurrentModification", "StoreSchemaTooOld",
    }
    import gplanner.errors as errors_module

    declared = {
        name
        for name, value in vars(errors_module).items()
        if isinstance(value, type)
        and issubclass(value, BaseException)
        and getattr(value, "__module__", "") == "gplanner.errors"
    }
    assert declared == frozen

    kernel.open_case(st, WORKFLOW_ID, spec())
    with pytest.raises(GovernedPlannerError) as refusal:
        with st.transaction():
            kernel.submit_for_review(st, WORKFLOW_ID, ActorKind.SYSTEM)
    assert_ownership_refusal(refusal.value, "submit_for_review")


def test_r01_the_ownership_check_is_not_a_registered_guard() -> None:
    """A structural precondition carries no guard ID (module docstring, §10 registry).

    The frozen registry assigns the kernel four guards. This check is not a governance
    decision -- it decides nothing about legality, authority, binding or replay -- so
    marking it would give the deferred mutation harness a fifth kernel site the plan
    does not register.
    """
    source = (SRC / "kernel.py").read_text(encoding="utf-8")
    assert set(re.findall(r"#\s*(guard:[a-z_]+)", source)) == {
        "guard:gp_approval_replay",
        "guard:gp_approval_workflow_binding",
        "guard:gp_approval_from_state",
        "guard:gp_approval_subject_digest",
    }


# --- B. uncommitted replay impossible --------------------------------------------


def test_r01_a_consumption_visible_only_inside_a_caller_transaction_is_never_a_replay(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The sharp form of the uncommitted-replay case.

    The caller writes a consumption row and advances the case through the **store**,
    which is allowed -- the store persists what it is told and decides nothing. Those
    rows exist on this connection and nowhere else. The old kernel read them through
    the same connection and reported `applied=False`, calling an uncommitted write a
    previously committed transition. A refusal is the only answer that is true.
    """
    opened, digest = pending
    statement = mint(digest)
    approval_digest = compute_digest(statement, APPROVAL_MEDIA_TYPE)

    with pytest.raises(GovernedPlannerError) as refusal:
        with opened.transaction():
            opened.record_consumption(
                approval_id=APPROVAL_ID,
                approval_digest=approval_digest,
                subject_digest=digest,
                workflow_id=WORKFLOW_ID,
                from_state=ScopeState.SCOPE_REVIEW_PENDING,
                to_state=ScopeState.SCOPE_APPROVED,
                consumed_at=ISSUED_AT,
            )
            opened.advance_case(
                workflow_id=WORKFLOW_ID,
                to_state=ScopeState.SCOPE_APPROVED,
                expected_revision=store.INITIAL_REVISION + 1,
            )
            # Everything step 4 compares now matches -- on this connection only.
            assert opened.find_consumption(APPROVAL_ID) is not None
            kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert_ownership_refusal(refusal.value, "apply_scope_approval")

    final = snapshot(h.governance_db)
    assert (final.consumptions, final.audits) == (0, 0)
    assert committed_state(h.governance_db)[0] == ScopeState.SCOPE_REVIEW_PENDING


def test_r01_a_repeated_call_inside_one_caller_transaction_never_converges_to_replay(
    pending: tuple[Store, str], h: Harness
) -> None:
    """Two identical calls inside one caller-owned transaction: two refusals.

    The old behaviour was `applied=True` then `applied=False` -- a full, reported
    consume-and-replay pair of which nothing was committed. Neither call may now claim
    anything at all.
    """
    opened, digest = pending
    statement = mint(digest)
    outcomes: list[kernel.ApplyOutcome] = []
    refusals: list[GovernedPlannerError] = []

    with opened.transaction():
        for _ in range(2):
            try:
                outcomes.append(kernel.apply_scope_approval(opened, WORKFLOW_ID, statement))
            except GovernedPlannerError as exc:
                refusals.append(exc)

    assert outcomes == []
    assert len(refusals) == 2
    for refusal in refusals:
        assert_ownership_refusal(refusal, "apply_scope_approval")
    final = snapshot(h.governance_db)
    assert (final.consumptions, final.audits) == (0, 0)


# --- C. a caught failure cannot be committed by the caller ------------------------


def test_r01_a_caught_kernel_failure_leaves_the_caller_nothing_partial_to_commit(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The partial-commit case, reproduced exactly and then prevented at the boundary.

    `append_audit` (§10 step 5h) is made to fail after the consumption and the CAS. In
    the old code the kernel's pass-through scope rolled nothing back, the caller caught
    the failure, and its outer `COMMIT` then made `SCOPE_APPROVED` + one consumption +
    **zero** audit rows durable -- governance state no committed approval ever
    authorized.

    The refusal now comes first, so the failure is never reached: the caller's
    transaction commits, and commits nothing. The probe's own exception class is
    asserted absent, which is what proves step 5h was never entered.
    """
    opened, digest = pending
    statement = mint(digest)

    def exploding_append_audit(**_kwargs: Any) -> None:
        raise Exploded("audit append failed after consumption and CAS")

    original = opened.append_audit
    opened.append_audit = exploding_append_audit  # type: ignore[method-assign]
    caught: list[BaseException] = []
    try:
        with opened.transaction():  # the caller's transaction, and it COMMITS
            try:
                kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
            except BaseException as exc:  # noqa: BLE001 - the caller swallows it
                caught.append(exc)
    finally:
        opened.append_audit = original  # type: ignore[method-assign]

    assert len(caught) == 1
    assert not isinstance(caught[0], Exploded), "step 5h must never have been reached"
    assert_ownership_refusal(caught[0], "apply_scope_approval")

    final = snapshot(h.governance_db)
    assert (final.consumptions, final.audits) == (0, 0)
    assert committed_state(h.governance_db) == (ScopeState.SCOPE_REVIEW_PENDING, 2)


def test_r01_a_kernel_owned_failure_still_rolls_its_own_transaction_back(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The other half: with the kernel owning the transaction, a failure undoes itself.

    Same forced failure, no caller transaction. The kernel's own `BEGIN IMMEDIATE`
    covers the `COMMIT`, so `_abort` rolls the consumption and the CAS back and there
    is no partial state for anyone to commit later -- the property the refusal exists
    to preserve rather than replace.
    """
    opened, digest = pending
    statement = mint(digest)

    def exploding_append_audit(**_kwargs: Any) -> None:
        raise Exploded("audit append failed after consumption and CAS")

    original = opened.append_audit
    opened.append_audit = exploding_append_audit  # type: ignore[method-assign]
    try:
        with pytest.raises(Exploded):
            kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    finally:
        opened.append_audit = original  # type: ignore[method-assign]

    final = snapshot(h.governance_db)
    assert (final.consumptions, final.audits) == (0, 0)
    assert committed_state(h.governance_db) == (ScopeState.SCOPE_REVIEW_PENDING, 2)
    assert opened.find_consumption(APPROVAL_ID) is None


# --- D. standalone behaviour preserved -------------------------------------------


def test_r01_applied_true_is_durable_the_instant_the_call_returns(
    pending: tuple[Store, str], h: Harness
) -> None:
    """`applied=True` only after a kernel-owned `COMMIT`, proven from outside.

    The consumption, the audit row and the advanced state are read on a **separate
    connection** immediately after the call returns. An uncommitted transaction is
    invisible there, so observing all three is observing a commit that has happened.
    """
    opened, digest = pending
    statement = mint(digest)

    outcome = kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert (outcome.applied, outcome.state) == (True, ScopeState.SCOPE_APPROVED)

    visible = snapshot(h.governance_db)
    assert (visible.consumptions, visible.audits) == (1, 1)
    assert committed_state(h.governance_db) == (ScopeState.SCOPE_APPROVED, 3)

    replay = kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert replay.applied is False
    assert snapshot(h.governance_db) == visible


def test_r01_the_store_still_nests_transactions_for_internal_composition(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The store's pass-through is preserved; only the kernel's boundary changed.

    §10 needs it: the kernel opens one `BEGIN IMMEDIATE` and the store methods it then
    calls must nest into that one transaction rather than open their own. Asserted
    through the store's own API, and through the fact that an approval -- four store
    writes inside one kernel transaction -- still commits as a unit.
    """
    opened, digest = pending
    assert opened.in_transaction is False
    with opened.transaction():
        assert opened.in_transaction is True
        with opened.transaction():  # the pass-through, still supported
            assert opened.in_transaction is True
            opened.append_audit(
                workflow_id=WORKFLOW_ID, at=ISSUED_AT, event="nested", detail_json=b"{}"
            )
    assert opened.in_transaction is False
    assert snapshot(h.governance_db).audits == 1

    outcome = kernel.apply_scope_approval(opened, WORKFLOW_ID, mint(digest))
    assert outcome.applied is True
    final = snapshot(h.governance_db)
    assert (final.consumptions, final.audits) == (1, 2)


def test_r01_the_ownership_check_runs_first_in_each_entry_point(st: Store) -> None:
    """Structural: the check is the first statement of each mutator, read off the AST.

    Behaviour proves it for today's code; this pins it against a later refactor that
    moved the call below the first store access, where a failure between the two would
    again leave work the kernel did not own.
    """
    source = (SRC / "kernel.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for name in ("open_case", "submit_for_review", "apply_scope_approval"):
        function = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        assert len(function) == 1, name
        body = function[0].body
        assert isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant), name
        first = body[1]
        assert isinstance(first, ast.Expr), f"{name}: first statement is not a call"
        assert isinstance(first.value, ast.Call), f"{name}: first statement is not a call"
        assert isinstance(first.value.func, ast.Name), name
        assert first.value.func.id == "_require_transaction_ownership", name

    # And the message `assert_ownership_refusal` keys on comes from that check and from
    # nowhere else. If a second site ever adopted the wording, the phrases would stop
    # identifying the ownership precondition and these regressions would silently
    # weaken back into "some GovernedPlannerError was raised".
    guards = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_require_transaction_ownership"
    ]
    assert len(guards) == 1
    span = range(guards[0].lineno, (guards[0].end_lineno or guards[0].lineno) + 1)
    lines = source.splitlines()
    for phrase in OWNERSHIP_REFUSAL_PHRASES:
        carrying = [number for number, line in enumerate(lines, start=1) if phrase in line]
        assert len(carrying) == 1, f"{phrase!r} is not unique in kernel.py: {carrying}"
        assert carrying[0] in span, f"{phrase!r} is raised outside the ownership check"
