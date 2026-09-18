"""GP-10 — restart and recovery across real process death.

Design basis: design/GP-SPK-001-governance-kernel.md §9 (`GK-INV-3`), §10, §12,
§13.1 (requirements 8, 9 and 10), §14.

Two obligations, and neither substitutes for the other.

**GP-10a** (requirement 9) proves that a receive the workflow had *already entered*
survives the death of the process that entered it: the durable deadline is
checkpointed, the process is SIGKILLed, the approval is delivered while nothing is
running, and a replacement process resumes that same receive and consumes it.

**GP-10b** (requirement 10, second half) proves convergence across the one window
§12 says cannot be closed: the governance commit and DBOS's step checkpoint are not
one transaction, so a crash between them re-runs the step. The crash is made to
happen exactly there, on purpose, and the recovered run is required to converge
through the kernel's §10 replay branch — one consumption row, one audit event, one
transition, `SUCCESS`.

What this file does **not** do
------------------------------
It adds no production code and changes none. It contains no second replay policy: the
recovered apply step calls the same `kernel.apply_scope_approval` the production step
calls, and the convergence asserted below is the kernel's, reached through
`governance.sqlite`, not through anything the workflow layer decides. It does not make
`_submit_for_review` idempotent, add a self-loop, or weaken `IllegalTransition` — see
the ST8-R02 section.

The parent is never an executor
--------------------------------
This process observes and delivers; it never runs a workflow. Every observation of
DBOS state goes through `DBOSClient` — `list_workflows`, `list_workflow_steps`, `send`
— which is public API and dispatches nothing, so `dbos_sys.sqlite` stays opaque (§12)
and the parent can never accidentally recover the very workflow it is about to assert
is unrecovered. Constructing a `DBOS` instance here would do exactly that: startup
recovery would pick up the parked workflow inside the test process and the SIGKILL
would be proving nothing.

Governance is read over its **own** connection, in this process, which is a different
process from every one that wrote — so a durability claim below is never made through
the writer's own handle.

The ST8-R02 window is measured, not closed (owner disposition)
---------------------------------------------------------------
`_submit_for_review` takes `SPK1-1`, which is a transition, and §3's frozen graph has
no `SCOPE_REVIEW_PENDING → SCOPE_REVIEW_PENDING` edge. A crash landing strictly
between that step's governance commit and its DBOS checkpoint therefore makes recovery
re-run it and raise `IllegalTransition` — correct behaviour under the frozen graph, and
the owner's recorded disposition is that no replay or idempotency semantics are
authorized for it. ST-10 does not test that window and does not close it. What ST-10
does instead is prove its own kill points lie **outside** it:
`test_a_kill_lands_past_the_submit_checkpoint` asserts, before either kill, that
`_open_case` and `_submit_for_review` are present in the step records **with a
completion timestamp** — so recovery skips them rather than replaying them. The
plan's §16 remark that both steps are "idempotent at the store level regardless" is
inaccurate for `_submit_for_review` and nothing here relies on it; what the proofs rely
on is the checkpoint, which is asserted rather than assumed.

What the acceptance oracle compares (ST10-R01, ST10-R02)
---------------------------------------------------------
Every acceptance assertion here compares an **expected durable value**, never a shape
and never a substring. The ST-10 discovery review demonstrated that the earlier,
weaker forms were satisfiable by wrong data:

* a receive assertion that checked only *completion* accepted a substituted approval
  carrying `approver_id="different-owner@example.invalid"`. It is now exact string
  equality against the text `deliver_approval` actually sent, and the workflow result
  is read through `DBOSClient.retrieve_workflow(...).get_result()` — the worker's
  stdout line is corroboration, not the oracle (`assert_exact_receive`,
  `workflow_result`);
* `approval_digest.startswith("sha256:")` accepted 64 zeroes. It is now equality with
  `worker.approval_digest(...)`, the §6 identity of the exact delivered statement;
* counting bare event names across the database accepted `{}` as the audit detail and
  accepted every approval audit being written under `unrelated-workflow`. The audit is
  now identified by `workflow_id` and compared byte-for-byte against
  `expected_transition_detail`, both over raw SQL and through `store.read_audit`.

GP-10b snapshots **whole rows** — `seq`, `workflow_id`, both untrusted timestamps and
the canonical detail bytes — before the kill and requires equality after recovery, so a
replacement row re-derived by the replayed step is not mistaken for the survivor. Each
of these is exercised by a `test_c_*` control that damages a fabricated store and
requires the oracle to fail.

Deferred engine import (the collection-time constraint)
--------------------------------------------------------
Three frozen tests assert `"dbos" not in sys.modules` in-process
(`test_gp04_transition_policy.py:479`, `test_gp05_approval_statement.py:1163`,
`test_gp07_duplicate_approval.py:776`), and pytest imports every test module at
collection. So `dbos` is imported here only inside `_client_surface()`, and
`_restart_worker` — imported at module level, to keep one definition of the
specification, the approval and the marker names — is engine-free above its own
`main()`. Both disciplines are asserted below rather than left as prose.

Bounds
------
Every wait in this file has a deadline: readiness through `h.wait_for_ready`,
termination through `communicate(timeout=...)`, and the worker's own polls through its
`PARK_TIMEOUT_SECONDS` / `RESUME_TIMEOUT_SECONDS` / `BARRIER_TIMEOUT_SECONDS`. No test
here can hang indefinitely, and a worker that fails to reach its synchronization point
publishes a distinct failure marker and exits non-zero so the parent reports the real
cause.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sqlite3
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from pydantic import ValidationError

import _restart_worker as worker
from conftest import Harness
from gplanner import codec, store
from gplanner.canonical import canonical_bytes
from gplanner.kernel import (
    SCOPE_APPROVED_EVENT,
    apply_scope_approval,
    open_case,
    submit_for_review,
)
from gplanner.states import ActorKind, ScopeState

SRC = Path(__file__).resolve().parents[1] / "src" / "gplanner"
WORKER_SCRIPT = str(Path(__file__).resolve().parent / "_restart_worker.py")
THIS_MODULE = Path(__file__).resolve()

WORKFLOW_ID = "gp-spk-001-restart-0001"

#: The unmodified production workflow's registered name, as `WorkflowStatus.name`
#: reports it. GP-10a asserts it for the same reason GP-10b asserts the variant's:
#: a workflow is recovered as the function it was **started** as, and a proof that
#: never looks cannot tell a recovery from a fresh start of something else.
PRODUCTION_NAME = "scope_approval_workflow"

#: How long a resume process is given to recover, finish and exit. Comfortably above
#: the worker's own `RESUME_TIMEOUT_SECONDS`, so a worker that gives up reports its
#: own diagnosis rather than being cut off by the parent's bound.
RESUME_WAIT_SECONDS = 240.0

#: Governance state the workflow holds while it is parked: submitted, nothing claimed.
PENDING_CASE = (WORKFLOW_ID, str(ScopeState.SCOPE_REVIEW_PENDING), 2)
#: The case revision one approval leaves behind: drafting 1, submitted 2, approved 3.
APPROVED_REVISION = 3
#: Governance state after exactly one approval has been applied.
APPROVED_CASE = (WORKFLOW_ID, str(ScopeState.SCOPE_APPROVED), APPROVED_REVISION)

#: §3's coordinate for `SCOPE_REVIEW_PENDING -> SCOPE_APPROVED`, which the audit detail
#: cites. Written out rather than read from `policy.LEGAL_TRANSITIONS`: the oracle must
#: name the edge it expects, not agree with whatever the table happens to say.
TRANSITION_ROW = "SPK1-2"

#: `kernel._now()` is `datetime.now(UTC).isoformat()`. `consumed_at` and `audit.at` are
#: untrusted process clocks (CLAUDE.md, known gaps), so they are shape-checked and never
#: compared to an expected instant -- but they are compared to *themselves* across
#: GP-10b's replay, where a fresh timestamp would mean a replacement row.
RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?\+00:00")


# --- the deferred engine surface --------------------------------------------------


class ClientSurface(NamedTuple):
    """Everything this module needs from the engine, and nothing that runs a workflow."""

    DBOSClient: Any
    PORTABLE: Any
    APPROVAL_TOPIC: str
    APPLICATION_VERSION: str


def _client_surface() -> ClientSurface:
    """Import `dbos` and the two engine-importing gplanner modules — never at collection."""
    from dbos import DBOSClient, WorkflowSerializationFormat

    from gplanner.app import APPLICATION_VERSION
    from gplanner.workflow import APPROVAL_TOPIC

    return ClientSurface(
        DBOSClient=DBOSClient,
        PORTABLE=WorkflowSerializationFormat.PORTABLE,
        APPROVAL_TOPIC=APPROVAL_TOPIC,
        APPLICATION_VERSION=APPLICATION_VERSION,
    )


@pytest.fixture
def surface() -> ClientSurface:
    return _client_surface()


@pytest.fixture
def client(h: Harness, surface: ClientSurface) -> Iterator[Any]:
    """Read-only observation and external delivery. Runs no workflow, recovers none."""
    opened = surface.DBOSClient(system_database_url=f"sqlite:///{h.system_db}")
    try:
        yield opened
    finally:
        opened.destroy()


# --- observation helpers ----------------------------------------------------------


def workflow_status(client: Any, workflow_id: str = WORKFLOW_ID) -> Any:
    """`WorkflowStatus` is a plain class — attributes, not keys."""
    found = client.list_workflows(workflow_ids=[workflow_id])
    assert found, f"DBOS has no record of workflow {workflow_id!r}"
    return found[0]


def step_records(client: Any, workflow_id: str = WORKFLOW_ID) -> dict[str, Any]:
    """`function_name` -> `StepInfo`. `StepInfo` is a `TypedDict` — subscripted."""
    return {step["function_name"]: step for step in client.list_workflow_steps(workflow_id)}


def completed_steps(client: Any, workflow_id: str = WORKFLOW_ID) -> set[str]:
    """The steps DBOS has durably recorded as **finished**, not merely started."""
    return {
        name
        for name, step in step_records(client, workflow_id).items()
        if step["completed_at_epoch_ms"] is not None
    }


def spawn_phase(
    h: Harness,
    phase: str,
    kind: str,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    """Launch one worker process for one phase, over this test's two databases.

    `workflow_kind` is passed positionally and has no default anywhere in the chain,
    so a phase can never be handed the wrong workflow by omission (plan finding 10).
    """
    return h.spawn(
        WORKER_SCRIPT,
        str(h.system_db),
        str(h.governance_db),
        str(h.ready_dir),
        phase,
        kind,
        WORKFLOW_ID,
        env=env,
    )


def run_to_exit(proc: subprocess.Popen[bytes], timeout: float = RESUME_WAIT_SECONDS) -> str:
    """Wait for a worker to finish on its own, bounded, and return its diagnostics.

    Bounded because nothing in this suite may hang: a resume process that never
    terminates is killed here and reported as a failure naming its own output, rather
    than being left to wedge the suite.
    """
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate(timeout=30)
        pytest.fail(
            f"worker did not exit within {timeout}s:\n{out.decode('utf-8', errors='replace')}"
        )
    return out.decode("utf-8", errors="replace")


def assert_exited_cleanly(proc: subprocess.Popen[bytes], output: str) -> None:
    assert proc.returncode == 0, f"expected a normal exit, got {proc.returncode}:\n{output}"


def result_line(output: str) -> str:
    """The workflow's durable result as the worker printed it, or a loud failure."""
    for line in output.splitlines():
        if line.startswith(worker.RESULT_PREFIX):
            return line[len(worker.RESULT_PREFIX) :]
    pytest.fail(f"worker printed no {worker.RESULT_PREFIX!r} line:\n{output}")


def approval_audits(gov: worker.Governance) -> tuple[worker.AuditRow, ...]:
    """Every `scope.approved` row in the whole database, whatever workflow it names.

    Deliberately unscoped. Scoping the query to `WORKFLOW_ID` would make an approval
    audit misfiled under another workflow read as *zero* rows here and be caught only
    by a count — and the ST-10 discovery review demonstrated exactly that corruption
    (every approval audit written under `unrelated-workflow`) passing the superseded
    oracle. Reading them all and then asserting the single row's `workflow_id` catches
    both the misfiling and a duplicate hidden under a second workflow.
    """
    return tuple(row for row in gov.audit if row.event == SCOPE_APPROVED_EVENT)


def expected_transition_detail(digest: str, *, revision: int = APPROVED_REVISION) -> bytes:
    """The exact `detail_json` the kernel must have written for this transition.

    The frozen field set of `kernel._transition_detail` — §3's row coordinate, the
    approval's identity, the subject binding, the edge, the claimed approver and the
    resulting case revision — encoded through `canonical.canonical_bytes`, the package's
    single JCS encoder (§5). So the expectation is canonical *bytes*, not a spelling of
    them, and the comparison below is byte equality.

    No field is invented: `decision` is absent because the kernel does not record it,
    and `at` is not in the detail at all. `approver_id` and `approver_kind` are recorded
    claims, not authenticated facts (§11) — asserting them proves the audit carries the
    claim that was made, which is precisely what an unauthenticated channel can offer.

    This is what makes `{}` a failure. The superseded oracle never looked at the detail.
    """
    return canonical_bytes(
        {
            "row": TRANSITION_ROW,
            "approval_id": worker.APPROVAL_ID,
            "approval_digest": worker.approval_digest(digest, WORKFLOW_ID),
            "subject_digest": digest,
            "from_state": str(ScopeState.SCOPE_REVIEW_PENDING),
            "to_state": str(ScopeState.SCOPE_APPROVED),
            "approver_id": worker.APPROVER_ID,
            "approver_kind": str(ActorKind.HUMAN),
            "issued_at": worker.ISSUED_AT,
            "case_revision": revision,
        }
    )


def deliver_approval(client: Any, surface: ClientSurface, digest: str) -> str:
    """Deliver the approval the way an external approver would, with nothing running.

    `DBOSClient.send` against the system database is the whole channel — which is also
    exactly what §11 says is unauthenticated. `PORTABLE` keeps the statement stored as
    JSON rather than as base64 pickle, so an authority-bearing message never travels
    through `pickle` and stays readable to an auditor not running this code (§7).

    Returns the **exact text that was sent**, so the caller holds the expected durable
    value rather than re-deriving something that ought to equal it (ST10-R01). The
    recovered `DBOS.recv` output is compared against this string and nothing else.
    """
    message = worker.approval_json(digest, WORKFLOW_ID)
    client.send(
        WORKFLOW_ID,
        message,
        topic=surface.APPROVAL_TOPIC,
        serialization_type=surface.PORTABLE,
    )
    return message


# --- the recovered receive and the recovered result, exactly (ST10-R01) -----------


def assert_exact_receive(recv: Any, expected_message: str) -> None:
    """The durable receive is **completed** and its output is the exact approval sent.

    Split out from `assert_recovered_receive` so a negative control can hand it a
    fabricated record: the oracle is then testable without a recovery lifetime, and
    "this assertion would fail" is demonstrated rather than asserted in prose.

    Exact string equality, against the text `deliver_approval` returned. Completion
    alone — which is all the superseded assertion checked — is satisfied by *any*
    delivered message: the ST-10 discovery review substituted an approval carrying
    `approver_id="different-owner@example.invalid"` and the test still passed. Equality
    here fails for a change to any identity-bearing field, because every one of them is
    in this string: the approval id, the subject digest that binds it to the scope, the
    workflow it authorizes, the approver, the authority label and the issued instant.
    """
    assert recv is not None, "DBOS holds no `DBOS.recv` record for this workflow"
    assert recv["completed_at_epoch_ms"] is not None, f"receive not completed: {recv}"
    assert recv["error"] is None, f"receive recorded an error: {recv['error']!r}"
    output = recv["output"]
    assert isinstance(output, str), f"receive output is {type(output)!r}, expected str"
    assert output == expected_message, (
        "the durable receive output is not the approval that was delivered:\n"
        f"  expected: {expected_message}\n  actual:   {output}"
    )


def assert_recovered_receive(client: Any, expected_message: str) -> None:
    """`assert_exact_receive` against DBOS's own public step record for this workflow."""
    assert_exact_receive(step_records(client).get("DBOS.recv"), expected_message)


def workflow_result(client: Any) -> Any:
    """The workflow's durable result, through the public workflow-result API.

    `DBOSClient.retrieve_workflow(...).get_result()` — not the worker's stdout. A
    printed line is the worker's *report* of the result; this is the result. The handle
    is checked to be the one that was asked for, so a result can never be read off some
    other workflow (ST10-R01). `DBOSClient` dispatches nothing, so reading it here does
    not turn the observing process into an executor.
    """
    handle = client.retrieve_workflow(WORKFLOW_ID)
    assert handle.workflow_id == WORKFLOW_ID, handle.workflow_id
    return handle.get_result()


def assert_recovered_result(client: Any) -> None:
    """The durable result is exactly the approved state string — same type, same value."""
    result = workflow_result(client)
    assert isinstance(result, str), f"workflow result is {type(result)!r}, expected str"
    assert result == str(ScopeState.SCOPE_APPROVED), repr(result)


def assert_settled_identity(h: Harness, digest: str) -> None:
    """The whole authoritative identity chain, re-derived after recovery.

    Final enum state is not enough: a crash must not be able to produce something that
    merely *looks* equivalent. So the case, the consumption row, the audit row and
    the stored artifact bytes are all checked against the specification this test
    started from, over a connection opened in this process.

    `sha256(canonical_preimage)` is recomputed here rather than by calling the
    production digest function, and the bytes are decoded through `codec`'s single
    JSON → domain path, so the readback proves the stored artifact is still the
    artifact the approval was bound to (`GK-INV-1`).

    Every comparison is against an **expected durable value** (ST10-R02). The
    superseded version asserted that `approval_digest` merely *looked* like a digest
    and counted bare event names across the database; the ST-10 discovery review showed
    that this accepted 64 zeroes as the approval digest, `{}` as the audit detail, and
    every approval audit written under `unrelated-workflow`. Three things are checked
    here instead:

    * `approval_digest` equals `worker.approval_digest(...)`, the §6 identity of the
      exact statement that was delivered — the binding between the row and *this*
      approval, not a string shape;
    * there is exactly one `scope.approved` row **in the entire database** and its
      `workflow_id` is this workflow — misfiling it elsewhere fails, and so does a
      duplicate under a second workflow;
    * its `detail_json` equals `expected_transition_detail(...)` byte for byte.

    The two untrusted clocks (`consumed_at`, `at`) are shape-checked only: §11 gives
    them no trusted source, so an expected instant would be a fiction. Their *stability*
    is what GP-10b asserts, by comparing whole rows across the replay.

    Read twice, deliberately. `worker.governance` is raw SQL over its own connection,
    independent of the production store; `store.open` then re-reads through the public
    API. A disagreement between the two is itself a failure.
    """
    expected_approval_digest = worker.approval_digest(digest, WORKFLOW_ID)
    expected_detail = expected_transition_detail(digest)

    gov = worker.governance(h.governance_db)
    assert gov.cases == (APPROVED_CASE,)
    assert len(gov.consumptions) == 1, gov.consumptions
    consumed = gov.consumptions[0]
    assert consumed.approval_id == worker.APPROVAL_ID
    assert consumed.approval_digest == expected_approval_digest
    assert consumed.subject_digest == digest
    assert consumed.workflow_id == WORKFLOW_ID
    assert consumed.from_state == str(ScopeState.SCOPE_REVIEW_PENDING)
    assert consumed.to_state == str(ScopeState.SCOPE_APPROVED)
    assert RFC3339_UTC.fullmatch(consumed.consumed_at), consumed.consumed_at

    audits = approval_audits(gov)
    assert len(audits) == 1, audits
    audited = audits[0]
    assert audited.workflow_id == WORKFLOW_ID, audited
    assert audited.event == SCOPE_APPROVED_EVENT
    assert audited.detail_json == expected_detail, (
        f"audit detail is not the expected transition record:\n"
        f"  expected: {expected_detail!r}\n  actual:   {audited.detail_json!r}"
    )
    assert RFC3339_UTC.fullmatch(audited.at), audited.at
    # `scope.approved` is the only event the kernel writes, so the whole table is it.
    assert gov.audit == (audited,), gov.audit

    with store.open(h.governance_db) as governance:
        case = governance.load_case(WORKFLOW_ID)
        assert case is not None
        assert case.state is ScopeState.SCOPE_APPROVED
        assert case.subject_digest == digest
        assert case.revision == APPROVED_REVISION
        stored = governance.get_artifact(digest)
        assert stored is not None
        assert "sha256:" + hashlib.sha256(stored.canonical_preimage).hexdigest() == digest
        assert codec.decode_scope_from_preimage(stored.canonical_preimage) == worker.scope_spec()
        consumption = governance.find_consumption(worker.APPROVAL_ID)
        assert consumption is not None
        assert consumption.approval_digest == expected_approval_digest
        assert consumption.workflow_id == WORKFLOW_ID
        assert consumption.from_state is ScopeState.SCOPE_REVIEW_PENDING
        assert consumption.to_state is ScopeState.SCOPE_APPROVED
        assert consumption.subject_digest == digest
        # The same single row, reached through the workflow-scoped public read: an
        # approval audit filed under another workflow is absent here, not merely
        # miscounted.
        scoped = governance.read_audit(WORKFLOW_ID)
        assert len(scoped) == 1, scoped
        assert scoped[0].event == SCOPE_APPROVED_EVENT
        assert scoped[0].workflow_id == WORKFLOW_ID
        assert scoped[0].detail_json == expected_detail
        assert scoped[0].seq == audited.seq


def await_barrier_entries(
    h: Harness,
    count: int,
    proc: subprocess.Popen[bytes],
    timeout: float = 180.0,
) -> None:
    """Block until `barrier.log` holds `count` lines, or fail loudly. Bounded."""
    deadline = time.monotonic() + timeout
    entries: tuple[str, ...] = ()
    while time.monotonic() < deadline:
        entries = worker.barrier_entries(h.ready_dir)
        if len(entries) >= count:
            assert len(entries) == count, entries
            return
        if proc.poll() is not None:
            out, _ = proc.communicate(timeout=30)
            pytest.fail(
                f"worker exited (returncode={proc.returncode}) with {len(entries)} "
                f"barrier entries, expected {count}:\n{out.decode('utf-8', errors='replace')}"
            )
        time.sleep(0.05)
    pytest.fail(f"barrier.log never reached {count} entries within {timeout}s: {entries}")

# --- GP-10a: a previously entered durable receive survives a real SIGKILL ---------


def park(h: Harness, phase: str, kind: str) -> subprocess.Popen[bytes]:
    """Start a workflow and block until it is genuinely parked in its receive."""
    proc = spawn_phase(h, phase, kind)
    h.wait_for_ready(worker.MARKER_PARKED, proc)
    return proc


def assert_parked(client: Any, surface: ClientSurface, *, name: str) -> None:
    """The pre-kill predicate, asserted from the parent through public API only.

    `DBOS.sleep` present means `recv_setup` committed its durable deadline, so the
    receive was entered. `DBOS.recv` absent means no receive result has been
    checkpointed. Stated no more strongly than that (ST0-R02): it does not prove
    `recv_setup` has returned or that a thread is already blocked in `event.wait`.
    """
    status = workflow_status(client)
    assert str(status.status) == "PENDING"
    assert status.name == name
    assert status.app_version == surface.APPLICATION_VERSION
    names = set(step_records(client))
    assert "DBOS.sleep" in names, names
    assert "DBOS.recv" not in names, names


def test_a_durable_receive_resumes_after_real_sigkill(
    h: Harness, client: Any, surface: ClientSurface
) -> None:
    """GP-10a — requirement 9, the owner's option A.

    The receive is entered and its deadline checkpointed; the process dies by real
    `SIGKILL`; the approval is delivered with nothing alive to hold it; a replacement
    process resumes that same receive, consumes the message and applies exactly one
    approval through the unmodified kernel.
    """
    digest = worker.subject_digest(worker.scope_spec())
    proc = park(h, worker.PHASE_PARK_PRODUCTION, worker.KIND_PRODUCTION)

    assert_parked(client, surface, name=PRODUCTION_NAME)
    parked_gov = worker.governance(h.governance_db)
    assert parked_gov.cases == (PENDING_CASE,)
    assert parked_gov.consumptions == ()
    assert parked_gov.audit == ()

    h.kill9(proc)  # asserts returncode == -SIGKILL

    # Requirement 8: the state is DBOS's, not the dead process's.
    assert str(workflow_status(client).status) == "PENDING"
    assert worker.governance(h.governance_db).cases == (PENDING_CASE,)

    # The exact text delivered, held as the expected durable value (ST10-R01).
    delivered = deliver_approval(client, surface, digest)

    # Delivery alone authorizes nothing: no governance code has run.
    after_send = worker.governance(h.governance_db)
    assert after_send.cases == (PENDING_CASE,)
    assert after_send.consumptions == ()

    resumed = spawn_phase(h, worker.PHASE_RESUME_PRODUCTION, worker.KIND_PRODUCTION)
    output = run_to_exit(resumed)
    assert_exited_cleanly(resumed, output)

    status = workflow_status(client)
    assert str(status.status) == "SUCCESS"
    assert status.name == PRODUCTION_NAME
    assert status.app_version == surface.APPLICATION_VERSION
    # The receive was consumed by the *recovered* execution: it was absent before the
    # kill, and it is present, completed, and carrying exactly the approval that was
    # sent while nothing was alive to hold it.
    assert "DBOS.recv" in completed_steps(client)
    assert_recovered_receive(client, delivered)
    # The result through the public workflow-result API. The worker's stdout line is
    # checked too, but only as corroboration -- DBOS is the oracle, not the print.
    assert_recovered_result(client)
    assert result_line(output) == workflow_result(client)
    assert_settled_identity(h, digest)


def test_a_kill_lands_past_the_submit_checkpoint(h: Harness, client: Any) -> None:
    """The ST8-R02 window is avoided by construction, and that is measured.

    `_submit_for_review` is not idempotent and is not made so. This asserts that both
    steps preceding the receive are durably **completed** before the kill, so recovery
    skips them instead of replaying `SPK1-1` into an `IllegalTransition`. The proofs
    rest on this checkpoint, never on the plan's inaccurate "idempotent at the store
    level regardless" remark.
    """
    proc = park(h, worker.PHASE_PARK_PRODUCTION, worker.KIND_PRODUCTION)
    finished = completed_steps(client)
    assert {"_open_case", "_submit_for_review"} <= finished, finished
    h.kill9(proc)
    assert {"_open_case", "_submit_for_review"} <= completed_steps(client)


# --- GP-10b: governance committed, DBOS checkpoint absent -------------------------


def test_b_crash_between_governance_commit_and_dbos_checkpoint(
    h: Harness, client: Any, surface: ClientSurface
) -> None:
    """GP-10b — requirement 10's second half, and the sharpest test in the spike.

    The crash is placed inside §12's cross-database window on purpose: the governance
    transaction has committed and DBOS has not checkpointed the step that committed
    it. Recovery therefore re-runs that step, at-least-once, against a case that is
    already `SCOPE_APPROVED` — the exact condition `GK-INV-3` exists for. Convergence
    has to come from `governance.sqlite`'s §10 replay branch, because there is nothing
    else that could supply it.

    The workflow is the crash variant for its **entire lifetime** — started as it, and
    recovered as it in both later processes — because a workflow is recorded under the
    name it was started with (plan finding 10). Only the environment flag differs
    between the three phases.
    """
    digest = worker.subject_digest(worker.scope_spec())

    # Phase 1 — park the crash variant and kill it in its receive.
    parked = park(h, worker.PHASE_PARK_CRASH_VARIANT, worker.KIND_CRASH_VARIANT)
    assert_parked(client, surface, name=worker.CRASH_VARIANT_NAME)
    assert {"_open_case", "_submit_for_review"} <= completed_steps(client)
    h.kill9(parked)

    # Phase 2 — deliver the approval with no process alive.
    delivered = deliver_approval(client, surface, digest)
    assert worker.governance(h.governance_db).consumptions == ()
    assert worker.barrier_entries(h.ready_dir) == ()

    # Phase 3 — recover, apply, and stop dead inside the window.
    crashing = spawn_phase(
        h,
        worker.PHASE_CRASH_MID_APPLY,
        worker.KIND_CRASH_VARIANT,
        env={worker.CRASH_FLAG: "1"},
    )
    h.wait_for_ready(worker.MARKER_APPLIED, crashing)

    # The governance commit really did happen first, observed from this process over
    # its own connection while the committing process is still alive and parked.
    committed = worker.governance(h.governance_db)
    assert committed.cases == (APPROVED_CASE,)
    assert len(committed.consumptions) == 1, committed.consumptions
    assert len(approval_audits(committed)) == 1, committed.audit
    # The exact pre-kill identity snapshot: whole consumption and audit rows, including
    # `seq`, `workflow_id`, both untrusted timestamps and the canonical detail bytes.
    # Recovery must leave every one of them untouched (ST10-R02).
    before_consumptions = committed.consumptions
    before_audit = committed.audit
    assert before_audit[0].workflow_id == WORKFLOW_ID, before_audit
    assert before_audit[0].detail_json == expected_transition_detail(digest)

    # ...and DBOS has *not* recorded the step that committed it. This is the window.
    assert str(workflow_status(client).status) == "PENDING"
    assert "_apply_with_optional_barrier" not in completed_steps(client)
    assert len(worker.barrier_entries(h.ready_dir)) == 1, worker.barrier_entries(h.ready_dir)

    h.kill9(crashing)

    # Phase 4 — recover with the flag absent. The replayed step must converge.
    resumed = spawn_phase(h, worker.PHASE_RESUME_CRASH_VARIANT, worker.KIND_CRASH_VARIANT)
    output = run_to_exit(resumed)
    assert_exited_cleanly(resumed, output)
    assert_recovered_receive(client, delivered)
    assert_recovered_result(client)
    assert result_line(output) == workflow_result(client)

    # The barrier was entered exactly once: the replay did not re-enter it, which is
    # what distinguishes "the kernel converged" from "the harness happened not to
    # block again".
    assert len(worker.barrier_entries(h.ready_dir)) == 1, worker.barrier_entries(h.ready_dir)

    status = workflow_status(client)
    assert str(status.status) == "SUCCESS"
    assert status.name == worker.CRASH_VARIANT_NAME
    assert status.app_version == surface.APPLICATION_VERSION
    assert "_apply_with_optional_barrier" in completed_steps(client)

    # No duplicate consumption, no duplicate audit, no second transition — and the
    # surviving row is byte-for-byte the one committed before the crash, not a
    # re-derived lookalike.
    settled = worker.governance(h.governance_db)
    assert settled.consumptions == before_consumptions
    assert settled.audit == before_audit  # same seq, same workflow, same detail bytes
    assert settled.cases == (APPROVED_CASE,)
    assert_settled_identity(h, digest)


def test_b_the_replayed_step_really_re_executes_and_the_kernel_still_absorbs_it(
    h: Harness, client: Any, surface: ClientSurface
) -> None:
    """The recovered run re-executes the uncheckpointed step — and consumes nothing new.

    This is the control that separates the two ways GP-10b could look green. A passing
    GP-10b shows one barrier entry after recovery; that is consistent with *either*
    "DBOS re-ran the step and the kernel refused to consume the approval twice" or
    "DBOS skipped the step, so nothing was re-run at all". Only the first is what
    `GK-INV-3` claims.

    So this run re-arms the barrier: the recovery process is spawned **with the crash
    flag still set**, which is the one thing GP-10b's own recovery phase never does. If
    DBOS replays the step, the barrier is entered a second time and `barrier.log` grows
    to two lines — direct, observable proof that the step really re-executed against a
    case that was already `SCOPE_APPROVED`.

    And with that proof in hand the governance assertion becomes the sharp one: after a
    genuine second execution of the apply step, `approval_consumptions` still has
    exactly one row, `audit_events` still has exactly one `scope.approved`, and the case
    is still at revision 3. The kernel's §10 step-4 match branch absorbed the replay,
    wrote nothing, and reported `applied=False`. Nothing in the workflow layer decided
    that; there is no code there that could.
    """
    digest = worker.subject_digest(worker.scope_spec())
    parked = park(h, worker.PHASE_PARK_CRASH_VARIANT, worker.KIND_CRASH_VARIANT)
    h.kill9(parked)
    delivered = deliver_approval(client, surface, digest)

    crashing = spawn_phase(
        h, worker.PHASE_CRASH_MID_APPLY, worker.KIND_CRASH_VARIANT, env={worker.CRASH_FLAG: "1"}
    )
    h.wait_for_ready(worker.MARKER_APPLIED, crashing)
    assert len(worker.barrier_entries(h.ready_dir)) == 1
    committed = worker.governance(h.governance_db)
    assert committed.cases == (APPROVED_CASE,)
    assert len(committed.consumptions) == 1
    assert len(approval_audits(committed)) == 1, committed.audit
    h.kill9(crashing)

    # The flag is deliberately left set: this process is the control, not GP-10b's
    # recovery phase, which runs without it.
    replaying = spawn_phase(
        h,
        worker.PHASE_RESUME_CRASH_VARIANT,
        worker.KIND_CRASH_VARIANT,
        env={worker.CRASH_FLAG: "1"},
    )
    await_barrier_entries(h, 2, replaying)  # the step really did run a second time
    h.kill9(replaying)

    settled = worker.governance(h.governance_db)
    # Not merely "one row": the same rows. Whole-row equality covers `consumed_at`,
    # `seq`, `workflow_id` and the canonical detail bytes, so a row silently replaced
    # by a re-derived lookalike with a fresh timestamp fails here.
    assert settled.consumptions == committed.consumptions
    assert settled.audit == committed.audit
    assert settled.cases == (APPROVED_CASE,)
    assert_settled_identity(h, digest)

    # And once the flag is gone the same replay converges and the workflow completes.
    resumed = spawn_phase(h, worker.PHASE_RESUME_CRASH_VARIANT, worker.KIND_CRASH_VARIANT)
    output = run_to_exit(resumed)
    assert_exited_cleanly(resumed, output)
    assert str(workflow_status(client).status) == "SUCCESS"
    assert_recovered_receive(client, delivered)
    assert_recovered_result(client)
    assert result_line(output) == workflow_result(client)
    assert len(worker.barrier_entries(h.ready_dir)) == 2  # the clean replay added none
    final = worker.governance(h.governance_db)
    assert final.consumptions == committed.consumptions
    assert final.audit == committed.audit
    assert_settled_identity(h, digest)


def test_b_workflow_identity_was_checked_in_all_three_processes(
    h: Harness, client: Any, surface: ClientSurface
) -> None:
    """Every GP-10b process asserted, at runtime, which workflow it was looking at.

    Recovery resolves a function by the name the workflow was started with and by
    `application_version` (`dbos/_recovery.py:57`). A lifetime that mixed the two
    kinds would recover nothing and read exactly like a DBOS recovery failure. Each
    phase writes back what it observed, and all three records must agree.
    """
    digest = worker.subject_digest(worker.scope_spec())
    expected = (worker.CRASH_VARIANT_NAME, surface.APPLICATION_VERSION)

    parked = park(h, worker.PHASE_PARK_CRASH_VARIANT, worker.KIND_CRASH_VARIANT)
    h.kill9(parked)
    deliver_approval(client, surface, digest)

    crashing = spawn_phase(
        h,
        worker.PHASE_CRASH_MID_APPLY,
        worker.KIND_CRASH_VARIANT,
        env={worker.CRASH_FLAG: "1"},
    )
    h.wait_for_ready(worker.MARKER_APPLIED, crashing)
    h.kill9(crashing)

    resumed = spawn_phase(h, worker.PHASE_RESUME_CRASH_VARIANT, worker.KIND_CRASH_VARIANT)
    assert_exited_cleanly(resumed, run_to_exit(resumed))

    observed = {
        phase: worker.read_identity(h.ready_dir, phase)
        for phase in (
            worker.PHASE_PARK_CRASH_VARIANT,
            worker.PHASE_CRASH_MID_APPLY,
            worker.PHASE_RESUME_CRASH_VARIANT,
        )
    }
    assert observed == dict.fromkeys(observed, expected), observed


# --- negative controls: the detectors detect --------------------------------------


def test_c_duplicate_consumption_would_be_detected(h: Harness) -> None:
    """A second consumption row fails the identity assertion, rather than passing it.

    Written against the same helper the recovery tests use, over a fabricated store,
    so the claim "exactly one consumption row" is known to be a check and not a
    formality.
    """
    digest = _seed_approved_case(h)
    assert_settled_identity(h, digest)  # the honest state passes
    _insert_second_consumption(h, digest)
    with pytest.raises(AssertionError):
        assert_settled_identity(h, digest)


def test_c_duplicate_audit_event_would_be_detected(h: Harness) -> None:
    """A second `scope.approved` row fails the audit assertion."""
    digest = _seed_approved_case(h)
    _insert_second_audit(h)
    assert len(approval_audits(worker.governance(h.governance_db))) == 2
    with pytest.raises(AssertionError):
        assert_settled_identity(h, digest)


# --- ST10-R02 controls: the identity oracle rejects each demonstrated corruption ---


def test_c_a_wrong_consumption_digest_would_be_detected(h: Harness) -> None:
    """Control A. `sha256:` + 64 zeroes is digest-*shaped* and is not the digest.

    The exact corruption the ST-10 discovery review applied, which the superseded
    `approval_digest.startswith("sha256:")` accepted. The row now has to carry the §6
    identity of the statement that was actually delivered.
    """
    digest = _seed_approved_case(h)
    assert_settled_identity(h, digest)  # the honest state passes
    forged = "sha256:" + "0" * 64
    assert forged != worker.approval_digest(digest, WORKFLOW_ID)
    _corrupt(h, "UPDATE approval_consumptions SET approval_digest = ?", (forged,))
    with pytest.raises(AssertionError):
        assert_settled_identity(h, digest)


def test_c_an_audit_under_another_workflow_would_be_detected(h: Harness) -> None:
    """Controls B and D. A correct-looking approval audit filed under another workflow.

    This is the corruption that mattered most in discovery: a temporary production
    mutation writing every approval audit under `unrelated-workflow` passed all 15
    GP-10 tests, and the saved recovery databases held **zero** approval audits for the
    workflow under test. Counting event names across the database could not see it.
    """
    digest = _seed_approved_case(h)
    assert_settled_identity(h, digest)
    _corrupt(h, "UPDATE audit_events SET workflow_id = ?", ("unrelated-workflow",))
    gov = worker.governance(h.governance_db)
    assert len(approval_audits(gov)) == 1  # still exactly one, still `scope.approved`
    assert approval_audits(gov)[0].workflow_id == "unrelated-workflow"
    with pytest.raises(AssertionError):
        assert_settled_identity(h, digest)


def test_c_an_empty_audit_detail_would_be_detected(h: Harness) -> None:
    """Control C. `{}` is valid JSON, is non-empty bytes, and records no transition.

    The contract requires the structured identity `kernel._transition_detail` writes;
    an audit trail whose detail could be replaced by an empty object records that
    something happened and nothing about what authorized it.
    """
    digest = _seed_approved_case(h)
    assert_settled_identity(h, digest)
    _corrupt(h, "UPDATE audit_events SET detail_json = ?", (b"{}",))
    with pytest.raises(AssertionError):
        assert_settled_identity(h, digest)


def test_c_a_corrupted_audit_detail_field_would_be_detected(h: Harness) -> None:
    """One wrong field inside an otherwise complete detail still fails.

    Byte equality against `expected_transition_detail`, so the oracle does not merely
    require *a* structured detail: it requires **the** one, down to the §3 row
    coordinate and the claimed approver.
    """
    digest = _seed_approved_case(h)
    honest = expected_transition_detail(digest)
    for field, value in (
        ("row", "SPK1-1"),
        ("approver_id", "different-owner@example.invalid"),
        ("approval_digest", "sha256:" + "0" * 64),
        ("case_revision", 99),
    ):
        forged = _detail_with(digest, field, value)
        assert forged != honest, field
        _corrupt(h, "UPDATE audit_events SET detail_json = ?", (forged,))
        with pytest.raises(AssertionError):
            assert_settled_identity(h, digest)
    _corrupt(h, "UPDATE audit_events SET detail_json = ?", (honest,))
    assert_settled_identity(h, digest)  # and the honest detail still passes


def test_c_a_replacement_consumption_row_is_not_the_original(h: Harness) -> None:
    """GP-10b's replay equality detects a row rewritten with a fresh timestamp.

    Whole-row equality is what makes "the surviving row is the one committed before the
    crash" a check. A projection that dropped `consumed_at` would accept a row the
    recovered execution had silently re-derived.
    """
    digest = _seed_approved_case(h)
    before = worker.governance(h.governance_db)
    _corrupt(h, "UPDATE approval_consumptions SET consumed_at = ?", ("2026-01-01T00:00:00+00:00",))
    after = worker.governance(h.governance_db)
    assert len(after.consumptions) == 1
    assert after.consumptions != before.consumptions
    assert_settled_identity(h, digest)  # still internally consistent -- only replay sees it


def test_c_a_replacement_audit_row_is_not_the_original(h: Harness) -> None:
    """The same, for the audit row GP-10b snapshots across the replay."""
    _seed_approved_case(h)
    before = worker.governance(h.governance_db)
    _corrupt(h, "UPDATE audit_events SET at = ?", ("2026-01-01T00:00:00+00:00",))
    after = worker.governance(h.governance_db)
    assert len(after.audit) == 1
    assert after.audit != before.audit
    assert after.audit[0].detail_json == before.audit[0].detail_json


# --- ST10-R01 controls: the receive oracle rejects a substituted approval ----------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("approver_id", "different-owner@example.invalid"),
        ("approval_id", "ffffffffffffffffffffffffffffffff"),
        ("workflow_id", "some-other-workflow"),
        ("issued_at", "2026-09-18T10:00:00Z"),
    ],
)
def test_c_a_substituted_approval_message_would_be_detected(field: str, value: str) -> None:
    """The exact reproduction of the ST-10 discovery review's transport substitution.

    `approver_id="different-owner@example.invalid"` is the substitution Codex delivered;
    the superseded GP-10a passed with it, because it asserted only that the receive had
    *completed*. Each substituted message below is a fully valid approval — it decodes
    through `codec` and re-encodes canonically, so the only difference from the expected
    text is the one identity-bearing field. `assert_exact_receive` has to fail on each.
    """
    digest = worker.subject_digest(worker.scope_spec())
    expected = worker.approval_json(digest, WORKFLOW_ID)
    substituted = _substituted_approval_json(digest, field, value)
    assert substituted != expected, field
    assert_exact_receive(_recv_record(expected), expected)  # the honest message passes
    with pytest.raises(AssertionError):
        assert_exact_receive(_recv_record(substituted), expected)


def test_c_a_substituted_scope_binding_would_be_detected() -> None:
    """Changing the subject digest — the scope/case binding — fails the same oracle."""
    digest = worker.subject_digest(worker.scope_spec())
    expected = worker.approval_json(digest, WORKFLOW_ID)
    other = "sha256:" + "0" * 64
    assert other != digest
    with pytest.raises(AssertionError):
        assert_exact_receive(_recv_record(worker.approval_json(other, WORKFLOW_ID)), expected)


def test_c_a_substituted_authority_cannot_even_be_decoded() -> None:
    """Authority is not substitutable at all: `approver_kind` is `Literal[HUMAN]` (§11).

    The receive oracle never gets the chance to reject a `SYSTEM`- or `LLM`-labelled
    approval, because `codec.decode_approval` — the single `gp_transport_decode` site —
    refuses it first. Recorded here so the required authority control is a demonstrated
    refusal rather than an untested gap in the parametrization above.
    """
    digest = worker.subject_digest(worker.scope_spec())
    for authority in (str(ActorKind.SYSTEM), str(ActorKind.LLM)):
        wire = worker.approval_wire(digest, WORKFLOW_ID)
        wire["predicate"]["approver_kind"] = authority  # type: ignore[index]
        with pytest.raises(ValidationError):
            codec.decode_approval(json.dumps(wire))


def test_c_an_incomplete_receive_is_not_accepted() -> None:
    """A receive with no completion timestamp, or an error, is not a recovered receive."""
    digest = worker.subject_digest(worker.scope_spec())
    expected = worker.approval_json(digest, WORKFLOW_ID)
    with pytest.raises(AssertionError):
        assert_exact_receive(None, expected)
    uncompleted = _recv_record(expected)
    uncompleted["completed_at_epoch_ms"] = None
    with pytest.raises(AssertionError):
        assert_exact_receive(uncompleted, expected)
    failed = _recv_record(expected)
    failed["error"] = RuntimeError("boom")
    with pytest.raises(AssertionError):
        assert_exact_receive(failed, expected)


def test_c_wrong_subject_identity_would_be_detected(h: Harness) -> None:
    """A case that settled on a different artifact fails, even in the right state.

    The failure mode this guards is precise: crash and restart must not be able to
    produce something that reads as `SCOPE_APPROVED` while being bound to an artifact
    the approval was never issued for.
    """
    digest = _seed_approved_case(h)
    other = "sha256:" + "0" * 64
    assert other != digest
    with pytest.raises(AssertionError):
        assert_settled_identity(h, other)


def test_c_barrier_counting_distinguishes_zero_one_and_many(h: Harness) -> None:
    """`barrier.log` counts entries; it does not merely record that one happened.

    Zero, one and two entries must be three distinguishable observations — otherwise
    "entered exactly once" could not be the evidence GP-10b rests on.
    """
    assert worker.barrier_entries(h.ready_dir) == ()
    worker.record_barrier_entry(h.ready_dir, WORKFLOW_ID)
    assert len(worker.barrier_entries(h.ready_dir)) == 1
    worker.record_barrier_entry(h.ready_dir, WORKFLOW_ID)
    assert len(worker.barrier_entries(h.ready_dir)) == 2


def test_c_missing_identity_record_is_not_silently_equal(h: Harness) -> None:
    """A phase that never ran its identity check reads as `None`, never as a match."""
    assert worker.read_identity(h.ready_dir, worker.PHASE_CRASH_MID_APPLY) is None
    worker.identity_record(h.ready_dir, worker.PHASE_CRASH_MID_APPLY).write_text(
        f"{worker.CRASH_VARIANT_NAME}\tgp-spk-001\n", encoding="utf-8"
    )
    assert worker.read_identity(h.ready_dir, worker.PHASE_CRASH_MID_APPLY) == (
        worker.CRASH_VARIANT_NAME,
        "gp-spk-001",
    )


def test_c_a_phase_cannot_be_given_the_wrong_workflow_kind() -> None:
    """`workflow_kind` is required, has no default, and is checked against the phase."""
    for phase, kind in worker.PHASE_KIND.items():
        wrong = (
            worker.KIND_CRASH_VARIANT if kind == worker.KIND_PRODUCTION else worker.KIND_PRODUCTION
        )
        with pytest.raises(SystemExit):
            worker._parse_args(["_restart_worker.py", "s", "g", "r", phase, wrong, "w"])
    with pytest.raises(SystemExit):
        worker._parse_args(["_restart_worker.py", "s", "g", "r", worker.PHASE_PARK_PRODUCTION])


# --- structural: no crash hook, no test flag, no barrier in production ------------


def test_d_production_carries_no_crash_hook_or_test_flag() -> None:
    """Every test-only construct lives under `tests/`, and nowhere else.

    The barrier is the one piece of this stage that could leave production code
    permanently dependent on test infrastructure. It does not, and that is asserted on
    the source rather than remembered.
    """
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert worker.CRASH_FLAG not in text, f"{path} names the crash flag"
        assert "GP_TEST" not in text, f"{path} names a test-only environment flag"
        assert "barrier" not in text.lower(), f"{path} mentions a barrier"


def test_d_the_worker_defers_every_engine_import() -> None:
    """`_restart_worker` is importable at collection without pulling in `dbos`.

    This module imports it at collection time, and three frozen tests assert the
    engine is absent from `sys.modules`. So the worker's engine imports must all sit
    inside function bodies — asserted structurally, because a future edit that hoisted
    one to module level would break three frozen tests in a way that looks unrelated.
    """
    forbidden = ("dbos", "gplanner.app", "gplanner.workflow", "_crash_variant")
    tree = ast.parse(Path(worker.__file__).read_text(encoding="utf-8"))
    for node in tree.body:  # module level only: nested imports are the whole point
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith(forbidden) for a in node.names), ast.dump(node)
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith(forbidden), ast.dump(node)


def test_d_this_module_defers_every_engine_import() -> None:
    """The same discipline, for this file: `dbos` is imported only inside a function."""
    tree = ast.parse(THIS_MODULE.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("dbos") for a in node.names), ast.dump(node)
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("dbos"), ast.dump(node)


def test_d_the_parent_never_constructs_a_dbos_executor() -> None:
    """The observing process uses `DBOSClient` only — it must never become an executor.

    A `DBOS` instance here would run startup recovery inside the test process and
    silently recover the very workflow the SIGKILL is meant to leave unrecovered.
    """
    tree = ast.parse(THIS_MODULE.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("dbos")
        for alias in node.names
    }
    assert "DBOS" not in imported, imported
    assert "DBOSClient" in imported


# --- fabricated governance state, for the negative controls only ------------------


def _seed_approved_case(h: Harness) -> str:
    """Drive the real kernel to `SCOPE_APPROVED` in-process, with no engine involved.

    The negative controls need an honest settled state to damage. It is produced by
    the production kernel rather than by hand-written rows, so the "before" half of
    each control is genuinely the thing the recovery tests assert.
    """
    model = worker.scope_spec()
    digest = worker.subject_digest(model)
    statement = codec.decode_approval(worker.approval_json(digest, WORKFLOW_ID))
    with store.open(h.governance_db) as governance:
        open_case(governance, WORKFLOW_ID, model)
        submit_for_review(governance, WORKFLOW_ID, ActorKind.SYSTEM)
        outcome = apply_scope_approval(governance, WORKFLOW_ID, statement)
    assert outcome.applied is True
    assert outcome.state is ScopeState.SCOPE_APPROVED
    return digest


def _insert_second_consumption(h: Harness, digest: str) -> None:
    """Forge a second consumption row. Only a negative control ever does this."""
    connection = sqlite3.connect(h.governance_db)
    try:
        connection.execute(
            "INSERT INTO approval_consumptions (approval_id, approval_digest, "
            "subject_digest, workflow_id, from_state, to_state, consumed_at) "
            "SELECT 'ffffffffffffffffffffffffffffffff', approval_digest, subject_digest, "
            "workflow_id, from_state, to_state, consumed_at FROM approval_consumptions"
        )
        connection.commit()
    finally:
        connection.close()
    assert len(worker.governance(h.governance_db).consumptions) == 2
    assert digest, "the caller's digest is what the damaged state must now fail against"


def _insert_second_audit(h: Harness) -> None:
    """Forge a second `scope.approved` event. Only a negative control ever does this."""
    connection = sqlite3.connect(h.governance_db)
    try:
        connection.execute(
            "INSERT INTO audit_events (workflow_id, at, event, detail_json) "
            "SELECT workflow_id, at, event, detail_json FROM audit_events"
        )
        connection.commit()
    finally:
        connection.close()


def _corrupt(h: Harness, sql: str, parameters: tuple[object, ...]) -> None:
    """Damage one column of a settled governance database. Negative controls only.

    Applied to a fabricated store the control built itself, never to a recovery
    lifetime's database, so no mutation of production behaviour is involved and nothing
    here survives the test. Parameterized rather than interpolated so the forged value
    is stored exactly as given — a digest string as a string, `{}` as a BLOB.
    """
    connection = sqlite3.connect(h.governance_db)
    try:
        connection.execute(sql, parameters)
        connection.commit()
    finally:
        connection.close()


def _detail_with(digest: str, field: str, value: object) -> bytes:
    """`expected_transition_detail` with exactly one field changed. Controls only."""
    detail: dict[str, object] = {
        "row": TRANSITION_ROW,
        "approval_id": worker.APPROVAL_ID,
        "approval_digest": worker.approval_digest(digest, WORKFLOW_ID),
        "subject_digest": digest,
        "from_state": str(ScopeState.SCOPE_REVIEW_PENDING),
        "to_state": str(ScopeState.SCOPE_APPROVED),
        "approver_id": worker.APPROVER_ID,
        "approver_kind": str(ActorKind.HUMAN),
        "issued_at": worker.ISSUED_AT,
        "case_revision": APPROVED_REVISION,
    }
    assert field in detail, field  # never invent a field the kernel does not write
    detail[field] = value
    return canonical_bytes(detail)


def _substituted_approval_json(digest: str, field: str, value: str) -> str:
    """A fully valid approval with exactly one predicate field changed. Controls only.

    Built from `worker.approval_wire` — the same mapping the delivered approval is
    rendered from — and round-tripped through `codec` exactly as `worker.approval_json`
    does. So the result is canonical transport text that differs from the expected
    message in one *semantic* field and in nothing else: no key reordering, no
    whitespace difference, nothing an oracle could trip over for the wrong reason.
    """
    wire = worker.approval_wire(digest, WORKFLOW_ID)
    predicate = wire["predicate"]
    assert isinstance(predicate, dict) and field in predicate, field
    predicate[field] = value
    return codec.encode_approval(codec.decode_approval(json.dumps(wire)))


def _recv_record(output: str) -> dict[str, Any]:
    """A `StepInfo`-shaped record for `DBOS.recv`, so the oracle can be tested directly.

    `StepInfo` is a `TypedDict` (CLAUDE.md), so a plain mapping with its keys is exactly
    what `assert_exact_receive` reads from a real one. Fabricating it here is what lets
    the substitution controls above run without a recovery lifetime — the alternative,
    a subprocess proxy that rewrites the delivered message, proves the same thing far
    more slowly and leaves a substitution hook in the suite.
    """
    return {
        "function_id": 3,
        "function_name": "DBOS.recv",
        "output": output,
        "error": None,
        "child_workflow_id": None,
        "started_at_epoch_ms": 1_789_744_066_788,
        "completed_at_epoch_ms": 1_789_744_068_711,
    }
