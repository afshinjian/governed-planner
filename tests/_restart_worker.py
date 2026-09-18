"""ST-10's restart worker — one OS process per phase of a recovery lifetime.

Design basis: design/GP-SPK-001-governance-kernel.md §12, §13.1 (requirements 8, 9
and 10), §14.

Not a test module: the name does not match `test_*`, so pytest never collects it.
It is launched as `python tests/_restart_worker.py <sys_db> <gov_db> <ready_dir>
<phase> <workflow_kind> <workflow_id>`. Together with `_crash_variant.py`, which holds
the barrier itself, it is the **only** place in the repository where a test-only crash
barrier exists. No production module contains a crash hook, a test flag, or a barrier
of any kind.

Why a separate process at all
-----------------------------
GP-10a and GP-10b are the two rows of §13.1 that cannot be established in-process.
Requirement 9 is about a durable receive surviving a process that no longer exists,
and requirement 10's second half is about the window between a governance commit and
a DBOS checkpoint — a window that only exists because the two databases are not one
transaction (§12). Both are claims about what survives a real `SIGKILL`, so both are
proven by killing a real process and starting another one over the same two SQLite
files. There is no monkeypatching here, no raised exception standing in for a crash,
and no in-process re-instantiation of the engine.

Importable without the engine (the collection-time constraint)
--------------------------------------------------------------
`tests/test_gp10_restart_recovery.py` imports this module at collection time to
share one definition of the scope specification, the approval statement and the
marker names. Three frozen tests assert `"dbos" not in sys.modules` in-process
(`test_gp04_transition_policy.py:479`, `test_gp05_approval_statement.py:1163`,
`test_gp07_duplicate_approval.py:776`), and pytest imports every test module before
running any test. So **nothing above `main()` imports `dbos`**: the engine, the two
engine-importing gplanner modules and the crash variant's registration all live
inside `_registered()`, which only a worker process ever calls. Everything above it
is standard library plus the governance layer, which §4 guarantees is engine-free.

Publishing and holding are two functions, never one (plan finding 7)
---------------------------------------------------------------------
`publish_ready` creates, fsyncs, renames and fsyncs the directory entry, then
**returns**. `hold_until_killed` parks the calling thread forever. They are separate
because a durable step that never returns is never checkpointed, so recovery
legitimately re-runs it — and a step that blocked forever the first time would block
forever again, invalidating a recovery proof even with a correct kernel. The only
`@DBOS.step` in this file that can block is the crash barrier, and it blocks only in
the process that is *deliberately* being killed, gated on an environment flag the
recovery process does not carry.

What "parked" means, no more strongly than it is (ST0-R02)
-----------------------------------------------------------
`recv_setup` checkpoints its durable deadline as `DBOS.sleep` **before** it begins
waiting (`dbos/_sys_db.py:3305`), and `DBOS.recv` is recorded only on consume. So

    "DBOS.sleep" in names and "DBOS.recv" not in names

means: **the receive was entered, the deadline checkpoint is committed, and no
receive result has been checkpointed.** It does *not* prove `recv_setup` has returned
or that a thread is already blocked in `event.wait` — the block itself is later
(`_sys_db.py:3470`). The receive has genuinely been entered, which is what
requirement 9 needs; nothing more is claimed here.

The predicate is evaluated from the worker's **main thread**, through
`DBOS.list_workflow_steps` — public introspection API, never SQL against
`dbos_sys.sqlite`, whose opacity (§12) binds test code too. Nothing it does is a
durable operation, so nothing it does can replay.

The ST8-R02 window is avoided, not absorbed
--------------------------------------------
`_submit_for_review` is **not** idempotent and is not made so anywhere: `SPK1-1` is a
transition and §3's frozen graph has no `SCOPE_REVIEW_PENDING → SCOPE_REVIEW_PENDING`
edge, so a re-run is refused as an illegal self-loop. That is the owner's recorded
disposition and it is correct behaviour, not a gap to engineer around. Both recovery
proofs therefore kill **after** that step has been checkpointed: the parked predicate
below requires `_open_case` and `_submit_for_review` to be present in the step records,
so the kill provably lands past the window rather than inside it. The window itself is
analyzed in the ST-10 handoff and left exactly as ST-8 froze it -- not tested, not
closed, and not worked around.

Every phase is bounded
----------------------
No phase waits forever except at a point where the parent is about to send `SIGKILL`.
Every poll has a deadline; on expiry the worker publishes a distinct failure marker
and exits non-zero, so the parent fails loudly with captured diagnostics instead of
hanging on a readiness timeout.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Final, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gplanner import codec  # noqa: E402
from gplanner.artifacts import ScopeSpec  # noqa: E402
from gplanner.digest import (  # noqa: E402
    APPROVAL_MEDIA_TYPE,
    SCOPE_MEDIA_TYPE,
    canonical_preimage,
    compute_digest,
    to_intoto_hex,
)
from gplanner.states import ActorKind, ScopeState  # noqa: E402
from gplanner.store import STORAGE_VERSION, UNSTAMPED_STORAGE_VERSION  # noqa: E402

# --- the two workflow kinds and the five phases -----------------------------------

#: The unmodified production `scope_approval_workflow`. GP-10a's whole lifetime.
KIND_PRODUCTION: Final[str] = "production"
#: The test-only variant carrying the crash barrier. GP-10b's whole lifetime.
KIND_CRASH_VARIANT: Final[str] = "crash_variant"

PHASE_PARK_PRODUCTION: Final[str] = "park_production"
PHASE_RESUME_PRODUCTION: Final[str] = "resume_production"
PHASE_PARK_CRASH_VARIANT: Final[str] = "park_crash_variant"
PHASE_CRASH_MID_APPLY: Final[str] = "crash_mid_apply"
PHASE_RESUME_CRASH_VARIANT: Final[str] = "resume_crash_variant"

#: Which kind each phase is allowed to be given. A workflow is recorded under the
#: function name it was **started** with, and registering a different function in a
#: later process does not retarget it (`dbos/_recovery.py:57`). Mixing a production
#: start with a crash-variant recovery therefore recovers nothing at all -- a harness
#: bug that would read exactly like a DBOS recovery failure. `workflow_kind` is a
#: required argument with no default, and every phase checks the kind it was handed.
PHASE_KIND: Final[dict[str, str]] = {
    PHASE_PARK_PRODUCTION: KIND_PRODUCTION,
    PHASE_RESUME_PRODUCTION: KIND_PRODUCTION,
    PHASE_PARK_CRASH_VARIANT: KIND_CRASH_VARIANT,
    PHASE_CRASH_MID_APPLY: KIND_CRASH_VARIANT,
    PHASE_RESUME_CRASH_VARIANT: KIND_CRASH_VARIANT,
}

#: The registered name of the crash variant, as `WorkflowStatus.name` reports it.
#: Asserted at runtime in all three GP-10b processes rather than assumed.
CRASH_VARIANT_NAME: Final[str] = "_crashable_scope_approval_workflow"

#: Set by the parent on the `crash_mid_apply` spawn and on no other. Absent from the
#: recovery process, which is what makes the replayed step return instead of parking.
CRASH_FLAG: Final[str] = "GP_TEST_CRASH_AFTER_GOVERNANCE_COMMIT"

# --- markers and evidence files ---------------------------------------------------

#: Published once the workflow is parked in its durable receive.
MARKER_PARKED: Final[str] = "parked"
#: Published by the crash barrier, after the governance transaction has committed.
MARKER_APPLIED: Final[str] = "applied"
#: Published instead of `parked` when the park poll times out, so the parent fails
#: with "worker never parked" rather than with an anonymous readiness timeout.
MARKER_PARK_FAILED: Final[str] = "park_failed"
#: Published when a recovery process cannot reach the barrier within its bound.
MARKER_CRASH_FAILED: Final[str] = "crash_failed"

#: One fsynced line per barrier entry. The line count is the direct, observable proof
#: of how many times the barrier was entered -- the evidence that separates "the
#: kernel converged" from "the harness happened not to block a second time".
BARRIER_LOG: Final[str] = "barrier.log"

#: The workflow's durable result, printed by a resume phase on its way to exit 0.
RESULT_PREFIX: Final[str] = "workflow-result: "

# --- bounds. Nothing here waits forever except where the parent is about to kill ---

PARK_TIMEOUT_SECONDS: Final[float] = 120.0
RESUME_TIMEOUT_SECONDS: Final[float] = 180.0
BARRIER_TIMEOUT_SECONDS: Final[float] = 180.0
POLL_INTERVAL_SECONDS: Final[float] = 0.05

# --- the artifact and the approval, defined once for parent and worker ------------

#: An opaque, unauthenticated label (§11). The spelling is a reminder, not a
#: credential: the approval channel proves nothing about who sent this.
APPROVER_ID: Final[str] = "unverified-owner@example.invalid"
APPROVAL_ID: Final[str] = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
ISSUED_AT: Final[str] = "2026-09-18T09:00:00Z"


def scope_spec() -> ScopeSpec:
    """The one scope specification both recovery proofs run against."""
    return ScopeSpec(
        title="Governance kernel feasibility",
        problem_statement="Prove the authority model survives a real process death.",
        in_scope=("durable approval waiting", "restart recovery"),
        out_of_scope=("signing",),
        acceptance_criteria=("a killed worker's successor applies exactly one approval",),
    )


def preimage_text(model: ScopeSpec) -> str:
    """The workflow's `spec_json` argument: the §6 canonical preimage document.

    `codec` exposes exactly one JSON -> `ScopeSpec` path and it reads the envelope
    (§7), so this is the only text `_open_case` can decode.
    """
    return canonical_preimage(model, SCOPE_MEDIA_TYPE).decode("utf-8")


def subject_digest(model: ScopeSpec) -> str:
    return compute_digest(model, SCOPE_MEDIA_TYPE)


def approval_json(digest: str, workflow_id: str, *, approval_id: str = APPROVAL_ID) -> str:
    """Transport text for one `SCOPE_REVIEW_PENDING → SCOPE_APPROVED` approval.

    The mapping is rendered with `json.dumps` and then passed through `codec`, which is
    the convention the frozen GP-09 suite already uses. Only the *decode* half is
    constrained: §7 forbids `json.loads(...)` + `model_validate(...)`, and the decode
    here is `codec.decode_approval`, the package's single `gp_transport_decode` site.

    Decoding before encoding is deliberate rather than round-about. It means a malformed
    builder fails here, against the model's own constraints, instead of being delivered
    as something the workflow then refuses for a reason that has nothing to do with what
    the test was proving.
    """
    return codec.encode_approval(
        codec.decode_approval(json.dumps(approval_wire(digest, workflow_id, approval_id)))
    )


def approval_wire(digest: str, workflow_id: str, approval_id: str = APPROVAL_ID) -> dict[str, Any]:
    """The in-toto mapping `approval_json` renders, as one editable definition.

    Exposed so the ST10-R01 negative controls can substitute exactly one
    identity-bearing field and leave everything else byte-identical. Keeping one wire
    definition is the point: a control that hand-built its own mapping could differ
    from the delivered approval in key order or whitespace and would then "detect" a
    difference that was never semantic.
    """
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "gplanner.scope/v1", "digest": {"sha256": to_intoto_hex(digest)}}],
        "predicateType": "https://governed-planner/ScopeApproval/v1",
        "predicate": {
            "predicate_version": "gplanner.scope-approval/v1",
            "approval_id": approval_id,
            "workflow_id": workflow_id,
            "from_state": str(ScopeState.SCOPE_REVIEW_PENDING),
            "to_state": str(ScopeState.SCOPE_APPROVED),
            "approver_id": APPROVER_ID,
            "approver_kind": str(ActorKind.HUMAN),
            "decision": "APPROVE",
            "issued_at": ISSUED_AT,
        },
    }


def approval_digest(subject: str, workflow_id: str, *, approval_id: str = APPROVAL_ID) -> str:
    """The `approval_digest` the kernel is required to record for that exact approval.

    The expected *durable value*, derived from the same statement the parent delivers
    (ST10-R02). `compute_digest` is the package's one identity pipeline, so this is the
    approval's §6 identity rather than a hash of transport text -- which is exactly the
    value `approval_consumptions.approval_digest` and the audit detail must carry.

    Any change to any identity-bearing field of the approval changes this string, so
    comparing against it is what makes "the right approval was consumed" a check rather
    than a shape test. The superseded `startswith("sha256:")` accepted 64 zeroes.
    """
    return compute_digest(
        codec.decode_approval(approval_json(subject, workflow_id, approval_id=approval_id)),
        APPROVAL_MEDIA_TYPE,
    )


# --- readiness primitives (plan finding 7: publishing and holding are separate) ----


def publish_ready(ready_dir: Path, name: str) -> None:
    """Publish a readiness marker durably. NEVER blocks; always returns.

    Both the file and the containing directory entry are fsynced, so the parent
    cannot observe readiness before the child genuinely reached this point. The
    rename is atomic, so a partially written marker is never visible under its final
    name.
    """
    ready_dir.mkdir(parents=True, exist_ok=True)
    tmp = ready_dir / f"{name}.ready.{os.getpid()}.partial"
    with open(tmp, "wb") as handle:
        handle.write(f"{name} {os.getpid()}\n".encode())
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, ready_dir / f"{name}.ready")
    fd = os.open(ready_dir, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def hold_until_killed() -> None:
    """Park this PROCESS until the parent sends `SIGKILL`.

    Never called from a durable step except inside the flag-gated crash barrier of
    the process that is deliberately being killed.
    """
    while True:
        time.sleep(3600)


def barrier_log(ready_dir: Path) -> Path:
    return ready_dir / BARRIER_LOG


def barrier_entries(ready_dir: Path) -> tuple[str, ...]:
    """Every recorded barrier entry, in order. Empty when the barrier never ran."""
    path = barrier_log(ready_dir)
    if not path.exists():
        return ()
    return tuple(line for line in path.read_text(encoding="utf-8").splitlines() if line)


def identity_record(ready_dir: Path, phase: str) -> Path:
    """Where a GP-10b phase records the workflow identity it observed."""
    return ready_dir / f"identity.{phase}.txt"


def read_identity(ready_dir: Path, phase: str) -> tuple[str, str] | None:
    """`(name, app_version)` as that phase observed them, or `None` if it never looked."""
    path = identity_record(ready_dir, phase)
    if not path.exists():
        return None
    name, _, app_version = path.read_text(encoding="utf-8").strip().partition("\t")
    return name, app_version


# --- governance observation (ours; `dbos_sys.sqlite` stays opaque) ----------------


class ConsumptionRow(NamedTuple):
    """One `approval_consumptions` row, **every** column of it (ST10-R02).

    Whole rows rather than a projection: GP-10b's replay proof asserts that the row
    which survives recovery is byte-for-byte the row committed before the crash, and a
    projection that dropped `from_state` or `consumed_at` would let a replacement row
    with a fresh timestamp pass as the original.
    """

    approval_id: str
    approval_digest: str
    subject_digest: str
    workflow_id: str
    from_state: str
    to_state: str
    consumed_at: str


class AuditRow(NamedTuple):
    """One `audit_events` row, carrying its identity and its content (ST10-R02).

    `workflow_id` and `detail_json` are kept because dropping them is precisely the
    weakness the ST-10 discovery review demonstrated: counting bare event *names*
    across the whole database accepted an approval audit written under an unrelated
    workflow, and accepted `{}` as its detail. `detail_json` stays `bytes` -- the store
    never parses it (§7) and neither does this observer.
    """

    seq: int
    workflow_id: str
    at: str
    event: str
    detail_json: bytes


class Governance(NamedTuple):
    cases: tuple[tuple[str, str, int], ...]
    consumptions: tuple[ConsumptionRow, ...]
    audit: tuple[AuditRow, ...]


def schema_committed(path: Path) -> bool:
    """Has the governance schema been **committed**, or is there merely a file?

    File existence is not readiness (ST9-R01): `store.open` connects and sets §12's
    pragmas before the DDL transaction, so the file exists for a window in which no
    table does. `_create_schema` writes the tables and `PRAGMA user_version` in one
    transaction, so the stamp is committed if and only if the tables are.

    Exactly two readings mean "not yet": no file, and the unstamped `0`. Every other
    version and every `sqlite3` failure is raised, so a broken database is reported
    as broken rather than waited out until the readiness bound blames the workflow.
    """
    if not path.exists():
        return False
    connection = sqlite3.connect(path)
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    finally:
        connection.close()
    if version == STORAGE_VERSION:
        return True
    if version == UNSTAMPED_STORAGE_VERSION:
        return False
    raise AssertionError(
        f"governance database at {path} reports storage version {version}, which is "
        f"neither {UNSTAMPED_STORAGE_VERSION} (not yet created) nor {STORAGE_VERSION}"
    )


def governance(path: Path) -> Governance:
    """Read `governance.sqlite` over its own connection — ours, and never DBOS's.

    A separate connection, and in the parent's case a separate *process*, from the one
    that wrote: a durability observation made through the writer's own handle would
    prove nothing about what survived it.
    """
    if not path.exists() or not schema_committed(path):
        return Governance((), (), ())
    connection = sqlite3.connect(path)
    try:
        cases = tuple(
            (str(row[0]), str(row[1]), int(row[2]))
            for row in connection.execute(
                "SELECT workflow_id, state, revision FROM cases ORDER BY workflow_id"
            )
        )
        consumptions = tuple(
            ConsumptionRow(
                str(r[0]), str(r[1]), str(r[2]), str(r[3]), str(r[4]), str(r[5]), str(r[6])
            )
            for r in connection.execute(
                "SELECT approval_id, approval_digest, subject_digest, workflow_id, "
                "from_state, to_state, consumed_at FROM approval_consumptions "
                "ORDER BY approval_id"
            )
        )
        audit = tuple(
            AuditRow(int(r[0]), str(r[1]), str(r[2]), str(r[3]), bytes(r[4]))
            for r in connection.execute(
                "SELECT seq, workflow_id, at, event, detail_json FROM audit_events ORDER BY seq"
            )
        )
        return Governance(cases, consumptions, audit)
    finally:
        connection.close()


# --- the engine-importing half. Nothing above this line imports `dbos`. -----------


class Registered(NamedTuple):
    """The engine surface plus the two workflows a phase may start or recover."""

    DBOS: Any
    SetWorkflowID: Any
    make_config: Any
    APPLICATION_VERSION: str
    production: Any
    crash_variant: Any


def _registered(ready_dir: Path) -> Registered:
    """Import the engine, register both workflows, and hand back the surface.

    Called only by a worker process, never at import time -- see the module
    docstring's collection-time constraint. Importing `_crash_variant` is what
    registers GP-10b's workflow, and it happens in **every** phase: `workflow_kind`
    decides which workflow is *started*, and a workflow is only ever recovered as the
    function it was started as (`dbos/_recovery.py:57`).
    """
    from dbos import DBOS, SetWorkflowID

    import _crash_variant
    from gplanner.app import APPLICATION_VERSION, make_config
    from gplanner.workflow import scope_approval_workflow

    _crash_variant.arm(ready_dir)
    return Registered(
        DBOS=DBOS,
        SetWorkflowID=SetWorkflowID,
        make_config=make_config,
        APPLICATION_VERSION=APPLICATION_VERSION,
        production=scope_approval_workflow,
        crash_variant=_crash_variant._crashable_scope_approval_workflow,
    )


def record_barrier_entry(ready_dir: Path, workflow_id: str) -> None:
    """Append exactly one fsynced line per barrier entry.

    Appended and fsynced rather than written, so a second entry could never overwrite
    the first: the count is the evidence, and an evidence file that could lose a line
    would make "entered once" and "entered twice" indistinguishable.
    """
    with open(barrier_log(ready_dir), "a", encoding="utf-8") as handle:
        handle.write(f"barrier {os.getpid()} {workflow_id}\n")
        handle.flush()
        os.fsync(handle.fileno())


# --- phase bodies -----------------------------------------------------------------


class Args(NamedTuple):
    sys_db: Path
    gov_db: Path
    ready_dir: Path
    phase: str
    workflow_kind: str
    workflow_id: str


def _parse_args(argv: list[str]) -> Args:
    if len(argv) != 7:
        raise SystemExit(
            "usage: _restart_worker.py <sys_db> <gov_db> <ready_dir> <phase> "
            "<workflow_kind> <workflow_id>"
        )
    _, sys_db, gov_db, ready_dir, phase, workflow_kind, workflow_id = argv
    if phase not in PHASE_KIND:
        raise SystemExit(f"unknown phase {phase!r}; expected one of {sorted(PHASE_KIND)}")
    if workflow_kind != PHASE_KIND[phase]:
        raise SystemExit(
            f"phase {phase!r} requires workflow_kind {PHASE_KIND[phase]!r}, "
            f"was given {workflow_kind!r}"
        )
    return Args(Path(sys_db), Path(gov_db), Path(ready_dir), phase, workflow_kind, workflow_id)


def _step_records(registered: Registered, workflow_id: str) -> dict[str, Any]:
    """`function_name` -> `StepInfo`. `StepInfo` is a `TypedDict`: subscripted."""
    return {
        step["function_name"]: step
        for step in registered.DBOS.list_workflow_steps(workflow_id)
    }


def _assert_identity(registered: Registered, args: Args) -> None:
    """Prove this process is looking at the workflow it thinks it is (plan finding 10).

    Run in every GP-10b process. A workflow is recorded under the name it was started
    with, and recovery resolves the function by that name and by `application_version`
    (`dbos/_recovery.py:57`). Reading both back and failing loudly turns "we believe
    recovery targeted the same function" into a checked fact -- and the record is
    written to a file so the parent can assert it even for the process it kills.
    """
    found = registered.DBOS.list_workflows(workflow_ids=[args.workflow_id])
    if not found:
        raise SystemExit(f"identity check: DBOS has no record of workflow {args.workflow_id!r}")
    status = found[0]  # `WorkflowStatus` is a plain class: attributes, not keys.
    identity_record(args.ready_dir, args.phase).write_text(
        f"{status.name}\t{status.app_version}\n", encoding="utf-8"
    )
    if status.name != CRASH_VARIANT_NAME or status.app_version != registered.APPLICATION_VERSION:
        raise SystemExit(
            f"identity check failed in phase {args.phase!r}: workflow "
            f"{args.workflow_id!r} is recorded as name={status.name!r} "
            f"app_version={status.app_version!r}, expected "
            f"name={CRASH_VARIANT_NAME!r} app_version={registered.APPLICATION_VERSION!r}"
        )
    print(
        f"identity-ok: phase={args.phase} name={status.name} "
        f"app_version={status.app_version}",
        flush=True,
    )


def _await_parked(registered: Registered, args: Args) -> None:
    """Block until the workflow is parked in its durable receive, or fail loudly.

    Four conditions, all required:

    * `governance.sqlite` reads `SCOPE_REVIEW_PENDING` for this workflow -- the
      governance half, read over its own connection once the schema is committed;
    * `_open_case` and `_submit_for_review` are both present in the step records --
      so the kill lands *past* the ST8-R02 window rather than inside it;
    * `DBOS.sleep` present -- the durable deadline is checkpointed, so the receive was
      entered;
    * `DBOS.recv` absent -- no receive result has been checkpointed.

    On expiry the worker publishes `park_failed.ready` and exits 1, so the parent
    reports "never parked" with diagnostics instead of waiting out its own bound.
    """
    deadline = time.monotonic() + PARK_TIMEOUT_SECONDS
    names: set[str] = set()
    cases: tuple[tuple[str, str, int], ...] = ()
    while time.monotonic() < deadline:
        names = set(_step_records(registered, args.workflow_id))
        cases = governance(args.gov_db).cases
        submitted = cases == ((args.workflow_id, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
        checkpointed = {"_open_case", "_submit_for_review"} <= names
        if submitted and checkpointed and "DBOS.sleep" in names and "DBOS.recv" not in names:
            print(f"parked: steps={sorted(names)} cases={cases}", flush=True)
            return
        time.sleep(POLL_INTERVAL_SECONDS)
    print(
        f"park failure: workflow {args.workflow_id!r} never parked within "
        f"{PARK_TIMEOUT_SECONDS}s: steps={sorted(names)} cases={cases}"
    , flush=True)
    publish_ready(args.ready_dir, MARKER_PARK_FAILED)
    raise SystemExit(1)


TERMINAL: Final[frozenset[str]] = frozenset(
    {"SUCCESS", "ERROR", "CANCELLED", "MAX_RECOVERY_ATTEMPTS_EXCEEDED"}
)


def _await_result(registered: Registered, args: Args) -> str:
    """Wait for the recovered workflow to finish, bounded, then return its result.

    `get_result()` on its own would block for the hour-long durable deadline if
    recovery never happened, so the status is polled to a terminal value first and the
    handle is only drained once there is a result to drain. A recovery that never
    starts therefore fails in `RESUME_TIMEOUT_SECONDS` with the status it was stuck on.
    """
    deadline = time.monotonic() + RESUME_TIMEOUT_SECONDS
    state = ""
    while time.monotonic() < deadline:
        found = registered.DBOS.list_workflows(workflow_ids=[args.workflow_id])
        state = str(found[0].status) if found else "<unknown>"
        if state in TERMINAL:
            handle = registered.DBOS.retrieve_workflow(args.workflow_id)
            result = str(handle.get_result())
            print(
                f"recovered: status={state} "
                f"recovery_attempts={found[0].recovery_attempts}",
                flush=True,
            )
            return result
        time.sleep(POLL_INTERVAL_SECONDS)
    print(
        f"resume failure: workflow {args.workflow_id!r} did not reach a terminal "
        f"status within {RESUME_TIMEOUT_SECONDS}s: status={state}"
    , flush=True)
    raise SystemExit(1)


def _park(registered: Registered, args: Args, target: Any) -> None:
    """Start `target`, wait until it is parked, publish, then hold for the SIGKILL."""
    with registered.SetWorkflowID(args.workflow_id):
        registered.DBOS.start_workflow(target, preimage_text(scope_spec()), str(args.gov_db))
    if args.workflow_kind == KIND_CRASH_VARIANT:
        _assert_identity(registered, args)
    _await_parked(registered, args)
    publish_ready(args.ready_dir, MARKER_PARKED)
    hold_until_killed()


def _resume(registered: Registered, args: Args) -> None:
    """Recover the workflow started by an earlier process and let it finish.

    `launch()` has already run by the time this is called: startup recovery is what
    picks the workflow up, gated on `application_version`, and nothing here asks for
    it explicitly. The process then waits, prints the durable result and exits 0.
    """
    if args.workflow_kind == KIND_CRASH_VARIANT:
        _assert_identity(registered, args)
    result = _await_result(registered, args)
    print(f"{RESULT_PREFIX}{result}", flush=True)


def _crash_mid_apply(registered: Registered, args: Args) -> None:
    """Recover the parked workflow and let its apply step park in the crash barrier.

    The barrier runs on the DBOS recovery thread, inside the step. This thread only
    waits for the marker that thread publishes and then holds for the parent's
    `SIGKILL` -- so if the barrier is never reached, the worker exits non-zero and the
    parent's readiness wait reports an exited worker with diagnostics rather than
    hanging.
    """
    if os.environ.get(CRASH_FLAG) != "1":
        raise SystemExit(f"phase {args.phase!r} requires {CRASH_FLAG}=1 in the environment")
    _assert_identity(registered, args)
    marker = args.ready_dir / f"{MARKER_APPLIED}.ready"
    deadline = time.monotonic() + BARRIER_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if marker.exists():
            hold_until_killed()
        time.sleep(POLL_INTERVAL_SECONDS)
    print(
        f"barrier failure: the crash barrier was not reached within "
        f"{BARRIER_TIMEOUT_SECONDS}s for workflow {args.workflow_id!r}"
    , flush=True)
    publish_ready(args.ready_dir, MARKER_CRASH_FAILED)
    raise SystemExit(1)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    args.ready_dir.mkdir(parents=True, exist_ok=True)

    registered = _registered(args.ready_dir)
    registered.DBOS(config=registered.make_config(args.sys_db))
    registered.DBOS.launch()

    if args.phase == PHASE_PARK_PRODUCTION:
        _park(registered, args, registered.production)
    elif args.phase == PHASE_PARK_CRASH_VARIANT:
        _park(registered, args, registered.crash_variant)
    elif args.phase == PHASE_CRASH_MID_APPLY:
        _crash_mid_apply(registered, args)
    else:
        _resume(registered, args)
        registered.DBOS.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
