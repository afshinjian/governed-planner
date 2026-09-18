"""GP-09 — the workflow parks in a durable receive, and one approval resumes it.

Design basis: design/GP-SPK-001-governance-kernel.md §13.1 (requirements 7 and 8),
§4, §7, §9 (`GK-INV-6`), §11, §12.

Two halves, and the second is the one that matters most. The first shows the
integration works: the workflow opens a case, submits it, parks in `DBOS.recv`, does
not advance while no approval exists, and reaches `SCOPE_APPROVED` once an approval is
delivered from outside by `DBOSClient.send`. The second shows what the integration did
**not** acquire on the way: no authority. Every refusal a delivered approval can earn
is the kernel's, arrives at the caller as the kernel's own error class, and leaves
`governance.sqlite` exactly as it was.

ST-9 is the integration, not the recovery campaign. Nothing here kills a process; the
real-`SIGKILL` proofs (GP-10a, GP-10b) are ST-10's, and the property this file relies
on -- that a receive survives a dead process -- was established by ST-0.

What "parked" means here, stated no more strongly than it is (ST0-R02)
----------------------------------------------------------------------
The predicate is `DBOS.sleep` present and `DBOS.recv` absent in
`DBOS.list_workflow_steps`, plus `SCOPE_REVIEW_PENDING` in `governance.sqlite`. It
means: **the receive was entered, its deadline checkpoint is committed, and no receive
result has been checkpointed.** `record_sleep` commits that deadline *inside*
`recv_setup` (`dbos/_sys_db.py:3305`), before it returns, and the block itself comes
later (`_sys_db.py:3470`), so the predicate does **not** prove `recv_setup` has
returned or that a thread is already waiting on the event. The receive has genuinely
been entered, which is what these tests need; nothing more is claimed.

Step records are read through `DBOS.list_workflow_steps`, DBOS's public introspection
API, never by SQL against `dbos_sys.sqlite` -- §12 makes that database opaque, and the
opacity rule holds for test code too. `StepInfo` is a `TypedDict`, so its fields are
read with `step["function_name"]`; `WorkflowStatus` is a plain class, so its fields are
read as attributes. The two conventions are genuinely mixed in one API.

Why the engine is imported lazily, and what that is working around
------------------------------------------------------------------
Three frozen tests assert `"dbos" not in sys.modules` in-process
(`test_gp04_transition_policy.py:479`, `test_gp05_approval_statement.py:1163`,
`test_gp07_duplicate_approval.py:776`). pytest imports every test module at collection,
before any test runs, so a module-level `import dbos` **here** puts the engine into
`sys.modules` and fails all three -- measured, not predicted.

So this module imports `dbos`, `gplanner.app` and `gplanner.workflow` inside
`_engine()`, on first use, never at collection. Under the repository's prescribed
whole-suite run the three frozen assertions therefore still execute before any engine
import happens. This is a deliberate, recorded workaround and not a fix: those
assertions are process-global, so they remain order-sensitive, and running this file
*before* one of those three in the same process would still fail it. Making them
order-independent means checking the import in a subprocess, which would edit three
frozen ST-4/ST-6/ST-8 test files; that is an owner decision, not an ST-9 one. The
discipline is asserted below (`test_d_this_module_defers_every_engine_import`) so it
cannot decay silently.

Readiness is a committed schema, not a created file (ST9-R01)
--------------------------------------------------------------
`sqlite3.connect` plus §12's `journal_mode` pragma creates `governance.sqlite` *before*
`store.open` has begun the DDL transaction, so the file exists for a window in which no
table does. An observer that treated file existence as readiness therefore queried
`cases` inside that window and failed with `no such table: cases` -- against a workflow
that went on to park perfectly well. The readiness predicate is `PRAGMA user_version`
instead: `store._create_schema` writes the DDL and that stamp in **one** transaction, so
the stamp is committed if and only if the four frozen tables are. `schema_committed`
absorbs exactly the two readings a half-built store produces -- no file, and the
unstamped `0` -- and raises on every other version and every other `sqlite3` failure, so
waiting for a slow start is still distinguishable from waiting on a broken database.

Releasing the parked receive (a test-process constraint, not a product one)
---------------------------------------------------------------------------
`DBOS.destroy()` does **not** interrupt a workflow thread blocked in `DBOS.recv`: the
thread is a non-daemon executor thread, and the interpreter joins it at exit, so a test
that leaves a workflow parked hangs the pytest process until the hour-long durable
deadline elapses -- measured on dbos 2.31.1. `DBOS.cancel_workflow` does not free it
either: `_sys_db.recv`'s wait loop rechecks for the *notification* and never for
cancellation (`_sys_db.py:3467-3471`). Delivering a message is therefore the only
release there is. The deadline is not shortened to work around this: §13 fixes it long
precisely so a crash-recovery window cannot be mistaken for a timeout. Instead
`start_and_park` delivers a release message in teardown, **after** every assertion has
run, which the receive consumes and the transport decode then refuses. Teardown is
therefore visible in the governance database as nothing at all.

Cleanup covers readiness, not just the assertions (ST9-R02)
------------------------------------------------------------
Because delivering that message is the only release, the window in which no cleanup is
armed has to be as close to empty as it can be made. `start_and_park` enters its
`try`/`finally` **immediately** after `start_workflow`, so waiting for readiness happens
*inside* cleanup protection: a readiness failure, a readiness timeout and an exception
in a test body all reach the same `release`. `release` is correspondingly teardown-grade
-- bounded, and it never raises -- because it now runs on paths where an exception is
already in flight, and one raised from a `finally` would replace the diagnosis with its
own. `await_ready` is a seam on `start_and_park` so those failure paths are exercised by
a regression test against a genuinely parked workflow, rather than merely described.
"""

from __future__ import annotations

import ast
import json
import sqlite3
import time
import warnings
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from conftest import Harness
from gplanner import codec, errors, store
from gplanner.artifacts import ScopeSpec
from gplanner.digest import (
    SCOPE_MEDIA_TYPE,
    canonical_preimage,
    compute_digest,
    to_intoto_hex,
)
from gplanner.errors import ApprovalBindingError, GovernedPlannerError, StaleApproval
from gplanner.states import ActorKind, ScopeState

SRC = Path(__file__).resolve().parents[1] / "src" / "gplanner"
THIS_FILE = Path(__file__).resolve()

WORKFLOW_ID = "gp-spk-001-workflow-0001"
OTHER_WORKFLOW_ID = "gp-spk-001-workflow-0002"
APPROVAL_ID = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a88"

#: An opaque, unauthenticated label. §11: the approval channel proves nothing about who
#: sent this, and the spelling is a reminder rather than a credential.
APPROVER_ID = "unverified-owner@example.invalid"
ISSUED_AT = "2026-09-17T11:22:33Z"

#: How long "no approval was delivered" is observed for. Not a synchronization device:
#: the parked predicate is already established before it starts, so this only gives the
#: workflow room to advance if it were going to.
HOLD_SECONDS = 1.0

#: Bounds on polling. Long enough to be unreachable on a healthy machine, short enough
#: that a genuine hang is reported as a failure rather than as a wedged suite.
PARK_TIMEOUT_SECONDS = 60.0
SETTLE_TIMEOUT_SECONDS = 60.0

#: The bound on teardown's release (ST9-R02). Separate from `SETTLE_TIMEOUT_SECONDS`
#: because it governs a path where a failure is already in flight: it decides how long
#: cleanup may take, not how long a workflow is given to be correct.
RELEASE_TIMEOUT_SECONDS = 60.0

#: Delivered in teardown only. It is valid transport (a JSON string) and invalid
#: approval JSON, so `codec.decode_approval` refuses it and no governance call is
#: reached -- the receive is released without anything being decided.
RELEASE_MESSAGE = "gp-spk-001 test teardown: this is not an approval"

#: The frozen governance hierarchy (plan of record revision 5, ST-2). ST-9 adds nothing
#: to it; `workflow.ApprovalTimeout` deliberately lives outside it.
FROZEN_ERROR_CLASSES = frozenset(
    {
        "ApprovalBindingError",
        "ApprovalReplay",
        "AuthorityDenied",
        "CanonicalizationError",
        "ConcurrentModification",
        "DigestMismatch",
        "IllegalTransition",
        "PayloadProfileViolation",
        "StaleApproval",
        "StoreSchemaTooOld",
    }
)

#: Every module plan §5 names, now complete: ST-9 adds the last two.
FROZEN_MODULES = frozenset(
    {
        "__init__",
        "app",
        "approvals",
        "artifacts",
        "canonical",
        "codec",
        "digest",
        "errors",
        "kernel",
        "policy",
        "profile",
        "require",
        "states",
        "store",
        "workflow",
    }
)


# --- the deferred engine surface --------------------------------------------------


class Engine(NamedTuple):
    """Everything this module needs from the engine-importing layers."""

    DBOS: Any
    DBOSClient: Any
    SetWorkflowID: Any
    PORTABLE: Any
    make_config: Any
    APPLICATION_NAME: str
    APPLICATION_VERSION: str
    APPROVAL_TOPIC: str
    APPROVAL_TIMEOUT_SECONDS: float
    ApprovalTimeout: type[BaseException]
    scope_approval_workflow: Any


def _engine() -> Engine:
    """Import `dbos`, `gplanner.app` and `gplanner.workflow` — never at collection.

    See the module docstring: three frozen tests assert the engine is absent from
    `sys.modules`, and pytest imports every test module before running any test.
    """
    from dbos import DBOS, DBOSClient, SetWorkflowID, WorkflowSerializationFormat

    from gplanner.app import APPLICATION_NAME, APPLICATION_VERSION, make_config
    from gplanner.workflow import (
        APPROVAL_TIMEOUT_SECONDS,
        APPROVAL_TOPIC,
        ApprovalTimeout,
        scope_approval_workflow,
    )

    return Engine(
        DBOS=DBOS,
        DBOSClient=DBOSClient,
        SetWorkflowID=SetWorkflowID,
        PORTABLE=WorkflowSerializationFormat.PORTABLE,
        make_config=make_config,
        APPLICATION_NAME=APPLICATION_NAME,
        APPLICATION_VERSION=APPLICATION_VERSION,
        APPROVAL_TOPIC=APPROVAL_TOPIC,
        APPROVAL_TIMEOUT_SECONDS=APPROVAL_TIMEOUT_SECONDS,
        ApprovalTimeout=ApprovalTimeout,
        scope_approval_workflow=scope_approval_workflow,
    )


# --- builders ---------------------------------------------------------------------


def spec(title: str = "Governance kernel feasibility") -> ScopeSpec:
    return ScopeSpec(
        title=title,
        problem_statement="Prove the authority model with no LLM in the loop.",
        in_scope=("durable approval waiting",),
        out_of_scope=("signing",),
        acceptance_criteria=("the workflow parks and one approval resumes it",),
    )


def preimage_text(model: ScopeSpec) -> str:
    """The workflow's `spec_json` argument: the §6 canonical preimage document.

    `codec` exposes exactly one JSON -> `ScopeSpec` path and it reads the envelope, so
    this is the only text `_open_case` can decode (§7).
    """
    return canonical_preimage(model, SCOPE_MEDIA_TYPE).decode("utf-8")


def wire(
    subject_digest: str,
    *,
    approval_id: str = APPROVAL_ID,
    workflow_id: str = WORKFLOW_ID,
    approver_id: str = APPROVER_ID,
) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "gplanner.scope/v1",
                "digest": {"sha256": to_intoto_hex(subject_digest)},
            }
        ],
        "predicateType": "https://governed-planner/ScopeApproval/v1",
        "predicate": {
            "predicate_version": "gplanner.scope-approval/v1",
            "approval_id": approval_id,
            "workflow_id": workflow_id,
            "from_state": str(ScopeState.SCOPE_REVIEW_PENDING),
            "to_state": str(ScopeState.SCOPE_APPROVED),
            "approver_id": approver_id,
            "approver_kind": str(ActorKind.HUMAN),
            "decision": "APPROVE",
            "issued_at": ISSUED_AT,
        },
    }


def approval_json(subject_digest: str, **overrides: Any) -> str:
    """Transport text, produced through `codec` so no second encoder exists in tests.

    The dict goes through `decode_approval` first, so a malformed builder fails here
    rather than being delivered as something the workflow then refuses for the wrong
    reason.
    """
    statement = codec.decode_approval(json.dumps(wire(subject_digest, **overrides)))
    return codec.encode_approval(statement)


# --- governance observation (ours; `dbos_sys.sqlite` stays opaque) -----------------


class Governance(NamedTuple):
    cases: tuple[tuple[str, str, int], ...]
    consumptions: tuple[tuple[Any, ...], ...]
    audit_events: tuple[str, ...]


def schema_committed(path: Path) -> bool:
    """Has the governance schema been **committed**, or is there merely a file (ST9-R01)?

    File existence is not readiness. `store.open` calls `sqlite3.connect` and then §12's
    `journal_mode` pragma, both of which precede the DDL transaction, so
    `governance.sqlite` exists for a window in which `cases` does not -- and an observer
    polling in that window fails with `no such table: cases` against a workflow that is
    on its way to parking correctly.

    `store._create_schema` writes the four `CREATE TABLE` statements and
    `PRAGMA user_version = STORAGE_VERSION` inside one transaction, so the stamp is
    committed if and only if the tables are. Reading the stamp is therefore an
    observation of the whole schema, and it is one that needs no table to exist yet.

    Exactly two readings mean "not ready yet": no file at all, and the unstamped `0` a
    half-built database reports. Every other version, and every `sqlite3` failure, is
    raised -- so a database that is broken rather than slow is reported as such instead
    of being waited out until the readiness timeout blames the workflow for it.
    """
    if not path.exists():
        return False
    connection = sqlite3.connect(path)
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    finally:
        connection.close()
    if version == store.STORAGE_VERSION:
        return True
    if version == store.UNSTAMPED_STORAGE_VERSION:
        return False
    raise AssertionError(
        f"governance database at {path} reports storage version {version}, which is "
        f"neither {store.UNSTAMPED_STORAGE_VERSION} (not yet created) nor "
        f"{store.STORAGE_VERSION} (this build's schema)"
    )


def governance(path: Path) -> Governance:
    """Read `governance.sqlite` directly — ours, and never DBOS's.

    The assertion reader, and it assumes a committed schema: `schema_committed` is what
    waits, and this is what looks (ST9-R01). A `sqlite3` failure here is a real defect
    and is left to propagate.
    """
    if not path.exists():
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
            tuple(row)
            for row in connection.execute(
                "SELECT approval_id, workflow_id, from_state, to_state "
                "FROM approval_consumptions ORDER BY approval_id"
            )
        )
        audit_events = tuple(
            str(row[0])
            for row in connection.execute("SELECT event FROM audit_events ORDER BY seq")
        )
        return Governance(cases, consumptions, audit_events)
    finally:
        connection.close()


# --- fixtures ---------------------------------------------------------------------


@dataclass
class Parked:
    """One workflow, parked in its durable receive."""

    workflow_id: str
    handle: Any
    subject_digest: str
    spec: ScopeSpec


@pytest.fixture
def engine() -> Engine:
    return _engine()


@pytest.fixture
def runtime(h: Harness, engine: Engine) -> Iterator[None]:
    """One configured, launched DBOS instance per test, over this test's `tmp_path`."""
    engine.DBOS(config=engine.make_config(h.system_db))
    engine.DBOS.launch()
    try:
        yield
    finally:
        engine.DBOS.destroy()


@pytest.fixture
def client(h: Harness, engine: Engine) -> Iterator[Any]:
    """The external delivery channel: a `DBOSClient` that runs no workflows."""
    opened = engine.DBOSClient(system_database_url=f"sqlite:///{h.system_db}")
    try:
        yield opened
    finally:
        opened.destroy()


#: The readiness observation `start_and_park` uses. A parameter, not a hard call, so
#: the cleanup-covers-readiness claim (ST9-R02) is exercised by a regression test
#: against a real parked workflow instead of being asserted in prose.
AwaitReady = Any


def start_and_park(
    h: Harness,
    engine: Engine,
    client: Any,
    await_ready: AwaitReady = None,
) -> Iterator[Parked]:
    """The `parked` fixture's body, as a generator a test can also drive (ST9-R02).

    The `try` opens on the statement **after** `start_workflow`, so everything that can
    fail from there on -- readiness failing, readiness timing out, a test body raising --
    is inside cleanup. Before this, readiness ran ahead of the `try`, so a readiness
    failure skipped `release` entirely and left a workflow parked in a receive that
    `DBOS.destroy()` cannot interrupt; pytest then reported the failure and the process
    stayed alive on a non-daemon thread until the hour-long durable deadline elapsed.
    """
    ready = await_parked if await_ready is None else await_ready
    model = spec()
    with engine.SetWorkflowID(WORKFLOW_ID):
        handle = engine.DBOS.start_workflow(
            engine.scope_approval_workflow, preimage_text(model), str(h.governance_db)
        )
    try:
        ready(engine, WORKFLOW_ID, h.governance_db)
        yield Parked(
            workflow_id=WORKFLOW_ID,
            handle=handle,
            subject_digest=compute_digest(model, SCOPE_MEDIA_TYPE),
            spec=model,
        )
    finally:
        release(engine, client, WORKFLOW_ID, handle)


@pytest.fixture
def parked(h: Harness, engine: Engine, runtime: None, client: Any) -> Iterator[Parked]:
    """Start `scope_approval_workflow` and wait until it is parked in `DBOS.recv`."""
    yield from start_and_park(h, engine, client)


# --- observation helpers ----------------------------------------------------------


def step_names(engine: Engine, workflow_id: str) -> set[str]:
    """`StepInfo` is a `TypedDict` — subscripted, never attribute-accessed."""
    return {step["function_name"] for step in engine.DBOS.list_workflow_steps(workflow_id)}


def status(engine: Engine, workflow_id: str) -> Any:
    """`WorkflowStatus` is a plain class — attributes, not keys. Mixed conventions."""
    return engine.DBOS.list_workflows(workflow_ids=[workflow_id])[0]


TERMINAL = frozenset({"SUCCESS", "ERROR", "CANCELLED", "MAX_RECOVERY_ATTEMPTS_EXCEEDED"})


def await_parked(engine: Engine, workflow_id: str, gov_db: Path) -> None:
    """Block until both halves of the parked predicate hold, or fail loudly.

    The governance half is read only once `schema_committed` says there is a schema to
    read (ST9-R01); until then this is still waiting, not yet observing. Bounded by
    `PARK_TIMEOUT_SECONDS` either way, and the failure names which half never arrived.
    """
    deadline = time.monotonic() + PARK_TIMEOUT_SECONDS
    names: set[str] = set()
    cases: tuple[tuple[str, str, int], ...] = ()
    committed = False
    while time.monotonic() < deadline:
        names = step_names(engine, workflow_id)
        committed = schema_committed(gov_db)
        if committed:
            cases = governance(gov_db).cases
            submitted = cases == ((workflow_id, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
            if submitted and "DBOS.sleep" in names and "DBOS.recv" not in names:
                return
        time.sleep(0.05)
    pytest.fail(
        f"workflow {workflow_id!r} never parked within {PARK_TIMEOUT_SECONDS}s: "
        f"governance schema committed={committed} steps={sorted(names)} cases={cases}"
    )


def await_terminal(engine: Engine, workflow_id: str) -> str:
    deadline = time.monotonic() + SETTLE_TIMEOUT_SECONDS
    state = ""
    while time.monotonic() < deadline:
        state = str(status(engine, workflow_id).status)
        if state in TERMINAL:
            return state
        time.sleep(0.05)
    pytest.fail(f"workflow {workflow_id!r} never reached a terminal status: {state}")


def observed_status(engine: Engine, workflow_id: str) -> str | None:
    """This workflow's status, or `None` if DBOS has no record of it yet.

    Never raises: it is read on teardown paths where an exception may already be in
    flight, and "cleanup could not look" must not become the reported failure.
    """
    try:
        found = engine.DBOS.list_workflows(workflow_ids=[workflow_id])
    except BaseException:  # noqa: BLE001 - teardown: an unreadable status is not a verdict
        return None
    return str(found[0].status) if found else None


def release(engine: Engine, client: Any, workflow_id: str, handle: Any) -> None:
    """Free the parked receive so this process can exit. Bounded, and never raises.

    Called from `start_and_park`'s `finally`, so it runs after every assertion on the
    success path **and** on the readiness-failure and readiness-timeout paths (ST9-R02).
    On those, a failure is already in flight and a second one raised from here would
    replace the diagnosis with its own -- so this asserts nothing and reports nothing it
    can recover from. It is release, not verification.

    Delivering a message is the only release available: `DBOS.destroy()` does not
    interrupt the blocked non-daemon thread, and `_sys_db.recv`'s wait loop never checks
    for cancellation. A workflow that is still non-terminal after the bound is therefore
    the one thing worth saying out loud, and it is said as a warning rather than a
    failure, because the test that is already failing owns the report.
    """
    state = observed_status(engine, workflow_id)
    if state is None:
        return  # DBOS never recorded it: nothing is parked and nothing needs freeing
    if state not in TERMINAL:
        try:
            client.send(
                workflow_id,
                RELEASE_MESSAGE,
                topic=engine.APPROVAL_TOPIC,
                serialization_type=engine.PORTABLE,
            )
        except BaseException:  # noqa: BLE001 - teardown: the wait below reports the outcome
            pass
        deadline = time.monotonic() + RELEASE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            state = observed_status(engine, workflow_id)
            if state is None or state in TERMINAL:
                break
            time.sleep(0.05)
    if state is not None and state not in TERMINAL:
        warnings.warn(
            f"teardown could not release workflow {workflow_id!r} within "
            f"{RELEASE_TIMEOUT_SECONDS}s: status={state}",
            stacklevel=2,
        )
        return
    try:
        handle.get_result()
    except BaseException:  # noqa: BLE001,S110 - teardown: the refusal is the point
        pass


def deliver(
    engine: Engine,
    client: Any,
    workflow_id: str,
    message: Any,
    *,
    portable: bool = True,
) -> None:
    """Deliver a message the way an external approver would (§13): `DBOSClient.send`."""
    client.send(
        workflow_id,
        message,
        topic=engine.APPROVAL_TOPIC,
        serialization_type=engine.PORTABLE if portable else None,
    )


def source(module_name: str) -> str:
    return (SRC / f"{module_name}.py").read_text(encoding="utf-8")


def top_level_imports(module_name: str) -> set[str]:
    """Root module names imported by a production module, read from its source."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source(module_name))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def imported_names(module_name: str) -> set[str]:
    """Every name a module imports, dotted for `from x import y` as `x.y`."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source(module_name))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(f"{node.module or ''}.{alias.name}" for alias in node.names)
    return names


def name_ids(module_name: str) -> set[str]:
    """Every bare name a module mentions, read from the syntax tree."""
    return {
        node.id for node in ast.walk(ast.parse(source(module_name))) if isinstance(node, ast.Name)
    }


def code_without_prose(module_name: str) -> str:
    """The module's code with every docstring removed, re-rendered from the tree.

    Prose has to be excluded or every structural assertion below would be satisfied or
    broken by a docstring that merely *names* what the module does not do.
    """
    tree = ast.parse(source(module_name))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body = node.body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def called_names(module_name: str) -> list[str]:
    """Every callee spelling in a module, as written."""
    calls: list[str] = []
    for node in ast.walk(ast.parse(source(module_name))):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                calls.append(func.id)
            elif isinstance(func, ast.Attribute):
                calls.append(func.attr)
    return calls


# --- Section A: the workflow parks (requirement 7) --------------------------------


def test_a_the_workflow_opens_and_submits_the_case_then_parks_in_the_durable_receive(
    h: Harness, engine: Engine, parked: Parked
) -> None:
    """Requirement 7, first half: the workflow can stop and wait for a human approval.

    The two durable steps before the wait have run and been checkpointed, the case is
    `SCOPE_REVIEW_PENDING` at revision 2 -- created at 1, advanced exactly once -- and
    the receive's deadline is recorded with nothing consumed.
    """
    names = step_names(engine, parked.workflow_id)
    assert "_open_case" in names
    assert "_submit_for_review" in names
    assert "DBOS.sleep" in names, "the durable receive's deadline is not checkpointed"
    assert "DBOS.recv" not in names, "a receive result is already checkpointed"

    observed = governance(h.governance_db)
    assert observed.cases == ((WORKFLOW_ID, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
    assert observed.consumptions == ()
    assert observed.audit_events == ()


def test_a_dbos_reports_the_parked_workflow_as_pending_under_the_pinned_version(
    engine: Engine, parked: Parked
) -> None:
    """Requirement 8: DBOS holds the workflow's state while it waits.

    The recorded `name` and `app_version` are asserted because recovery resolves a
    workflow by exactly those two facts (`dbos/_recovery.py:57`): a workflow is recorded
    under the function name it was *started* with, and a process on a different
    `application_version` recovers nothing.
    """
    recorded = status(engine, parked.workflow_id)
    assert str(recorded.status) == "PENDING"
    assert recorded.name == "scope_approval_workflow"
    assert recorded.app_version == engine.APPLICATION_VERSION
    assert recorded.workflow_id == WORKFLOW_ID


def test_a_with_no_approval_delivered_the_case_never_advances(
    h: Harness, engine: Engine, parked: Parked
) -> None:
    """Requirement 7, second half: waiting is waiting. Nothing advances on its own.

    Asserted over the governance database rather than over elapsed time: the claim is
    that no transition happened, not that it did not happen quickly.
    """
    before = governance(h.governance_db)
    time.sleep(HOLD_SECONDS)
    after = governance(h.governance_db)

    assert after == before
    assert after.cases == ((WORKFLOW_ID, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
    assert after.consumptions == ()
    assert after.audit_events == ()
    assert str(status(engine, parked.workflow_id).status) == "PENDING"
    assert "DBOS.recv" not in step_names(engine, parked.workflow_id)


# --- Section B: one approval resumes it (requirements 7, 8) -----------------------


def test_b_an_approval_delivered_by_dbosclient_resumes_the_workflow_and_approves(
    h: Harness, engine: Engine, parked: Parked, client: Any
) -> None:
    """The GP-09 row, end to end, with `applied=True` evidenced rather than asserted.

    `ApplyOutcome.applied` is not part of the workflow's durable result -- §13 freezes
    that as the case's state -- so it is established the way an auditor would: there
    were **zero** consumption rows before the approval was delivered and **exactly one**
    after, filed under this approval's id for this workflow's edge. A replay writes
    nothing, so the row can only have been written by a call that committed the
    transition.

    Delivery is `DBOSClient.send` with `PORTABLE` serialization: the approval crosses
    as JSON text, which the workflow hands straight to `codec.decode_approval` (§7).
    """
    assert governance(h.governance_db).consumptions == ()

    deliver(engine, client, parked.workflow_id, approval_json(parked.subject_digest))

    assert parked.handle.get_result() == str(ScopeState.SCOPE_APPROVED)

    recorded = status(engine, parked.workflow_id)
    assert str(recorded.status) == "SUCCESS"

    names = step_names(engine, parked.workflow_id)
    assert "DBOS.recv" in names, "the receive was never consumed"
    assert "_apply_approval" in names

    observed = governance(h.governance_db)
    assert observed.cases == ((WORKFLOW_ID, str(ScopeState.SCOPE_APPROVED), 3),)
    assert observed.consumptions == (
        (
            APPROVAL_ID,
            WORKFLOW_ID,
            str(ScopeState.SCOPE_REVIEW_PENDING),
            str(ScopeState.SCOPE_APPROVED),
        ),
    )
    assert observed.audit_events == ("scope.approved",)


def test_b_the_approval_is_accepted_on_its_label_alone_and_nothing_authenticates_it(
    h: Harness, engine: Engine, parked: Parked, client: Any
) -> None:
    """§11, preserved rather than quietly improved.

    The `approver_id` carried here is an arbitrary opaque string that nothing verified,
    and the approval is applied anyway. That is the documented limit of this spike:

    > **HUMAN authority label enforced; human identity/authenticity not proven until
    > the signing/authentication stage.**

    What *is* enforced is the label: `approver_kind` is `Literal[ActorKind.HUMAN]`, so
    a `SYSTEM` or `LLM` statement fails `codec.decode_approval` before any kernel call
    exists to reach (GP-05 asserts that half).
    """
    message = approval_json(parked.subject_digest, approver_id="anyone-at-all")
    deliver(engine, client, parked.workflow_id, message)

    assert parked.handle.get_result() == str(ScopeState.SCOPE_APPROVED)
    assert governance(h.governance_db).cases == (
        (WORKFLOW_ID, str(ScopeState.SCOPE_APPROVED), 3),
    )


# --- Section C: refusals are the kernel's, propagated not reimplemented -----------


def test_c_a_stale_approval_is_refused_by_the_kernel_and_surfaces_as_staleapproval(
    h: Harness, engine: Engine, parked: Parked, client: Any
) -> None:
    """The workflow does not check staleness; it does not need to, and must not.

    The statement is well-formed and correctly bound to this workflow and edge -- only
    its subject digest names different content. Nothing in `workflow.py` compares a
    digest, so the refusal can only have come from `kernel.apply_scope_approval`'s
    `gp_approval_subject_digest` guard, and it arrives at the caller as that guard's
    own error class rather than as an orchestration failure.

    The approval is refused, not burnt: no consumption row is written, so it still
    authorizes the digest it was actually issued for.
    """
    elsewhere = compute_digest(spec(title="A different scope entirely"), SCOPE_MEDIA_TYPE)
    assert elsewhere != parked.subject_digest

    deliver(engine, client, parked.workflow_id, approval_json(elsewhere))

    with pytest.raises(StaleApproval) as excinfo:
        parked.handle.get_result()
    assert isinstance(excinfo.value, GovernedPlannerError)

    assert str(status(engine, parked.workflow_id).status) == "ERROR"
    observed = governance(h.governance_db)
    assert observed.cases == ((WORKFLOW_ID, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
    assert observed.consumptions == ()
    assert observed.audit_events == ()


def test_c_an_approval_bound_to_another_workflow_is_refused_by_the_kernel(
    h: Harness, engine: Engine, parked: Parked, client: Any
) -> None:
    """`GK-INV-2`'s workflow binding, decided in the kernel and only there.

    DBOS delivered this message to the right workflow -- delivery is addressing, not
    authority. The statement says it authorizes a different case, and the kernel's
    `gp_approval_workflow_binding` guard is what notices.
    """
    message = approval_json(parked.subject_digest, workflow_id=OTHER_WORKFLOW_ID)
    deliver(engine, client, parked.workflow_id, message)

    with pytest.raises(ApprovalBindingError):
        parked.handle.get_result()

    observed = governance(h.governance_db)
    assert observed.cases == ((WORKFLOW_ID, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
    assert observed.consumptions == ()
    assert observed.audit_events == ()


def test_c_a_payload_that_is_not_approval_json_never_reaches_the_kernel(
    h: Harness, engine: Engine, parked: Parked, client: Any
) -> None:
    """The transport boundary is the gate, and it is `codec`'s (§7).

    A raw `dict` is delivered with DBOS's default serialization -- the pickle path the
    design refuses to use for approvals. It is refused by `decode_approval`'s
    model-enforced `gp_transport_decode` guard, with a `ValidationError` rather than a
    governance error, because no governance decision was ever reached: the kernel's
    signature takes an `ApprovalStatement` and never a `dict`.
    """
    from pydantic import ValidationError

    deliver(
        engine,
        client,
        parked.workflow_id,
        wire(parked.subject_digest),
        portable=False,
    )

    with pytest.raises(ValidationError):
        parked.handle.get_result()

    observed = governance(h.governance_db)
    assert observed.cases == ((WORKFLOW_ID, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
    assert observed.consumptions == ()
    assert observed.audit_events == ()


# --- Section D: the boundary, asserted structurally -------------------------------


def test_d_app_and_workflow_are_the_only_modules_that_import_the_engine() -> None:
    """§4's load-bearing rule, over the whole package rather than over call sites."""
    importers = {
        path.stem for path in sorted(SRC.glob("*.py")) if "dbos" in top_level_imports(path.stem)
    }
    assert importers == {"app", "workflow"}
    assert {path.stem for path in SRC.glob("*.py")} == set(FROZEN_MODULES)


def test_d_the_workflow_never_reaches_policy_and_holds_no_transition_table() -> None:
    """`GK-INV-6`: orchestration may not hold a second opinion about legality.

    Read from the syntax tree, so the module docstring naming `SPK1-1` or
    `LEGAL_TRANSITIONS` in prose is not mistaken for using them.
    """
    roots = top_level_imports("workflow")
    assert "policy" not in roots
    assert "gplanner.policy" not in imported_names("workflow")

    names = name_ids("workflow")
    assert "LEGAL_TRANSITIONS" not in names
    assert "refuse_unless_allowed" not in names
    assert "ScopeState" not in names

    calls = called_names("workflow")
    assert "refuse_unless_allowed" not in calls
    assert "require" not in calls, "a guard here would be a governance decision here"
    assert "# guard:" not in source("workflow"), "no frozen guard ID is owned by this layer"


def test_d_the_workflow_reaches_governance_only_through_the_kernel_and_codec() -> None:
    """Every governance-relevant call in the module is a call into a layer that owns it."""
    imported = imported_names("workflow")
    assert imported >= {
        "gplanner.kernel.open_case",
        "gplanner.kernel.submit_for_review",
        "gplanner.kernel.apply_scope_approval",
    }
    assert not {name for name in imported if name.startswith("gplanner.store.")}

    calls = called_names("workflow")
    assert calls.count("open_case") == 1
    assert calls.count("submit_for_review") == 1
    assert calls.count("apply_scope_approval") == 1
    assert calls.count("decode_approval") == 1
    assert calls.count("decode_scope_from_preimage") == 1


def test_d_the_workflow_reimplements_no_replay_or_single_use_semantics() -> None:
    """ST8-R02: replay is `governance.sqlite`'s guarantee, and stays there.

    Nothing here reads `approval_consumptions`, asks the store whether an approval was
    used, or branches on `ApplyOutcome.applied`. The workflow also adds no state read
    to make `_submit_for_review` idempotent: `SPK1-1` is a transition, §3's graph has no
    self-loop for it, and no replay semantics for it are authorized.
    """
    code = code_without_prose("workflow")
    for absent in (
        "find_consumption",
        "load_case",
        "approval_consumptions",
        "applied",
        "ApprovalReplay",
        "SCOPE_REVIEW_PENDING",
    ):
        assert absent not in code, absent


def test_d_the_workflow_uses_the_frozen_durable_receive_mechanism() -> None:
    """The wait is `DBOS.recv` on the frozen topic with the frozen durable deadline."""
    engine = _engine()
    assert engine.APPROVAL_TOPIC == "scope_approval"
    assert engine.APPROVAL_TIMEOUT_SECONDS == 3600.0

    calls = called_names("workflow")
    assert calls.count("recv") == 1

    recv = [
        node
        for node in ast.walk(ast.parse(source("workflow")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "recv"
    ]
    keywords = {kw.arg: ast.unparse(kw.value) for kw in recv[0].keywords}
    assert keywords == {"topic": "APPROVAL_TOPIC", "timeout_seconds": "APPROVAL_TIMEOUT_SECONDS"}


def test_d_the_governance_layer_is_still_provable_with_the_engine_absent() -> None:
    """§4/§13.2's structural gate, run in a subprocess so this process's imports cannot
    make it pass by accident."""
    import subprocess
    import sys

    program = (
        "import importlib, sys\n"
        "for m in ('canonical','profile','digest','artifacts','states','policy',"
        "'approvals','codec','store','kernel'):\n"
        "    importlib.import_module(f'gplanner.{m}')\n"
        "assert 'dbos' not in sys.modules, 'governance layer imported dbos'\n"
        "assert not {'anthropic','openai'} & sys.modules.keys(), 'LLM SDK imported'\n"
        "print('structural gate OK')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    assert "structural gate OK" in result.stdout


def test_d_neither_new_module_imports_json_or_an_llm_sdk() -> None:
    """§7 and §2, over the two modules ST-9 adds."""
    for module_name in ("app", "workflow"):
        roots = top_level_imports(module_name)
        assert "json" not in roots, module_name
        assert not {"anthropic", "openai"} & roots, module_name
        assert "model_validate" not in {
            node.attr
            for node in ast.walk(ast.parse(source(module_name)))
            if isinstance(node, ast.Attribute)
        }, module_name


def test_d_both_new_modules_cite_their_design_basis() -> None:
    for module_name in ("app", "workflow"):
        docstring = ast.get_docstring(ast.parse(source(module_name)))
        assert docstring is not None, module_name
        assert "Design basis: design/GP-SPK-001-governance-kernel.md §" in docstring, module_name


def test_d_this_module_defers_every_engine_import() -> None:
    """The workaround recorded in this file's docstring, asserted so it cannot decay.

    A module-level `import dbos` here fails three frozen tests that assert the engine is
    absent from `sys.modules` -- measured, not predicted. Every engine import therefore
    lives inside a function body.
    """
    tree = ast.parse(THIS_FILE.read_text(encoding="utf-8"))
    deferred = {"dbos", "gplanner.app", "gplanner.workflow"}
    for node in tree.body:
        if isinstance(node, ast.Import):
            assert not {alias.name for alias in node.names} & deferred
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "") not in deferred


# --- Section E: the engine's configuration surface --------------------------------


def test_e_the_config_names_dbos_own_database_and_creates_no_application_database(
    h: Harness, engine: Engine
) -> None:
    """§12: two databases, never joined. DBOS is given nowhere to put governance data."""
    config = engine.make_config(h.system_db)
    assert config["system_database_url"] == f"sqlite:///{h.system_db}"
    assert "application_database_url" not in config
    assert "database_url" not in config
    assert config["name"] == engine.APPLICATION_NAME


def test_e_the_recovery_gate_is_pinned_and_the_admin_and_telemetry_surfaces_are_off(
    h: Harness, engine: Engine
) -> None:
    """`application_version` gates recovery (`dbos/_recovery.py:57`), so it is a constant."""
    config = engine.make_config(h.system_db)
    assert config["application_version"] == "gp-spk-001"
    assert engine.APPLICATION_VERSION == "gp-spk-001"
    assert config["run_admin_server"] is False
    assert config["enable_otlp"] is False

    overridden = engine.make_config(h.system_db, "other-version")
    assert overridden["application_version"] == "other-version"


def test_e_the_approval_timeout_is_not_a_governance_refusal(engine: Engine) -> None:
    """A timeout decides nothing, so it is not in the frozen governance hierarchy.

    `errors.py` ships whole and later stages import from it rather than grow it. ST-9
    grows it by nothing: `ApprovalTimeout` is an orchestration failure and lives in
    `workflow.py`, outside `GovernedPlannerError`, so `except GovernedPlannerError`
    cannot mistake "nobody approved anything" for "the authority model refused".
    """
    assert issubclass(engine.ApprovalTimeout, Exception)
    assert not issubclass(engine.ApprovalTimeout, GovernedPlannerError)

    raised = engine.ApprovalTimeout(WORKFLOW_ID)
    assert WORKFLOW_ID in str(raised)
    assert raised.workflow_id == WORKFLOW_ID

    declared = {
        name
        for name, value in vars(errors).items()
        if isinstance(value, type)
        and issubclass(value, BaseException)
        and value is not GovernedPlannerError
    }
    assert declared == set(FROZEN_ERROR_CLASSES), "errors.py is frozen and ST-9 grew it"


# --- Section F: the three ST-9 review findings, closed and kept closed -------------


def half_built_governance_db(root: Path) -> Path:
    """A governance database at the exact point Codex's startup schedule exposed.

    `store.open`'s first two actions -- `sqlite3.connect` and §12's pragmas -- and not
    its third, the DDL transaction. The file is on disk, no application table is, and
    `PRAGMA user_version` still reads unstamped. This is a real prefix of `store.open`,
    not an invented state: the same statements in the same order, stopped one step
    short.
    """
    path = root / "governance.sqlite"
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        for name, value in store.PRAGMAS:
            connection.execute(f"PRAGMA {name} = {value}")
    finally:
        connection.close()
    return path


def commit_governance_schema(path: Path, cases: tuple[tuple[str, str, int], ...]) -> None:
    """Finish the schedule: `store`'s own DDL and stamp, in one transaction, plus rows."""
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("BEGIN IMMEDIATE")
        for statement in store.SCHEMA_SQL:
            connection.execute(statement)
        connection.execute(f"PRAGMA user_version = {store.STORAGE_VERSION}")
        digest = compute_digest(spec(), SCOPE_MEDIA_TYPE)
        connection.execute(
            "INSERT INTO artifacts (digest, media_type, canonical_preimage, byte_len) "
            "VALUES (?, ?, ?, ?)",
            (digest, SCOPE_MEDIA_TYPE, b"", 0),
        )
        for workflow_id, state, revision in cases:
            connection.execute(
                "INSERT INTO cases (workflow_id, state, subject_digest, revision) "
                "VALUES (?, ?, ?, ?)",
                (workflow_id, state, digest, revision),
            )
        connection.execute("COMMIT")
    finally:
        connection.close()


class StubDBOS:
    """Just enough of `DBOS` for `await_parked`: the parked step record, always."""

    @staticmethod
    def list_workflow_steps(workflow_id: str) -> list[dict[str, str]]:
        return [{"function_name": "DBOS.sleep"}]


def test_f_r01_a_created_governance_file_is_not_a_committed_schema(tmp_path: Path) -> None:
    """ST9-R01: the window the old readiness predicate could not see.

    File existence was the predicate, and it is `True` here -- while the governance
    observation it authorized fails with `no such table: cases`. Both halves are
    asserted, so this records the defect rather than only the fix.
    """
    path = half_built_governance_db(tmp_path)

    assert path.exists(), "the old readiness predicate held here"
    with pytest.raises(sqlite3.OperationalError, match="no such table: cases"):
        governance(path)

    assert schema_committed(path) is False


def test_f_r01_readiness_waits_through_a_delayed_schema_then_observes_the_park(
    engine: Engine, tmp_path: Path
) -> None:
    """ST9-R01: a valid delayed initialization is waited for, not failed on.

    The schema is committed from another thread after the observer has already begun
    polling -- Codex's schedule, with the window forced wide rather than raced for. The
    observer must survive the window and then see the parked predicate.
    """
    import threading

    path = half_built_governance_db(tmp_path)
    parked_cases = ((WORKFLOW_ID, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
    delayed = threading.Timer(1.0, commit_governance_schema, (path, parked_cases))
    delayed.start()
    try:
        await_parked(engine._replace(DBOS=StubDBOS()), WORKFLOW_ID, path)
    finally:
        delayed.cancel()
        delayed.join()

    assert schema_committed(path) is True
    assert governance(path).cases == parked_cases


def test_f_r01_a_broken_governance_database_is_reported_not_waited_out(
    tmp_path: Path,
) -> None:
    """ST9-R01: the fix waits for a slow store, and refuses to wait for a broken one.

    Two failures that are not "not ready yet": a stamp from a build this one cannot
    read, and a file that is not a database at all. Neither is absorbed, so neither can
    be reported later as "the workflow never parked" -- which would blame the workflow
    for the store.
    """
    stamped = half_built_governance_db(tmp_path)
    connection = sqlite3.connect(stamped, isolation_level=None)
    try:
        connection.execute(f"PRAGMA user_version = {store.STORAGE_VERSION + 41}")
    finally:
        connection.close()
    with pytest.raises(AssertionError, match="storage version"):
        schema_committed(stamped)

    not_a_database = tmp_path / "rubbish" / "governance.sqlite"
    not_a_database.parent.mkdir()
    not_a_database.write_bytes(b"this is not an SQLite database, it is a text file")
    with pytest.raises(sqlite3.DatabaseError):
        schema_committed(not_a_database)


def test_f_r02_a_readiness_failure_releases_the_workflow_it_started(
    h: Harness, engine: Engine, runtime: None, client: Any
) -> None:
    """ST9-R02: readiness failing before the park still reaches cleanup.

    The harshest ordering: readiness fails while the workflow is still on its way to
    the receive, so the release message is delivered before there is anything blocked
    to receive it. DBOS holds the notification durably, the receive consumes it on
    arrival, and the workflow terminates -- inside the cleanup bound, rather than at the
    hour-long durable deadline.
    """

    def fail_immediately(engine_: Engine, workflow_id: str, gov_db: Path) -> None:
        raise RuntimeError("forced readiness failure")

    lifecycle = start_and_park(h, engine, client, await_ready=fail_immediately)
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="forced readiness failure"):
        next(lifecycle)
    elapsed = time.monotonic() - started

    assert observed_status(engine, WORKFLOW_ID) in TERMINAL
    assert elapsed < RELEASE_TIMEOUT_SECONDS
    assert governance(h.governance_db).consumptions == ()


def test_f_r02_a_readiness_timeout_releases_the_parked_workflow(
    h: Harness, engine: Engine, runtime: None, client: Any
) -> None:
    """ST9-R02: `await_parked`'s own failure mode is covered by cleanup too.

    A readiness timeout raises `Failed` from `pytest.fail`, which is a `BaseException`
    and not an `Exception`; a cleanup arranged only for the latter would miss it. The
    workflow is genuinely parked first, so this is the case where nothing but a
    delivered message can free the thread.
    """

    def park_then_time_out(engine_: Engine, workflow_id: str, gov_db: Path) -> None:
        await_parked(engine_, workflow_id, gov_db)
        pytest.fail("forced readiness timeout")

    lifecycle = start_and_park(h, engine, client, await_ready=park_then_time_out)
    with pytest.raises(pytest.fail.Exception, match="forced readiness timeout"):
        next(lifecycle)

    assert observed_status(engine, WORKFLOW_ID) in TERMINAL
    observed = governance(h.governance_db)
    assert observed.cases == ((WORKFLOW_ID, str(ScopeState.SCOPE_REVIEW_PENDING), 2),)
    assert observed.consumptions == ()
    assert "scope.approved" not in observed.audit_events


def test_f_r02_the_success_path_still_releases_the_workflow(
    h: Harness, engine: Engine, runtime: None, client: Any
) -> None:
    """ST9-R02: arming cleanup earlier did not stop it running on the ordinary path."""
    lifecycle = start_and_park(h, engine, client)
    entry = next(lifecycle)
    assert entry.workflow_id == WORKFLOW_ID
    assert str(status(engine, WORKFLOW_ID).status) == "PENDING"

    lifecycle.close()

    assert observed_status(engine, WORKFLOW_ID) in TERMINAL


def test_f_r03_the_approval_timeout_survives_reconstruction(engine: Engine) -> None:
    """ST9-R03: what DBOS rebuilds must be what was raised.

    Unpickling an exception calls `cls(*args)`, so `args` holding the formatted
    diagnostic was fed back in as the workflow id and the message nested itself. Both
    reconstruction idioms are checked, because both are the same defect.
    """
    import pickle

    raised = engine.ApprovalTimeout(WORKFLOW_ID)
    assert raised.args == (WORKFLOW_ID,)
    assert WORKFLOW_ID in str(raised)

    for rebuilt in (pickle.loads(pickle.dumps(raised)), type(raised)(*raised.args)):
        assert type(rebuilt) is engine.ApprovalTimeout
        assert rebuilt.workflow_id == WORKFLOW_ID
        assert str(rebuilt) == str(raised)
        assert str(raised) not in rebuilt.workflow_id


def test_f_r03_the_approval_timeout_survives_dbos_durable_retrieval(
    h: Harness, engine: Engine, runtime: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ST9-R03: the real boundary — a timed-out workflow, retrieved publicly.

    The durable deadline is shortened **for this test only**, because a timeout is what
    is being retrieved and §13's hour is what makes one unobservable. Nothing is
    asserted about elapsed time; the assertion is on the exception DBOS hands back
    through `DBOS.retrieve_workflow`, which reads it from `dbos_sys.sqlite` and
    deserializes it rather than returning the in-memory object.

    The expected diagnostic is computed by constructing the exception directly at the
    same moment, so this compares durable against direct rather than against a literal
    that the shortened deadline would make wrong.
    """
    import gplanner.workflow as workflow_module

    monkeypatch.setattr(workflow_module, "APPROVAL_TIMEOUT_SECONDS", 3.0)
    timed_out = "gp-spk-001-workflow-timeout"

    with engine.SetWorkflowID(timed_out):
        engine.DBOS.start_workflow(
            engine.scope_approval_workflow,
            preimage_text(spec()),
            str(h.governance_db),
        )

    retrieved = engine.DBOS.retrieve_workflow(timed_out)
    with pytest.raises(engine.ApprovalTimeout) as caught:
        retrieved.get_result()

    durable = caught.value
    assert durable.workflow_id == timed_out
    assert str(durable) == str(engine.ApprovalTimeout(timed_out))
    assert str(durable).startswith(f"no approval was delivered to workflow {timed_out!r}")
    assert not isinstance(durable, GovernedPlannerError)
    assert governance(h.governance_db).cases == (
        (timed_out, str(ScopeState.SCOPE_REVIEW_PENDING), 2),
    )
