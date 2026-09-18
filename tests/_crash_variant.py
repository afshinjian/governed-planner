"""GP-10b's crash-capable workflow variant — the engine-bound half of the worker.

Design basis: design/GP-SPK-001-governance-kernel.md §10, §12, §13.1 (requirement 10).

Test-only, and the only place in the repository with a crash barrier. No production
module contains a crash hook, a test flag, or a barrier, and
`test_gp10_restart_recovery.py::test_d_production_carries_no_crash_hook_or_test_flag`
asserts that on the source rather than trusting it.

Why this is a separate module from `_restart_worker.py`
-------------------------------------------------------
Two independent reasons, both load-bearing.

**Names.** DBOS records a workflow and a step under `func.__qualname__`
(`dbos/_core.py:2103`, `dbos/_core.py:2764`), and recovery resolves a workflow by the
name it was **started** with (`dbos/_recovery.py:57`). Defining these functions inside
a helper function would record them as `_registered.<locals>._crashable_...` — a name
that encodes the harness's own call structure and would change if the helper were ever
renamed. At module scope the recorded name *is* the function name, so the identity
assertion compares against something real instead of against a spelling of the
scaffolding. The alternative — passing `name=` to the decorators — would let the
recorded name and the function disagree, which is precisely what that assertion exists
to detect.

**Collection.** `_restart_worker.py` is imported by the test module at collection time,
and three frozen tests assert `"dbos" not in sys.modules` in-process. This module
imports the engine at module scope, so it must never be imported at collection — and
it is not: only `_restart_worker._registered()` imports it, inside a worker process.

The variant is the production workflow plus one barrier
--------------------------------------------------------
`_crashable_scope_approval_workflow` is `workflow.scope_approval_workflow` line for
line, with `_apply_with_optional_barrier` substituted for `_apply_approval`. The two
steps before the receive are the **production step objects themselves**, imported
rather than copied, so the checkpoints this variant writes and replays are the ones
production writes. A drift in either of them breaks this proof instead of being
quietly absorbed by a local copy.
"""

from __future__ import annotations

import os
from pathlib import Path

from dbos import DBOS

from _restart_worker import (
    CRASH_FLAG,
    MARKER_APPLIED,
    hold_until_killed,
    publish_ready,
    record_barrier_entry,
)
from gplanner import codec
from gplanner.kernel import apply_scope_approval
from gplanner.store import open as open_store
from gplanner.workflow import (
    APPROVAL_TIMEOUT_SECONDS,
    APPROVAL_TOPIC,
    ApprovalTimeout,
    _open_case,
    _submit_for_review,
)

#: Where the barrier publishes and records. A module global rather than a step
#: parameter: `_apply_with_optional_barrier` must take exactly the arguments the
#: production apply step takes, because a step whose signature differed from
#: production's would no longer be the thing being proven. The barrier is scaffolding
#: hanging off the side of that step, so it is wired in beside it.
_READY_DIR: Path | None = None


def arm(ready_dir: Path) -> None:
    """Point the barrier at this run's ready directory. Called once, before `launch()`."""
    global _READY_DIR
    _READY_DIR = ready_dir


def _require_ready_dir() -> Path:
    if _READY_DIR is None:
        raise RuntimeError("the crash barrier ran before `arm()` set the ready directory")
    return _READY_DIR


@DBOS.step()
def _apply_with_optional_barrier(gov_db: str, workflow_id: str, message: str) -> str:
    """The real kernel call, and then — only under the flag — a barrier it never leaves.

    The two statements before the flag check are `workflow._apply_approval`'s two
    statements, calling the **unmodified** production kernel through the **unmodified**
    production transport decode. Nothing about the governance decision differs from
    production. The only difference is what this process does *after* that decision has
    already committed.

    With the flag set, the step records one barrier entry, publishes readiness and
    parks — so it never returns, and DBOS never checkpoints it. That is exactly §12's
    cross-database window: `governance.sqlite` is durably `SCOPE_APPROVED` while DBOS
    still has no record that this step ran.

    With the flag absent — every recovery process — the replayed call reaches the
    kernel's §10 step-4 match branch, is told `applied=False`, skips the barrier and
    returns, letting DBOS checkpoint it. The convergence is the kernel's: this step
    neither detects the replay nor decides anything about it, and it does not branch on
    `ApplyOutcome.applied`.
    """
    statement = codec.decode_approval(message)
    with open_store(gov_db) as governance:
        state = str(apply_scope_approval(governance, workflow_id, statement).state)
    if os.environ.get(CRASH_FLAG) == "1":
        ready_dir = _require_ready_dir()
        record_barrier_entry(ready_dir, workflow_id)
        publish_ready(ready_dir, MARKER_APPLIED)
        hold_until_killed()  # the parent SIGKILLs here; the step never returns
    return state


@DBOS.workflow()
def _crashable_scope_approval_workflow(spec_json: str, gov_db: str) -> str:
    """GP-10b's workflow, for its entire lifetime — started as this, recovered as this."""
    workflow_id = DBOS.workflow_id
    if workflow_id is None:
        raise RuntimeError("the crash variant requires a DBOS workflow context")
    _open_case(gov_db, workflow_id, spec_json)
    _submit_for_review(gov_db, workflow_id)
    message = DBOS.recv(topic=APPROVAL_TOPIC, timeout_seconds=APPROVAL_TIMEOUT_SECONDS)
    if message is None:
        raise ApprovalTimeout(workflow_id)
    return _apply_with_optional_barrier(gov_db, workflow_id, message)
