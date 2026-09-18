"""The DBOS workflow boundary — orchestration, never decision.

Design basis: design/GP-SPK-001-governance-kernel.md §4, §7, §9 (`GK-INV-6`), §12.

`GK-INV-6` in one module: **the kernel decides and never orchestrates; the workflow
orchestrates and never decides.** Everything here is about *when* a governance call
happens and how its inputs cross a process boundary. Nothing here is about *whether*
the call is allowed.

What that rules out, concretely. This module holds no copy of §3's transition table,
never imports `policy`, never compares a case's state against an approval's, never
inspects `approver_kind`, and never decides that an approval is fresh, bound, or
unused. Those are `policy.py`'s and `kernel.py`'s single answers, reached by calling
them. A second opinion here would be a second authority model -- the defect the module
boundaries in §4 exist to prevent -- and it would be one that DBOS could reach without
governance code ever running.

What DBOS does supply, and only this: durability of the orchestration, and delivery of
a message while no process is alive to hold it. It carries the approval's bytes; it
does not vouch for them, and it authorizes nothing.

Three steps, one durable wait
-----------------------------
| Step | Calls | Decides |
|---|---|---|
| `_open_case` | `kernel.open_case` | nothing |
| `_submit_for_review` | `kernel.submit_for_review` | nothing |
| `_apply_approval` | `codec.decode_approval` then `kernel.apply_scope_approval` | nothing |

Each step opens the governance store itself and closes it on the way out, so a store
handle never spans a durable boundary and no step inherits a transaction from another
(the kernel refuses a caller-owned transaction outright -- ST8-R01).

The transport-decoding adapter, and the only one (§7)
-----------------------------------------------------
The approval crosses the boundary as JSON **text**, sent with
`WorkflowSerializationFormat.PORTABLE` so DBOS stores it as JSON in its `notifications`
table rather than as base64 pickle. An authority-bearing message must not travel
through `pickle`, and a JSON-stored approval stays readable to an auditor who is not
running this code.

`DBOS.recv` is typed `Any`, and what comes back is whatever a sender put in. It is
handed straight to `codec.decode_approval`, the package's frozen `gp_transport_decode`
site, which is the **first** thing that happens to it: a payload that is not valid
approval JSON is refused there, by the model's own constraints, before any governance
call exists to be reached. The kernel's signature takes an `ApprovalStatement` and
never a `dict`, so an unvalidated payload cannot reach governance code even by mistake.

`spec_json` is the artifact's **canonical preimage document** (§6), not a bare
`ScopeSpec` rendering, because `codec` exposes exactly one JSON → `ScopeSpec` path --
`decode_scope_from_preimage` -- and that path reads the envelope. This is a
consequence of §7 rather than a choice made here: a second scope-ingestion function
would be a second decode path, which is what §7 forbids package-wide.

`SYSTEM` is a claim, not a decision
-----------------------------------
`_submit_for_review` names `ActorKind.SYSTEM` because a caller of the kernel has to say
what it claims to be. Whether `SYSTEM` may take `SPK1-1` is decided by
`policy.refuse_unless_allowed`, which this module does not call and does not duplicate.
The label is exactly as unproven as §11 says every label in this spike is.

Authority is a label on the approval side too (§11)
---------------------------------------------------
Nothing in this module authenticates anything, and DBOS vouches for nothing it
carries. Anyone able to call `DBOSClient.send` against the system database can deliver
a statement labelled `HUMAN` carrying an arbitrary `approver_id`, and no part of this
spike detects it. What *is* enforced is the label: `approvals.ApprovalStatement` pins
`approver_kind` to `Literal[ActorKind.HUMAN]`, so a statement labelled `SYSTEM` or
`LLM` fails validation at the decode above before any kernel call exists to reach.

> **HUMAN authority label enforced; human identity/authenticity not proven until the
> signing/authentication stage.** (§11, quoted verbatim.)

The timeout is a durable deadline
---------------------------------
`DBOS.recv`'s timeout is committed at first execution (`dbos/_sys_db.py:3305`), so it
keeps running while no process is alive. A short timeout would silently convert
"resumed correctly" after a crash into "timed out". `APPROVAL_TIMEOUT_SECONDS` is
therefore an hour, fixed by the plan of record (revision 5 §13), and tests assert on
returned values and final state, never on elapsed time.

What this module does **not** make idempotent (ST8-R02)
-------------------------------------------------------
DBOS steps are at-least-once. `_apply_approval` is safe under re-delivery because the
kernel's §10 replay branch recognizes a transition that same approval already
committed and returns `applied=False` -- a guarantee that lives in `governance.sqlite`,
not in DBOS.

`_submit_for_review` has no such guarantee and is **not** given one here. `SPK1-1` is a
transition, §3's frozen graph contains no `SCOPE_REVIEW_PENDING → SCOPE_REVIEW_PENDING`
edge, and a re-run is therefore refused as an illegal self-loop -- which is the correct
behaviour, and the owner's recorded disposition on ST8-R02: no `submit_for_review`
replay or idempotency semantics are authorized. Adding a state read here to skip the
call would be this layer deciding that a transition is unnecessary, which is precisely
the decision `GK-INV-6` says it may not make. The consequence is stated rather than
engineered away: a crash landing strictly between the governance commit of `SPK1-1` and
DBOS's checkpoint of this step makes recovery re-run it and raise `IllegalTransition`.
A caller that needs to know whether a submit already happened reads the case state; it
does not ask the kernel to absorb a repeat.
"""

from __future__ import annotations

from typing import Final

from dbos import DBOS

from gplanner import codec, store
from gplanner.kernel import apply_scope_approval, open_case, submit_for_review
from gplanner.states import ActorKind

#: The DBOS topic the approval is delivered on. One topic: a message on any other is
#: not an approval and this workflow never looks for one.
APPROVAL_TOPIC: Final[str] = "scope_approval"

#: A **durable deadline**, not a test timeout. See the module docstring: it is
#: committed at first execution and keeps running across a crash, so it is long.
APPROVAL_TIMEOUT_SECONDS: Final[float] = 3600.0


class ApprovalTimeout(Exception):
    """No approval arrived before the durable deadline expired.

    Deliberately **not** in `errors.py`. That hierarchy is the frozen set of
    *governance* refusals -- each class names a decision the authority model made --
    and it explicitly excludes vendor and transport failures. A timeout is neither: no
    approval was evaluated, nothing was refused, and no invariant was tested. A caller
    writing `except GovernedPlannerError` is asking about governance outcomes and must
    not catch this, so it does not subclass that root.

    This exception crosses a durable boundary, so what it carries has to survive being
    rebuilt (ST9-R03). DBOS records a workflow failure with `pickle`, and unpickling an
    exception calls `cls(*args)`: an `args` holding the *formatted diagnostic* is
    therefore fed back in as though it were the workflow id, and the retrieved
    exception's message nests the whole previous message where the id belongs. So
    `args` holds the **workflow id** -- the constructor's own argument, which is what
    `args` is for -- and the diagnostic is rendered by `__str__` from that id and the
    two module constants above. Reconstruction is then exact by construction rather
    than by a second copy of the message kept in step with the first, and the same
    holds for every other `type(exc)(*exc.args)` idiom, not only for `pickle`.
    """

    def __init__(self, workflow_id: str) -> None:
        super().__init__(workflow_id)
        self.workflow_id = workflow_id

    def __str__(self) -> str:
        """The diagnostic, derived from the identity rather than stored beside it."""
        return (
            f"no approval was delivered to workflow {self.workflow_id!r} on topic "
            f"{APPROVAL_TOPIC!r} within {APPROVAL_TIMEOUT_SECONDS}s"
        )


def _require_workflow_context() -> str:
    """The running workflow's id, or a loud failure.

    `DBOS.workflow_id` is `None` outside a workflow context. Inside `@DBOS.workflow()`
    it never is, so this is a narrowing of the engine's own optional type rather than a
    governance check -- hence `RuntimeError`, which is not a `GovernedPlannerError` and
    says what it is: the engine context this function requires was absent.
    """
    workflow_id = DBOS.workflow_id
    if workflow_id is None:
        raise RuntimeError(
            "scope_approval_workflow requires a DBOS workflow context; "
            "DBOS.workflow_id is None, so this is not running as a workflow"
        )
    return workflow_id


@DBOS.step()
def _open_case(gov_db: str, workflow_id: str, spec_json: str) -> None:
    """Durable step: decode the preimage document and open the case (`SCOPE_DRAFTING`).

    Re-running this step is safe because `kernel.open_case` is idempotent for identical
    content -- it is not a transition and mutates no state -- and not because anything
    here detects a repeat.
    """
    spec = codec.decode_scope_from_preimage(spec_json.encode("utf-8"))
    with store.open(gov_db) as governance:
        open_case(governance, workflow_id, spec)


@DBOS.step()
def _submit_for_review(gov_db: str, workflow_id: str) -> None:
    """Durable step: take `SPK1-1` by asking the kernel to, claiming `SYSTEM`.

    Not idempotent, and not made so here -- see the module docstring's ST8-R02 section.
    """
    with store.open(gov_db) as governance:
        submit_for_review(governance, workflow_id, ActorKind.SYSTEM)


@DBOS.step()
def _apply_approval(gov_db: str, workflow_id: str, message: str) -> str:
    """Durable step: decode the transport payload, then let the kernel decide.

    Two calls, in this order, and no third. The decode is the frozen
    `gp_transport_decode` site; the kernel call is §10's entire algorithm. Whether the
    approval is legal, bound, fresh and unused is decided there -- this step neither
    pre-screens nor post-checks it, and it does not branch on `ApplyOutcome.applied`:
    both `True` (this call committed it) and `False` (a replay of the transition this
    same approval already committed) leave the case in the state returned here, which
    is the only fact orchestration needs.

    The returned value is `ApplyOutcome.state` rendered as the plain state token, so
    the workflow's durable result is a `str` in the same spelling the governance
    database, the audit log and an approval statement all use.
    """
    statement = codec.decode_approval(message)
    with store.open(gov_db) as governance:
        return str(apply_scope_approval(governance, workflow_id, statement).state)


@DBOS.workflow()
def scope_approval_workflow(spec_json: str, gov_db: str) -> str:
    """Open a scope case, submit it, wait durably for one approval, apply it.

    The whole of GP-SPK-001's orchestration, and it makes no governance decision at any
    line. Between `_submit_for_review` and `DBOS.recv` the process may be killed, may
    stay dead while the approval is delivered by `DBOSClient.send`, and may be replaced
    by a different process that resumes the same durable receive -- which is the
    property ST-0 established and ST-10 proves against the real workflow.

    Returns the case's state as the governance kernel left it.
    """
    workflow_id = _require_workflow_context()
    _open_case(gov_db, workflow_id, spec_json)
    _submit_for_review(gov_db, workflow_id)
    message = DBOS.recv(topic=APPROVAL_TOPIC, timeout_seconds=APPROVAL_TIMEOUT_SECONDS)
    if message is None:
        raise ApprovalTimeout(workflow_id)
    return _apply_approval(gov_db, workflow_id, message)
