"""The governance kernel — the only mutator of case state.

Design basis: design/GP-SPK-001-governance-kernel.md §10, §4, §9.

**The kernel decides; nothing else does** (`GK-INV-6`). It composes the layers below
it — `policy` for legality and authority, `store` for persistence and structural
uniqueness, `digest` for identity, `approvals` for the record's shape — and it is the
single place a `cases` row is moved from one state to another. It imports no engine, so
the whole authority model is decidable with DBOS absent (§4); when `workflow.py` exists
it will supply durability and transport and will never make a decision.

Three entry points, frozen by §10, and no others.

| Entry point | Mutates | Approval |
|---|---|---|
| `open_case` | creates a case at `SCOPE_DRAFTING` | no |
| `submit_for_review` | `SCOPE_DRAFTING → SCOPE_REVIEW_PENDING` (`SPK1-1`) | no |
| `apply_scope_approval` | `SCOPE_REVIEW_PENDING → SCOPE_APPROVED` (`SPK1-2`) | yes |

Replay-first, and why the order is the design rather than an implementation detail
--------------------------------------------------------------------------------
`apply_scope_approval` looks the `approval_id` up in `approval_consumptions`
**before** evaluating transition legality. After the first successful transition the
case is `SCOPE_APPROVED`, so a re-run would evaluate `SCOPE_APPROVED →
SCOPE_APPROVED`, find no such edge, and raise `IllegalTransition` before ever reaching
the idempotency branch. DBOS steps are at-least-once, so that is not hypothetical —
it is the defect revision 1 of the plan of record carried, and the reason the ordering
below is written out step by step.

Everything else follows from two opposite obligations meeting in one function:

* a **refused** approval must never be burnt, so every policy and binding check
  precedes the claim in step 5f;
* a **committed** approval must never commit twice, so the claim and the state change
  are adjacent inside one `BEGIN IMMEDIATE`.

`applied` is the whole answer to "did *this call* do it": `True` means this call
committed the transition, `False` means this call recognized a transition **this same
approval** already committed. A replay is reported, never silently absorbed, because an
at-least-once caller needs to be able to tell the difference.

Transaction ownership — the kernel opens the transaction, never joins one (ST8-R01)
-----------------------------------------------------------------------------------
Every entry point in the table above refuses a `Store` that is **already inside a
transaction**, before it does any work at all.

`store.transaction()` is reentrant and its inner scope is a pass-through, which is
precisely what §10 needs *within* one owner: the kernel opens one `BEGIN IMMEDIATE` and
every store write it then performs nests into that one transaction. Across two owners
the same property inverts. A caller that had already opened a transaction would leave the
kernel's own scope issuing no `BEGIN` and, decisively, no `COMMIT` — so

* `applied=True` would be returned with nothing committed, and a later rollback by the
  caller would erase a transition this function had already reported as applied;
* step 3's lookup reads through the caller's connection, so a second call would find
  the **uncommitted** consumption row and report `applied=False` — recognizing as a
  *previously committed* transition something no commit has ever made durable;
* a failure escaping step 5 would roll nothing back, because a pass-through scope has
  no commit of its own to protect; a caller that caught it could then commit
  `SCOPE_APPROVED`, one consumption and **zero** audit rows.

`applied` is only as true as the commit behind it, so the kernel must own that commit.
The refusal is a structural precondition on the caller — a plain `if ... raise` raising
`GovernedPlannerError`, no guard ID — and it is deliberately *not* a repair of
`store.transaction()`: the store's nesting is correct and stays exactly as it is.

Guard convention
----------------
A `require(...)` carrying a `# guard:<id>` marker is a site in the plan's frozen guard
registry (§10) and is one deletable statement, with its marker on the statement's
closing line — `store.py`'s convention, for a refusal whose reason does not fit in 100
columns. The four IDs this module owns are `gp_approval_replay`,
`gp_approval_workflow_binding`, `gp_approval_from_state` and
`gp_approval_subject_digest`. `gp_transition_legal` and `gp_transition_authority` are
registered at `policy.refuse_unless_allowed` and are reached by calling it: re-marking
them here would give one guard two sites and would mean the kernel had grown its own
opinion about legality.

A plain `if ... raise` is a **structural precondition**, not a registered guard: a
missing case, or a subject artifact the store does not hold. Those refusals are not
governance decisions and carry no guard ID.

What this module deliberately does not do
-----------------------------------------
It writes **no audit event for `open_case` or `submit_for_review`.** §10 registers one
audit append, for the approval transition, and `audit_events` is append-only by
convention with no hash chaining in GP-SPK-001 (CLAUDE.md, known gaps). Inventing
further events would be inventing governance semantics the frozen contract does not
ask for, and would make "exactly one audit event per committed approval" harder to
read rather than easier.

It reads **no trusted clock.** `consumed_at` and an audit row's `at` are this process's
own observation of local time, in the same RFC 3339 shape `issued_at` is syntax-checked
against. They record when this process believed it committed; they are not evidence
about when an approver acted, and nothing in this spike is — §8 defers freshness, TTL
and clock trust entirely. Neither value takes part in the replay comparison, so the
outcome of §10 step 4 does not depend on a clock at all.

It performs **no signing and no authentication.** `approver_kind` is a *label*: only a
statement labelled `ActorKind.HUMAN` can authorize `SPK1-2`, and that label is enforced
by `approvals.py` before the kernel sees it.

> **HUMAN authority label enforced; human identity/authenticity not proven until the
> signing/authentication stage.** (§11, quoted verbatim.)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from gplanner.approvals import ApprovalStatement, ScopeApprovalPredicate
from gplanner.artifacts import ArtifactRef, ScopeSpec
from gplanner.canonical import canonical_bytes
from gplanner.digest import (
    APPROVAL_MEDIA_TYPE,
    SCOPE_MEDIA_TYPE,
    canonical_preimage,
    compute_digest,
    digest_of_preimage_bytes,
    from_intoto_hex,
)
from gplanner.errors import (
    ApprovalBindingError,
    ApprovalReplay,
    GovernedPlannerError,
    StaleApproval,
)
from gplanner.policy import TransitionRule, refuse_unless_allowed
from gplanner.require import require
from gplanner.states import ActorKind, ScopeState
from gplanner.store import CaseRecord, ConsumptionRecord, Store

#: The one audit event name in GP-SPK-001, fixed by the plan of record (revision 5 §23,
#: which counts `audit_events WHERE event = "scope.approved"` as the verdict evidence).
SCOPE_APPROVED_EVENT: Final[str] = "scope.approved"


@dataclass(frozen=True)
class ApplyOutcome:
    """What one `apply_scope_approval` call did — §10's frozen two-field contract.

    Frozen, and exactly two fields. A third field describing *why* would invite callers
    to branch on it, and every refusal in this design is an exception rather than a
    returned status precisely so a caller cannot ignore one by forgetting to look.
    """

    #: The case's state once this call returned. On a replay this is the state the
    #: approval's own committed transition left behind, which the branch has just
    #: verified the case is still in.
    state: ScopeState
    #: `True` -- this call committed the transition. `False` -- this call recognized
    #: the transition this same approval had already committed, and wrote nothing.
    applied: bool


def _now() -> str:
    """This process's observation of local time, RFC 3339 with an offset.

    Not a trusted timestamp, and never compared against anything. See the module
    docstring: the store reads no clock, so the caller supplies one, and this is the
    single place in the governance layer that does.
    """
    return datetime.now(UTC).isoformat()


def _load_case(store: Store, workflow_id: str) -> CaseRecord:
    """The case, or a refusal naming the workflow that has none.

    A structural precondition rather than a registered guard: there is no governance
    decision to make about a case that does not exist, and every entry point needs the
    row before it can decide anything at all.
    """
    case = store.load_case(workflow_id)
    if case is None:
        raise GovernedPlannerError(
            f"no governance case exists for workflow {workflow_id!r}; "
            "open_case must run before any transition"
        )
    return case


def _require_transaction_ownership(store: Store, entry_point: str) -> None:
    """Refuse a `Store` whose transaction this call does not own (ST8-R01).

    A structural precondition, not a registered guard: it decides nothing about
    legality, authority, binding or replay. It decides whether this function is in a
    position to keep the promise its return value makes, which is a question about the
    caller rather than about governance.

    Refusing is the only honest answer available. The kernel cannot commit a
    transaction it did not open — committing somebody else's would make the caller's
    pending writes durable as a side effect of applying an approval — and it cannot
    report `applied=True` for a transition whose durability is still another scope's to
    decide. `GovernedPlannerError` is the class this module already raises for a caller
    that has not met a precondition; `errors.py` is frozen and grows nothing here.
    """
    if store.in_transaction:
        raise GovernedPlannerError(
            f"{entry_point} requires the governance transaction it opens itself, but "
            f"the store is already inside a transaction owned by the caller; a "
            f"committed result cannot be promised from inside a transaction this call "
            f"can neither commit nor roll back (§10)"
        )


def _subject_digest(statement: ApprovalStatement) -> str:
    """The `sha256:<hex>` digest an approval is about, from its one in-toto subject.

    `subject` is bounded to exactly one member by the model (§8), so the index is not a
    choice being made here. `from_intoto_hex` is the single conversion from in-toto's
    bare hex to our prefixed wire format, and it validates rather than assuming.
    """
    return from_intoto_hex(statement.subject[0].digest.sha256)


def _identity_from_storage(store: Store, case: CaseRecord) -> None:
    """§10 step 5e: prove the subject's identity from the bytes the store actually holds.

    The re-derivation is `store.get_artifact`, which rehashes the authoritative
    preimage and refuses a mismatch under the registry's `gp_digest_rehash` -- a guard
    the plan registers at the store, on both its read and its write path, so it is not
    re-marked here. Calling it from *inside* this transaction is what makes the
    identity proven the identity this transaction is about to act on.

    A missing row is a structural precondition, not a governance decision, and is
    unreachable through the schema: `cases.subject_digest` is a foreign key into
    `artifacts`. Checked because unreachability is a property of the schema rather than
    of this function.
    """
    if store.get_artifact(case.subject_digest) is None:
        raise GovernedPlannerError(
            f"case {case.workflow_id!r} references subject {case.subject_digest!r}, "
            "which the store does not hold"
        )


def _is_own_commit(
    recorded: ConsumptionRecord,
    case: CaseRecord,
    *,
    approval_digest: str,
    workflow_id: str,
    subject_digest: str,
    predicate: ScopeApprovalPredicate,
) -> bool:
    """Is this exactly the transition `recorded` already committed? (§10 step 4.)

    Six conditions, all required. Five compare the submitted statement against the
    recorded claim; the sixth compares the *world* against it, because a row saying the
    case was left in `to_state` is only a description of a replay if the case is still
    there.

    `approval_digest` covers the statement's entire content -- including its own
    `predicate.workflow_id`, `issued_at` and `approver_id` -- so a re-minted or edited
    approval under a used id cannot match. `workflow_id` is compared as the workflow
    this call was made *against*, which is the binding the row asserts and the one a
    reused id would break.
    """
    return (
        recorded.approval_digest == approval_digest
        and recorded.workflow_id == workflow_id
        and recorded.subject_digest == subject_digest
        and recorded.from_state == predicate.from_state
        and recorded.to_state == predicate.to_state
        and case.state == recorded.to_state
    )


def _replay_reason(
    recorded: ConsumptionRecord,
    case: CaseRecord,
    *,
    approval_digest: str,
    workflow_id: str,
    subject_digest: str,
    predicate: ScopeApprovalPredicate,
) -> str:
    """Name every field that differs, so a refusal does not require a debugger.

    A helper so the guard site stays one statement: the mutation harness proves a guard
    is tested by deleting it, and a refusal whose message is built inline would delete
    into several lines of unrelated string construction.
    """
    differences = [
        f"{field}: recorded {was!r} != submitted {now!r}"
        for field, was, now in (
            ("approval_digest", recorded.approval_digest, approval_digest),
            ("workflow_id", recorded.workflow_id, workflow_id),
            ("subject_digest", recorded.subject_digest, subject_digest),
            ("from_state", str(recorded.from_state), str(predicate.from_state)),
            ("to_state", str(recorded.to_state), str(predicate.to_state)),
        )
        if was != now
    ]
    if case.state != recorded.to_state:
        differences.append(
            f"case state: recorded to_state {str(recorded.to_state)!r} != "
            f"current {str(case.state)!r}"
        )
    return (
        f"approval_id {recorded.approval_id!r} was already consumed at "
        f"{recorded.consumed_at} and this is not a replay of that same committed "
        f"transition (GK-INV-3); " + "; ".join(differences)
    )


def _consumption_branch(
    recorded: ConsumptionRecord,
    case: CaseRecord,
    *,
    approval_digest: str,
    workflow_id: str,
    subject_digest: str,
    predicate: ScopeApprovalPredicate,
) -> ApplyOutcome:
    """§10 step 4: an `approval_id` already claimed — replay, or refusal.

    **A pure read.** It recognizes a previously committed transition; it never performs
    or authorizes a second one, and it writes nothing on either path. That is what lets
    it run before the transition evaluation without weakening anything: the only
    outcomes are "the transition you are asking for is already committed, unchanged"
    and a refusal.

    The site the plan's §10 registry names for `gp_approval_replay`.
    """
    require(
        _is_own_commit(
            recorded,
            case,
            approval_digest=approval_digest,
            workflow_id=workflow_id,
            subject_digest=subject_digest,
            predicate=predicate,
        ),
        _replay_reason(
            recorded,
            case,
            approval_digest=approval_digest,
            workflow_id=workflow_id,
            subject_digest=subject_digest,
            predicate=predicate,
        ),
        error=ApprovalReplay,
    )  # guard:gp_approval_replay
    return ApplyOutcome(state=recorded.to_state, applied=False)


def _transition_detail(
    rule: TransitionRule,
    *,
    predicate: ScopeApprovalPredicate,
    approval_digest: str,
    subject_digest: str,
    revision: int,
) -> bytes:
    """The audit row's `detail_json`: what authorized this transition, as JCS bytes.

    Serialized through `canonical.canonical_bytes`, the package's one JSON encoder, so
    no second serializer comes into existence here. These bytes are **not** an
    identity preimage -- there is no `preimage_version`, no `payload_profile` and no
    `media_type` -- and nothing hashes them; `store.py` stores them opaquely and never
    parses them.

    `row` is the design coordinate of the edge, taken from the same `TransitionRule`
    that permitted the transition rather than looked up again, so the audit cannot cite
    an authority different from the one that actually applied. `approver_id` and
    `approver_kind` are recorded as *claims*: §11 is explicit that neither is
    authenticated.
    """
    return canonical_bytes(
        {
            "row": rule.row,
            "approval_id": predicate.approval_id,
            "approval_digest": approval_digest,
            "subject_digest": subject_digest,
            "from_state": str(predicate.from_state),
            "to_state": str(predicate.to_state),
            "approver_id": predicate.approver_id,
            "approver_kind": str(predicate.approver_kind),
            "issued_at": predicate.issued_at,
            "case_revision": revision,
        }
    )


def open_case(store: Store, workflow_id: str, spec: ScopeSpec) -> ArtifactRef:
    """Store a scope specification and open a case against it at `SCOPE_DRAFTING`.

    Identity first, and only once: the authoritative bytes are produced by §5's single
    pipeline and the digest is the hash of *those* bytes, so nothing is serialized
    twice and no second representation exists to disagree with the first.

    **Idempotent for identical content.** Re-running with the same spec returns the
    same reference and changes nothing, which is what the plan of record relies on when
    it records that this step is safe for an at-least-once engine to re-run (revision 5
    §16). It is not a transition and mutates no state, so repeating it contradicts no
    row of §3's table -- unlike `submit_for_review`, which is a transition and is
    therefore refused as a self-loop rather than quietly absorbed.

    A case that already exists under a **different** subject is refused by the store's
    primary key: this entry point opens cases, it does not repoint them. GP-SPK-001 has
    no revision loop (§2), so there is no authorized way to change a case's subject,
    and inventing one here would add a state transition the design does not contain.

    The returned reference and the idempotency claim are both statements about what the
    store now **holds**, so this entry point owns its transaction like the other two
    (ST8-R01): inside a caller's, the artifact and the case row could be rolled back
    under a reference already handed out, or an artifact could be committed with no case
    beside it after a caught failure.
    """
    _require_transaction_ownership(store, "open_case")
    blob = canonical_preimage(spec, SCOPE_MEDIA_TYPE)
    digest = digest_of_preimage_bytes(blob)
    with store.transaction():
        ref = store.put_artifact(
            digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob
        )
        existing = store.load_case(workflow_id)
        if existing is None or existing.subject_digest != digest:
            store.create_case(
                workflow_id=workflow_id,
                state=ScopeState.SCOPE_DRAFTING,
                subject_digest=digest,
            )
    return ref


def submit_for_review(store: Store, workflow_id: str, actor_kind: ActorKind) -> ScopeState:
    """Take `SPK1-1`: submit a drafted case for human review. No approval required.

    The legality and authority decision is `policy.refuse_unless_allowed`'s, so `SYSTEM`
    is the only actor kind that can take this edge and a self-loop on an
    already-submitted case is refused as absent from the graph. The kernel holds no copy
    of either rule.

    `requires_approval` is read from the rule that permitted the edge, so this entry
    point cannot take an edge the table says needs a bound approval. Under the frozen
    table that is unreachable -- `SPK1-1` requires none -- and it is checked anyway,
    because otherwise the column would be declarative decoration and a future row could
    quietly rely on a check nobody wrote.

    The returned state is a statement that the case **is** in `SCOPE_REVIEW_PENDING`,
    and the compare-and-set it rests on reads a revision that must be committed rather
    than merely visible on the caller's connection. So this entry point owns its
    transaction too (ST8-R01).
    """
    _require_transaction_ownership(store, "submit_for_review")
    with store.transaction():
        case = _load_case(store, workflow_id)
        rule = refuse_unless_allowed(case.state, ScopeState.SCOPE_REVIEW_PENDING, actor_kind)
        if rule.requires_approval:
            raise GovernedPlannerError(
                f"{rule.row}: {case.state} -> {ScopeState.SCOPE_REVIEW_PENDING} requires a "
                "bound approval and cannot be taken by submit_for_review"
            )
        advanced = store.advance_case(
            workflow_id=workflow_id,
            to_state=ScopeState.SCOPE_REVIEW_PENDING,
            expected_revision=case.revision,
        )
    return advanced.state


def apply_scope_approval(
    store: Store, workflow_id: str, statement: ApprovalStatement
) -> ApplyOutcome:
    """Apply one approval to one case, in §10's order, inside one `BEGIN IMMEDIATE`.

    The steps below are numbered as §10 numbers them, and the order is the contract:

    1. load the case;
    2. compute the validated statement's `approval_digest`;
    3. look the `approval_id` up **before** any transition evaluation;
    4. if a row exists, replay or refuse -- `_consumption_branch`, a pure read;
    5. only with no row: (a) legality and authority, (b) workflow binding,
       (c) `from_state` binding, (d) subject digest, (e) identity re-derived from the
       stored bytes, (f) claim the approval, (g) compare-and-set the case forward,
       (h) append exactly one audit event, (i) commit.

    Steps 5a-5e all precede 5f, so **a refused approval is never burnt**: a stale or
    mis-bound statement still authorizes the case and digest it was actually issued
    for. Steps 5f and 5g are adjacent in one transaction, so a claimed approval and the
    state it authorized commit together or not at all.

    `BEGIN IMMEDIATE` takes the write lock at `BEGIN`, so two concurrent submissions of
    the same statement serialize rather than race: one commits and returns
    `applied=True`, the other reads the committed row, converges through step 4's match
    branch and returns `applied=False`. One consumption row, one audit event, one
    transition -- deterministically, not by tolerance.

    Note where each `return` sits. The replay branch returns from *inside* the
    transaction because it wrote nothing, so its answer does not depend on the commit.
    The `applied=True` outcome is constructed only **after** the transaction has
    committed, so the flag cannot claim a transition that a failed commit rolled back.

    `requires_approval` is not re-checked here. The only edge in §3's table that needs
    no approval is `SPK1-1`, whose authority is `SYSTEM`, and `approver_kind` is
    `Literal[ActorKind.HUMAN]` -- so step 5a already refuses it on authority, and a
    second check would be a second opinion with nothing left to decide.

    **Step 0, before step 1:** the store must not already be inside a transaction. Every
    sentence above about what `applied` means is a sentence about a commit, and the
    module docstring's ST8-R01 section sets out what each of them degrades into when the
    commit belongs to the caller. The refusal precedes the case load, so a refused call
    has read nothing and claimed nothing.
    """
    _require_transaction_ownership(store, "apply_scope_approval")
    predicate = statement.predicate
    with store.transaction():
        case = _load_case(store, workflow_id)  # step 1
        approval_digest = compute_digest(statement, APPROVAL_MEDIA_TYPE)  # step 2
        subject_digest = _subject_digest(statement)
        recorded = store.find_consumption(predicate.approval_id)  # step 3
        if recorded is not None:  # step 4
            return _consumption_branch(
                recorded,
                case,
                approval_digest=approval_digest,
                workflow_id=workflow_id,
                subject_digest=subject_digest,
                predicate=predicate,
            )
        rule = refuse_unless_allowed(  # step 5a
            case.state, predicate.to_state, predicate.approver_kind
        )
        require(
            predicate.workflow_id == workflow_id,
            f"approval {predicate.approval_id!r} is bound to workflow "
            f"{predicate.workflow_id!r} and cannot authorize {workflow_id!r} (GK-INV-2)",
            error=ApprovalBindingError,
        )  # guard:gp_approval_workflow_binding
        require(
            predicate.from_state == case.state,
            f"approval {predicate.approval_id!r} authorizes a transition from "
            f"{str(predicate.from_state)!r}, but case {workflow_id!r} is in "
            f"{str(case.state)!r} (GK-INV-2)",
            error=ApprovalBindingError,
        )  # guard:gp_approval_from_state
        require(
            subject_digest == case.subject_digest,
            f"approval {predicate.approval_id!r} is bound to subject "
            f"{subject_digest!r}, but case {workflow_id!r} now carries "
            f"{case.subject_digest!r} (GK-INV-2); the approval is stale, not void",
            error=StaleApproval,
        )  # guard:gp_approval_subject_digest
        _identity_from_storage(store, case)  # step 5e
        store.record_consumption(  # step 5f
            approval_id=predicate.approval_id,
            approval_digest=approval_digest,
            subject_digest=subject_digest,
            workflow_id=workflow_id,
            from_state=predicate.from_state,
            to_state=predicate.to_state,
            consumed_at=_now(),
        )
        advanced = store.advance_case(  # step 5g
            workflow_id=workflow_id,
            to_state=predicate.to_state,
            expected_revision=case.revision,
        )
        store.append_audit(  # step 5h
            workflow_id=workflow_id,
            at=_now(),
            event=SCOPE_APPROVED_EVENT,
            detail_json=_transition_detail(
                rule,
                predicate=predicate,
                approval_digest=approval_digest,
                subject_digest=subject_digest,
                revision=advanced.revision,
            ),
        )
    return ApplyOutcome(state=advanced.state, applied=True)  # step 5i
