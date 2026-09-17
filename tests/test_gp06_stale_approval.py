"""GP-06 — an approval binds one digest; a changed artifact stales it.

Design basis: design/GP-SPK-001-governance-kernel.md §13.1 requirement 5, §10, §6.

The plan of record's GP-06 (revision 5 §15) is a six-step adversarial sequence plus
five frozen variants, and requirement 5 is accepted only when **all variants** pass,
the negative case included. This file is organized around that list, in that order, so
a reader can put the plan beside it and account for every clause.

What "stale" means here, precisely. The approval is **not void**: it still authorizes
the digest it was actually issued for. It simply does not authorize the artifact the
case now carries. Two consequences are asserted rather than implied — a stale refusal
**burns nothing** (no consumption row, no state change, no audit event), and the same
approval is accepted again, unchanged, once the case genuinely carries its digest
again. A guard that consumed the approval on the way to refusing it would satisfy a
weaker reading of "refused" while destroying an authority-bearing record.

Ordering interaction with §10, which this file depends on and does not re-prove.
No consumption row exists in any case below, so control reaches step 5 and the
subject-digest guard fires *before* the claim in step 5f. GP-07 owns the replay branch.

Revising the case's subject
---------------------------
`store.py` deliberately offers **no subject-revision mutator**, and ST-8 is not
authorized to add production API for a test's setup. GP-SPK-001 has no revision loop
(§2): "the artifact was revised under review" is a situation the kernel must *refuse
safely*, not one it has an entry point for. So the revised artifact is written through
the authorized `put_artifact` — digest-verified by the store, so the foreign key is
genuinely satisfied and the bytes genuinely hash to what they are filed under — and
only the `cases.subject_digest` pointer is moved, with `revision + 1`, in the shape
`advance_case` uses. The kernel re-reads the case inside its own transaction, so it
sees the revised subject and a revision it did not choose.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from conftest import Harness
from gplanner import codec, kernel, store
from gplanner.approvals import (
    PREDICATE_VERSION,
    SCOPE_APPROVAL_PREDICATE_TYPE,
    STATEMENT_TYPE,
    ApprovalStatement,
)
from gplanner.artifacts import ScopeSpec
from gplanner.digest import (
    SCOPE_MEDIA_TYPE,
    canonical_preimage,
    compute_digest,
    to_intoto_hex,
)
from gplanner.errors import ApprovalBindingError, StaleApproval
from gplanner.states import ActorKind, ScopeState
from gplanner.store import Store

SRC = Path(__file__).resolve().parents[1] / "src" / "gplanner"

WORKFLOW_ID = "gp-spk-001-case-0001"
OTHER_WORKFLOW_ID = "gp-spk-001-case-0002"
APPROVAL_ID = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a88"
APPROVER_ID = "owner@example.invalid"
ISSUED_AT = "2026-09-17T11:22:33Z"

# --- builders --------------------------------------------------------------------


def spec(
    *,
    title: str = "Governance kernel feasibility",
    in_scope: tuple[str, ...] = ("digest-bound approvals", "single-use consumption"),
) -> ScopeSpec:
    """One spec, with the two fields the variants mutate exposed as arguments."""
    return ScopeSpec(
        title=title,
        problem_statement="Prove the authority model with no LLM in the loop.",
        in_scope=in_scope,
        out_of_scope=("signing",),
        acceptance_criteria=("the approval binds one digest",),
    )


def artifact_of(model: ScopeSpec) -> tuple[str, bytes]:
    """The digest and THE authoritative bytes, from the one §5 pipeline."""
    return (
        compute_digest(model, SCOPE_MEDIA_TYPE),
        canonical_preimage(model, SCOPE_MEDIA_TYPE),
    )


def mint(
    subject_digest: str,
    *,
    approval_id: str = APPROVAL_ID,
    workflow_id: str = WORKFLOW_ID,
    from_state: ScopeState = ScopeState.SCOPE_REVIEW_PENDING,
    to_state: ScopeState = ScopeState.SCOPE_APPROVED,
) -> ApprovalStatement:
    """A valid statement bound to `subject_digest`, built through the one decode path.

    Minted from JSON text rather than by constructing the model directly, because JSON
    text is what the transport carries (§7) and `codec.decode_approval` is the only
    conversion. A statement that could only be built in-process would prove less.
    """
    wire: dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": "gplanner.scope/v1", "digest": {"sha256": to_intoto_hex(subject_digest)}}
        ],
        "predicateType": SCOPE_APPROVAL_PREDICATE_TYPE,
        "predicate": {
            "predicate_version": PREDICATE_VERSION,
            "approval_id": approval_id,
            "workflow_id": workflow_id,
            "from_state": str(from_state),
            "to_state": str(to_state),
            "approver_id": APPROVER_ID,
            "approver_kind": str(ActorKind.HUMAN),
            "decision": "APPROVE",
            "issued_at": ISSUED_AT,
        },
    }
    return codec.decode_approval(json.dumps(wire))


def raw(path: Path) -> sqlite3.Connection:
    """A connection that bypasses the store, for counting rows and repointing a case."""
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def evidence(path: Path) -> tuple[int, int, str, int]:
    """(consumption rows, audit rows, case state, case revision) — read outside the store."""
    conn = raw(path)
    try:
        consumptions = int(conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0])
        audits = int(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
        row = conn.execute(
            "SELECT state, revision FROM cases WHERE workflow_id = ?", (WORKFLOW_ID,)
        ).fetchone()
        return consumptions, audits, str(row[0]), int(row[1])
    finally:
        conn.close()


def revise_subject(opened: Store, path: Path, model: ScopeSpec) -> str:
    """Store `model` through the authorized path, then repoint the case at it.

    See the module docstring for why the pointer move is direct SQL: the frozen store
    API has no subject-revision mutator, and inventing one for a test's setup would
    widen production API this stage is not authorized to touch.
    """
    digest, blob = artifact_of(model)
    opened.put_artifact(digest=digest, media_type=SCOPE_MEDIA_TYPE, canonical_preimage=blob)
    conn = raw(path)
    try:
        conn.execute(
            "UPDATE cases SET subject_digest = ?, revision = revision + 1 "
            "WHERE workflow_id = ?",
            (digest, WORKFLOW_ID),
        )
    finally:
        conn.close()
    return digest


@pytest.fixture
def st(h: Harness) -> Iterator[Store]:
    with store.open(h.governance_db) as opened:
        yield opened


@pytest.fixture
def pending(st: Store) -> tuple[Store, str]:
    """A case submitted for review, through the kernel, carrying `spec()` as its subject."""
    spec_v1 = spec()
    ref = kernel.open_case(st, WORKFLOW_ID, spec_v1)
    state = kernel.submit_for_review(st, WORKFLOW_ID, ActorKind.SYSTEM)
    assert state is ScopeState.SCOPE_REVIEW_PENDING
    assert ref.digest == compute_digest(spec_v1, SCOPE_MEDIA_TYPE)
    return st, ref.digest


# =================================================================================
# Section 1 — the mandated adversarial sequence (plan §15, steps 1-6)
# =================================================================================


def test_an_approval_for_the_previous_digest_is_refused_against_the_revised_artifact(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The whole of requirement 5 in one sequence, with both digests named in the refusal.

    `spec_v2` differs from `spec_v1` in exactly one character of one field, so the only
    thing that can have changed the verdict is identity.
    """
    opened, d1 = pending
    statement = mint(d1)

    d2 = revise_subject(opened, h.governance_db, spec(title="Governance kernel feasibilitY"))
    assert d2 != d1

    with pytest.raises(StaleApproval) as refusal:
        kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)

    message = str(refusal.value)
    assert d1 in message, "the refusal must name the digest the approval was issued for"
    assert d2 in message, "the refusal must name the digest the case actually carries"

    consumptions, audits, state, _ = evidence(h.governance_db)
    assert state == ScopeState.SCOPE_REVIEW_PENDING
    assert consumptions == 0, "a refused approval must not be burnt (§10: guards precede the claim)"
    assert audits == 0, "a refusal is not a transition and appends no transition event"


def test_a_stale_refusal_is_a_binding_failure_not_a_bare_error(
    pending: tuple[Store, str], h: Harness
) -> None:
    """`StaleApproval` subclasses `ApprovalBindingError` (§9), so a caller handling
    binding failures catches it without enumerating subclasses."""
    opened, d1 = pending
    statement = mint(d1)
    revise_subject(opened, h.governance_db, spec(title="Revised"))
    with pytest.raises(ApprovalBindingError):
        kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)


# =================================================================================
# Section 2 — the frozen variants (plan §15)
# =================================================================================


def test_reordering_in_scope_changes_the_digest_and_stales_the_approval(
    pending: tuple[Store, str], h: Harness
) -> None:
    """Order is semantic and is never sorted away: the same strings, reversed, are a
    different spec, so an approval for the original does not authorize it."""
    opened, d1 = pending
    statement = mint(d1)
    reordered = spec(in_scope=("single-use consumption", "digest-bound approvals"))
    d2 = revise_subject(opened, h.governance_db, reordered)
    assert d2 != d1

    with pytest.raises(StaleApproval):
        kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert evidence(h.governance_db)[:2] == (0, 0)


def test_one_trailing_space_in_the_title_stales_the_approval(
    pending: tuple[Store, str], h: Harness
) -> None:
    """No normalization anywhere on the identity path: whitespace is content."""
    opened, d1 = pending
    statement = mint(d1)
    d2 = revise_subject(opened, h.governance_db, spec(title="Governance kernel feasibility "))
    assert d2 != d1

    with pytest.raises(StaleApproval):
        kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)


def test_an_unchanged_reserialization_leaves_the_approval_valid(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The negative case, and the reason determinism is a requirement at all.

    An equal spec re-serialized yields the identical digest, so the approval is
    accepted and the transition commits. Without this, "changed content stales the
    approval" could be satisfied by an implementation that stales everything.
    """
    opened, d1 = pending
    statement = mint(d1)
    assert compute_digest(spec(), SCOPE_MEDIA_TYPE) == d1
    assert revise_subject(opened, h.governance_db, spec()) == d1

    outcome = kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert outcome.applied is True
    assert outcome.state is ScopeState.SCOPE_APPROVED

    consumptions, audits, state, _ = evidence(h.governance_db)
    assert (consumptions, audits, state) == (1, 1, ScopeState.SCOPE_APPROVED)


def test_reverting_byte_for_byte_restores_the_digest_and_the_approval_is_accepted(
    pending: tuple[Store, str], h: Harness
) -> None:
    """Revival is digest-honest: the approval works again because the digest genuinely
    matches again, not because a refusal was remembered and later forgiven."""
    opened, d1 = pending
    statement = mint(d1)

    d2 = revise_subject(opened, h.governance_db, spec(title="Under revision"))
    assert d2 != d1
    with pytest.raises(StaleApproval):
        kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)

    assert revise_subject(opened, h.governance_db, spec()) == d1
    outcome = kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert (outcome.applied, outcome.state) == (True, ScopeState.SCOPE_APPROVED)
    assert evidence(h.governance_db)[:2] == (1, 1)


def test_the_same_digest_in_another_workflow_does_not_bypass_workflow_binding(
    pending: tuple[Store, str], h: Harness
) -> None:
    """Digest binding and workflow binding are independent (`GK-INV-2`).

    The second case carries the *same* subject digest, so the subject-digest guard
    would pass. The refusal is a workflow-binding failure and specifically **not**
    `StaleApproval`, because nothing here is stale.
    """
    opened, d1 = pending
    kernel.open_case(opened, OTHER_WORKFLOW_ID, spec())
    kernel.submit_for_review(opened, OTHER_WORKFLOW_ID, ActorKind.SYSTEM)

    issued_for_other = mint(d1, workflow_id=OTHER_WORKFLOW_ID)
    with pytest.raises(ApprovalBindingError) as refusal:
        kernel.apply_scope_approval(opened, WORKFLOW_ID, issued_for_other)
    assert not isinstance(refusal.value, StaleApproval)
    assert OTHER_WORKFLOW_ID in str(refusal.value) and WORKFLOW_ID in str(refusal.value)

    consumptions, audits, state, _ = evidence(h.governance_db)
    assert (consumptions, audits, state) == (0, 0, ScopeState.SCOPE_REVIEW_PENDING)


def test_an_approval_naming_the_wrong_from_state_is_refused(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The `from_state` binding, broken alone: the edge is legal and the digest matches,
    so only the statement's own claim about where the case stood is wrong."""
    opened, d1 = pending
    statement = mint(d1, from_state=ScopeState.SCOPE_DRAFTING)
    with pytest.raises(ApprovalBindingError) as refusal:
        kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert not isinstance(refusal.value, StaleApproval)
    assert evidence(h.governance_db)[:2] == (0, 0)


# =================================================================================
# Section 3 — a refused approval is never burnt
# =================================================================================


def test_a_stale_refusal_leaves_the_approval_usable_against_its_own_digest(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The same `approval_id`, refused as stale three times, still authorizes its digest.

    This is the property the §10 ordering exists for: every policy and binding check
    precedes the claim, so a refusal cannot consume the single use it refused.
    """
    opened, d1 = pending
    statement = mint(d1)
    for title in ("v2", "v3", "v4"):
        revise_subject(opened, h.governance_db, spec(title=title))
        with pytest.raises(StaleApproval):
            kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)
    assert evidence(h.governance_db)[0] == 0

    assert revise_subject(opened, h.governance_db, spec()) == d1
    assert kernel.apply_scope_approval(opened, WORKFLOW_ID, statement).applied is True


def test_the_stale_check_reads_the_case_and_not_the_statements_own_claim(
    pending: tuple[Store, str], h: Harness
) -> None:
    """Identity is proven from storage, never from what the caller asserts (§10 step 5e).

    The statement names a digest no artifact in the store has. The refusal still names
    the case's actual subject, which is the value re-derived from the stored bytes.
    """
    opened, d1 = pending
    absent = "sha256:" + "b" * 64
    with pytest.raises(StaleApproval) as refusal:
        kernel.apply_scope_approval(opened, WORKFLOW_ID, mint(absent))
    assert d1 in str(refusal.value) and absent in str(refusal.value)
    assert evidence(h.governance_db)[:2] == (0, 0)


# =================================================================================
# Section 4 — the guard the plan registers for GP-06
# =================================================================================


def guarded_statement(source: str, marker: str) -> str:
    """The single `require(...)` statement carrying `# guard:<id>`, as one string.

    The marker sits on the statement's closing line, following `store.py`'s frozen
    convention for a guard whose reason does not fit in 100 columns. Reading the whole
    statement back is what lets a test assert the guard ID and the refusal class are
    bound to each other, rather than merely both present in the file somewhere.
    """
    lines = source.splitlines()
    marked = [index for index, line in enumerate(lines) if f"# {marker}" in line]
    assert len(marked) == 1, f"{marker} must be marked exactly once, found {len(marked)}"
    assert lines[marked[0]].rstrip().endswith(f"# {marker}")
    start = marked[0]
    while "require(" not in lines[start]:
        start -= 1
        assert start >= 0, f"{marker} is not attached to a require() call"
    return "\n".join(lines[start : marked[0] + 1])


def test_the_subject_digest_guard_is_the_registered_site_and_refuses_as_stale() -> None:
    """Plan §10 registers `guard:gp_approval_subject_digest` at
    `kernel.apply_scope_approval`, refusing with `StaleApproval`, covered by GP-06."""
    source = (SRC / "kernel.py").read_text(encoding="utf-8")
    statement = guarded_statement(source, "guard:gp_approval_subject_digest")
    assert "StaleApproval" in statement
    assert "case.subject_digest" in statement
