"""The transition graph and its evaluator — decidable with nothing else present.

Design basis: design/GP-SPK-001-governance-kernel.md §3, §4, §9.

Legality is a **declarative table plus a pure function over it**. The table is the whole
authority model for the spike: two edges, each naming the single actor kind that may
authorize it and whether a bound approval is mandatory.

Why the table rather than a chain of checks. §13.1 requirement 6 is a statement about
all nine ordered pairs, and `GK-INV-5` is a statement about every edge. Both are
answerable by reading this tuple. Written as conditionals, each would instead be a claim
about control flow that only holds for the branches someone thought to test.

This module imports no store, no engine, no clock, no serializer and no I/O of any kind
(§4). That is what makes the authority model provable with DBOS absent: GP-04 decides
every pair with nothing running. It performs no mutation either -- `resolve` reads the
table and returns a verdict, so no call can leave the graph different from how it found
it.

The split, following the sibling `governed-runtime`'s precedent:

* `resolve` returns a verdict and **never raises**, so a test can interrogate all 27
  (pair, actor) combinations without a `try`/`except` per cell;
* `refuse_unless_allowed` raises, so a call site gets one deletable guard line per
  refusal -- the shape GP-SPK-002's mutation harness requires, with guard IDs
  `gp_transition_legal` and `gp_transition_authority` frozen now (D-2).

Two refusals, deliberately distinct. `IllegalTransition` says the edge does not exist;
`AuthorityDenied` says it exists and this actor may not take it. Collapsing them would
tell an operator to go looking for the wrong fix.

**Typing is the only input discipline here.** `ScopeState` and `ActorKind` are `StrEnum`
subclasses whose members compare and hash equal to their own names, so a bare string
resolves exactly as the corresponding member does. The layer performs no runtime type
check: callers are constrained by `mypy --strict`, and from GP-05 by validated models
carrying `Literal[ActorKind.HUMAN]`. GP-04 asserts this consequence explicitly rather
than leaving it to be discovered. An unrecognized token names no edge, so it refuses as
absent from the graph -- it can never widen the table.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from gplanner.errors import AuthorityDenied, IllegalTransition
from gplanner.require import require
from gplanner.states import ActorKind, ScopeState


@dataclass(frozen=True)
class TransitionRule:
    """One row of §3's transition table.

    Frozen, because the table is a constant of the design rather than configuration.
    `row` carries the design-doc coordinate (`SPK1-1`, `SPK1-2`) so a refusal, an audit
    event, or a reviewer can name the authority for a decision instead of paraphrasing
    it.
    """

    from_state: ScopeState
    to_state: ScopeState
    #: The ONLY actor kind that may authorize this edge. Never a set: an edge with two
    #: authorities would be two rows, so the table always reads one edge per authority.
    authority: ActorKind
    #: True => a bound `ApprovalStatement` is mandatory. This module states the
    #: requirement and nothing more; what satisfies it is GP-05's and the kernel's
    #: business, and a check here would be a second opinion about approvals.
    requires_approval: bool
    row: str


LEGAL_TRANSITIONS: Final[tuple[TransitionRule, ...]] = (
    TransitionRule(
        from_state=ScopeState.SCOPE_DRAFTING,
        to_state=ScopeState.SCOPE_REVIEW_PENDING,
        authority=ActorKind.SYSTEM,
        requires_approval=False,
        row="SPK1-1",
    ),
    TransitionRule(
        from_state=ScopeState.SCOPE_REVIEW_PENDING,
        to_state=ScopeState.SCOPE_APPROVED,
        authority=ActorKind.HUMAN,
        requires_approval=True,
        row="SPK1-2",
    ),
)
"""The complete transition graph. Two edges; every other ordered pair is absent.

Absent, not listed-and-denied: there is no row anywhere that names `ActorKind.LLM`, so
`GK-INV-5` is a property of what this tuple *contains* rather than of a denial list that
someone could forget to extend.
"""

#: Edge lookup. Derived from the tuple above, never maintained beside it, so the index
#: and the table cannot come to disagree about which edges exist.
_EDGE_INDEX: Final[dict[tuple[ScopeState, ScopeState], TransitionRule]] = {
    (rule.from_state, rule.to_state): rule for rule in LEGAL_TRANSITIONS
}


class Outcome(StrEnum):
    """The three verdicts `resolve` can reach."""

    ALLOW = "ALLOW"
    REFUSE_NOT_IN_GRAPH = "REFUSE_NOT_IN_GRAPH"
    REFUSE_AUTHORITY = "REFUSE_AUTHORITY"


@dataclass(frozen=True)
class Resolution:
    """A verdict, plus enough to explain it without re-deriving it.

    `row` is the design coordinate of the edge under consideration, or `None` when there
    is no such edge to cite. A populated `row` on a refusal therefore means "this edge
    exists and you may not take it", which is a different operator instruction from "no
    such edge".
    """

    outcome: Outcome
    reason: str
    row: str | None


def resolve(from_state: ScopeState, to_state: ScopeState, actor_kind: ActorKind) -> Resolution:
    """Decide `(from_state, to_state, actor_kind)` against the table. Never raises.

    Pure and total: every input reaches exactly one of the three outcomes, and the table
    is only read. The graph question is answered first -- an edge that does not exist
    cannot be authorized by anyone, so reporting an authority failure for it would imply
    the edge was otherwise available.
    """
    rule = _EDGE_INDEX.get((from_state, to_state))
    if rule is None:
        return Resolution(
            outcome=Outcome.REFUSE_NOT_IN_GRAPH,
            reason=(
                f"{from_state} -> {to_state} is not an edge in LEGAL_TRANSITIONS "
                f"(GK-INV-2); the legal edges are "
                f"{', '.join(f'{r.from_state} -> {r.to_state}' for r in LEGAL_TRANSITIONS)}"
            ),
            row=None,
        )
    if actor_kind != rule.authority:
        return Resolution(
            outcome=Outcome.REFUSE_AUTHORITY,
            reason=(
                f"{rule.row}: {from_state} -> {to_state} may be authorized only by "
                f"{rule.authority}, not by {actor_kind} (GK-INV-4/5)"
            ),
            row=rule.row,
        )
    return Resolution(
        outcome=Outcome.ALLOW,
        reason=f"{rule.row}: {from_state} -> {to_state} authorized by {actor_kind}",
        row=rule.row,
    )


def refuse_unless_allowed(
    from_state: ScopeState, to_state: ScopeState, actor_kind: ActorKind
) -> TransitionRule:
    """Return the governing rule, or refuse.

    The thin raising face of `resolve`, for call sites that want a guard rather than a
    verdict. Returning the rule and not merely `None` is what lets the kernel read
    `requires_approval` and `row` from the same decision that permitted the transition,
    instead of looking them up again and risking a second, divergent answer.
    """
    verdict = resolve(from_state, to_state, actor_kind)
    in_graph = verdict.outcome is not Outcome.REFUSE_NOT_IN_GRAPH
    authorized = verdict.outcome is not Outcome.REFUSE_AUTHORITY
    require(in_graph, verdict.reason, error=IllegalTransition)  # guard:gp_transition_legal
    require(authorized, verdict.reason, error=AuthorityDenied)  # guard:gp_transition_authority
    return _EDGE_INDEX[(from_state, to_state)]
