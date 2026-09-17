"""The case state vocabulary — data only.

Design basis: design/GP-SPK-001-governance-kernel.md §3.

This module declares **what the terms are**, never what may be done with them. It holds
no table, no evaluator and no function at all: legality lives in `policy.py`, and a
helper here would put a second opinion about transitions beside the declarative table
that is supposed to be the only one.

Both enums are `StrEnum`, and every member's value is its own name. A state written to
the governance database, quoted in an audit event, or carried in an approval statement
is therefore the same token in storage, on the wire and in this source — there is no
translation table that could drift from the names it translates.

`ActorKind.LLM` is declared here **precisely so it can be proven never sufficient**
(§11, `GK-INV-5`). Omitting it would make "no LLM may authorize a transition" a claim
about the code that happens to exist today; naming it lets GP-04 assert the far stronger
property that the LLM kind is refused on every ordered pair of the transition graph.
`SYSTEM` and `HUMAN` are likewise labels: §11 records that human authenticity is not
established by this spike.
"""

from __future__ import annotations

from enum import StrEnum


class ScopeState(StrEnum):
    """The three states in the GP-SPK-001 slice (§3).

    `SCOPE_APPROVED` is terminal **in this spike**, not terminal in principle.
    `SCOPE_REJECTED` and revision loops are out of scope by §2 and are deliberately
    absent rather than stubbed: a state no transition can reach or leave would be dead
    vocabulary that later reading might mistake for a supported outcome.
    """

    SCOPE_DRAFTING = "SCOPE_DRAFTING"
    SCOPE_REVIEW_PENDING = "SCOPE_REVIEW_PENDING"
    SCOPE_APPROVED = "SCOPE_APPROVED"


class ActorKind(StrEnum):
    """Who is claiming to authorize something — a **label**, never a proof (§11).

    Nothing in this spike establishes that an actor labelled `HUMAN` is one. The label
    is what the authority model is enforced over; authenticating it is the signing
    stage's obligation, and `GK-INV-4` is worded to match.
    """

    HUMAN = "HUMAN"
    SYSTEM = "SYSTEM"
    LLM = "LLM"
