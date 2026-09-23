"""`AuthorityEnvelope` — the closed statement of what one bounded activation may do.

Design basis: AP-03 §2.3, §3.1 rows 2 and 3, §5.1 (derivation relation), §5.2 (what
an envelope carries), §5.3 (`EV-1`…`EV-7`), §5.4, §16.3; `AP03-I12`, `AP03-I13`,
`AP03-I14`, `AP03-I30`, `AP03-I33`; AP-11 §7 (`NV11-6`).

**The envelope names an instance, never a record.** `resolved_root` is typed
`OwnerAuthorizationId`, so an envelope naming an `AuthorizationRecordId` is not
merely invalid — it is inexpressible (`AP03-I33`, `EV-1`).

**Identity is minted and never content.** Two envelopes with identical bounds are two
envelopes (AP-03 §3.1 row 2). Content identity over bounds would collapse a permitted
later derivation with *equivalent* bounds onto the consumed identity — it would **be**
the revival `EV-5` and `AP03-I12` forbid.

**What an envelope carries, and what it must never carry.** AP-03 §5.2 is exhaustive:
its own identity, the resolved root authorization identity, the stage, the entry
boundary, exactly one role, its granted bounds, and a declared-closed marker. It
carries **no provider identity, no prompt text, no time-derived validity, no
signature, and no retry, transport or step attribute**. `tests_gpauto` asserts each
absence structurally; provider in particular is excluded because a change of vendor
would otherwise change authority (`NV11-6`, `AP03-I17`).

**Absence of an envelope is correct, not a stripped authority.** On a branch where a
role is not activated, no envelope exists (`EV-6`, `AP03-I30`). There is therefore no
"empty" or "null" envelope type here, and none should be added: absence is expressed
by there being nothing, which is what stops a later phase from acting on a
placeholder.

**No derivation is implemented here.** `AP03-I13` makes derivation a total function
with no free parameters of `(resolved root, role, branch, applicable frozen set,
entry boundary)`, and `EV-3` requires `bounds ≤ ceiling` dimension-wise. Both are
`GP-AUTO-ST-06`'s; this module declares what the result looks like and computes
nothing. `AP03-I14`'s equivalent-or-narrower rule likewise constrains any pair of
envelopes that exists — AP-03 states nothing about whether a second may be derived,
and neither does this module.
"""

from __future__ import annotations

from gpauto.bounds import AuthorityBounds
from gpauto.identity import (
    AuthorityEnvelopeId,
    EntryStateBoundaryId,
    GovernedStageId,
    OwnerAuthorizationId,
)
from gpauto.schema import DomainEntity
from gpauto.vocabulary import Role


class AuthorityEnvelope(DomainEntity):
    """One role, one activation, one stage, one entry boundary (`EV-2`).

    `declared_closed` carries the `E-19` marker. `E-19` is AP-02's and is not
    re-decided here: the marker is recorded, not evaluated.
    """

    identity: AuthorityEnvelopeId
    resolved_root: OwnerAuthorizationId
    stage: GovernedStageId
    entry_boundary: EntryStateBoundaryId
    role: Role
    bounds: AuthorityBounds
    declared_closed: bool
