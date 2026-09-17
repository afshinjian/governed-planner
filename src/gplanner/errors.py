"""Governance failure classes.

Design basis: design/GP-SPK-001-governance-kernel.md §9.

Each error names a **governance** failure class, never a vendor or transport failure.
Adapters translate their own failures into these, so a refusal always reads as a
statement about the authority model rather than about the library that noticed it.

The hierarchy is flat and one level deep by design: a caller that wants to catch "any
refusal" catches :class:`GovernedPlannerError`, and every other class is a specific
statement. The single nesting -- :class:`StaleApproval` under
:class:`ApprovalBindingError` -- exists because a stale approval *is* a binding
failure, and a caller handling binding failures should catch it without enumerating.

The whole hierarchy ships at once because it is frozen design. Later stages import
from it rather than grow it, so the set cannot drift piecemeal across eight stages.
Their *semantics* are implemented by the stage that first raises them; this module
declares what those refusals will be called.
"""

from __future__ import annotations


class GovernedPlannerError(Exception):
    """Base for every refusal this package raises."""


class CanonicalizationError(GovernedPlannerError):
    """A value is not representable as JSON, so it has no canonical form (GK-INV-1).

    Raised rather than coerced: a silent coercion would make identity depend on the
    coercion rule instead of on the content.
    """


class PayloadProfileViolation(GovernedPlannerError):
    """A value lies outside `gplanner.payload-profile/1` (GK-INV-1).

    Distinct from :class:`CanonicalizationError`: the value may be perfectly valid
    JSON that governed-planner declines to content-address, such as a float, whose
    JCS form would map two distinct values onto one identity.
    """


class DigestMismatch(GovernedPlannerError):
    """Stored preimage bytes do not rehash to the digest they are filed under
    (GK-INV-1)."""


class IllegalTransition(GovernedPlannerError):
    """The requested edge is absent from `LEGAL_TRANSITIONS` (GK-INV-2)."""


class AuthorityDenied(GovernedPlannerError):
    """The actor kind is not the authority for this edge (GK-INV-4/5)."""


class ApprovalBindingError(GovernedPlannerError):
    """An approval does not bind the case it was presented against (GK-INV-2)."""


class StaleApproval(ApprovalBindingError):
    """The approval's subject digest is not the case's current artifact (GK-INV-2).

    The approval is not thereby void: it still authorizes the digest it was issued
    for. It simply does not authorize *this* one.
    """


class ApprovalReplay(GovernedPlannerError):
    """An `approval_id` already consumed, and not by this same committed transition
    (GK-INV-3)."""


class ConcurrentModification(GovernedPlannerError):
    """The case revision compare-and-set lost to a concurrent writer (GK-INV-3)."""


class StoreSchemaTooOld(GovernedPlannerError):
    """The database predates this build and there is no migration path.

    A store that opens cleanly and then cannot be read is worse than one that
    refuses: the first error an operator sees should name the cause.
    """
