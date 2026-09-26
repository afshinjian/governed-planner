"""The authorization domain: the single root of authority, and how it is seen.

Design basis: AP-03 §2.2 (authorization entities), §4.1 (`OwnerAuthorization`,
constitution, dispositions), §4.2 (authorization identity), §4.3
(`AuthorityBearingContent`), §4.4 (content equivalence), §4.5 (root candidate model),
§4.6, §4.7 (ambiguity), §16.2; `AP03-I01`…`AP03-I06`, `AP03-I33`, `AP03-I35`.

**GP-AUTO never sees an `OwnerAuthorization` directly; it sees records.** An instance
is *constituted* by the class of valid records that share one `RA-00` identity and are
mutually content-equivalent. Constitution turns on validity and equivalence alone —
never on eligibility — which is why an instance persists under every disposition and
every historical reference to it stays valid (`AP03-I35`). A record is **never an
authority source**: authority is borne by the constituted instance, and where records
under one identity conflict, *no instance is constituted at all*, which is why the
outcome is ambiguity rather than a choice between two authorizations (`AP03-I33`).

**What a disposition may not be established by is carried structurally.** AP-03 §4.1
says the domain records which liveness-relevant facts hold *and what established
each*. Here each disposition is its own value type carrying its own establisher, so
`CONSUMED` cannot be recorded without a `StageOutcome`, `REVOKED` cannot be recorded
without an `OwnerDecision`, and `SUSPENDED` cannot be recorded without one of the four
unresolved governance events. There is deliberately **no `SUPERSEDED`**: supersession
is expressed only by explicit revocation or binding change, never inferred from
recency, arrival order or the existence of a later record (`AP03-I05`).

**The authority-bearing projection is enumerated and closed** (AP-03 §4.3 rule 1).
Content AP-03 does not place in one of its two columns is, fail-closed,
authority-bearing. `AuthorityBearingContent` therefore carries exactly the left-hand
column and nothing else — in particular no presentation or formatting, no storage
location, **no arrival, insertion or discovery order, no timestamp or clock-derived
value of any kind**, no prose rationale, and not the record's own instance identity.
The exclusion of timestamps and arrival order is `P-16` and `D-AP02-01(a)`, not a
convenience: nothing in the right-hand column may enter a comparison, an ordering or
a tie-break, and the surest way to keep it out of one is for it not to exist.

**Nothing here resolves anything.** AP-03 §4.4 expressly does not design canonical
serialization, digest, normalization or any comparison algorithm, and §4.5 expressly
provides no ordering, ranking, merge, union, intersection, reconciliation or any
operation taking a candidate set and returning one — *the absence is the model*.
`RootResolution` is the **record of a resolution's outcome**; the resolution itself is
`GP-AUTO-ST-06`'s. A later phase needing a selection operation is proposing an
authority expansion, not a representation.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from gpauto.absence import Determined
from gpauto.bounds import AuthorityBounds
from gpauto.identity import (
    AuthorityAmbiguityId,
    AuthorizationRecordId,
    BaselineIdentityId,
    CandidateExclusionId,
    EnvelopeViolationId,
    GovernedStageId,
    OwnerAuthorizationId,
    OwnerDecisionId,
    ProjectId,
    RefusalId,
    RepositoryBoundaryId,
    RootResolutionId,
    StageContractId,
    StageOutcomeId,
    UnaccountedMutationId,
)
from gpauto.schema import DomainEntity, DomainValue
from gpauto.vocabulary import (
    AmbiguityForm,
    AuthorityBearingContentClass,
    AuthorizationDisposition,
    BoundedPreflightPermission,
    RaAttribute,
    Role,
    RootResolutionOutcome,
)


class OwnerHumanLabel(DomainValue):
    """`RA-08`: a label, **never an identity claim** (`DM-08`, `F4`, `AP03-I29`).

    It asserts no authenticated human identity, no authorship and no non-repudiation.
    Naming it a label in the type is the whole of the guarantee.
    """

    label: str


class LiveDisposition(DomainValue):
    """None of consumed, revoked or suspended holds (AP-03 §4.1)."""

    disposition: Literal[AuthorizationDisposition.LIVE] = AuthorizationDisposition.LIVE


class ConsumedDisposition(DomainValue):
    """Established by a `StageOutcome`, and by nothing else (`V-01`, `AP03-I34`)."""

    disposition: Literal[AuthorizationDisposition.CONSUMED] = AuthorizationDisposition.CONSUMED
    established_by_outcome: StageOutcomeId


class RevokedDisposition(DomainValue):
    """Established by an `OwnerDecision` of kind revocation, and by nothing else (`V-09`)."""

    disposition: Literal[AuthorizationDisposition.REVOKED] = AuthorizationDisposition.REVOKED
    established_by_decision: OwnerDecisionId


class SuspendedDisposition(DomainValue):
    """Established by an unresolved governance event (`V-08`).

    **Suspended is not consumed.** A stage halted on a refusal and awaiting OWNER
    resolution has no `StageOutcome`; merging the two would either consume an
    authorization the OWNER never settled, or leave a settled stage's authorization
    usable.
    """

    disposition: Literal[AuthorizationDisposition.SUSPENDED] = AuthorizationDisposition.SUSPENDED
    established_by_event: RefusalId | EnvelopeViolationId | UnaccountedMutationId


type LivenessFact = (
    LiveDisposition | ConsumedDisposition | RevokedDisposition | SuspendedDisposition
)
"""A statement about **governing capacity, not existence** (`AP03-I35`)."""


class AuthorityBearingContent(DomainValue):
    """The closed, enumerated projection of an `AuthorizationRecord` (AP-03 §4.3).

    This is what content equivalence compares — a value-level projection, not an
    entity. `RA-00` is the identity the projection is compared *within* and is
    therefore not one of its fields.
    """

    project: ProjectId
    stage: GovernedStageId
    contract: StageContractId
    repository_boundary: RepositoryBoundaryId
    baseline: BaselineIdentityId
    authorized_roles: tuple[Role, ...]
    authority_ceiling: AuthorityBounds
    owner_human_label_present: bool
    preflight_permission: BoundedPreflightPermission
    liveness: LivenessFact


class AuthorizationRecord(DomainEntity):
    """One visible assertion of an authorization (AP-03 §2.2).

    Required because AP-02 needs *one identity whose visible records conflict* to be
    representable and halting — and a single entity cannot disagree with itself.
    Persistence must surface **every** visible record sharing one identity; collapsing
    or deduplicating them is semantic authority a store does not have (`AP03-I27`).
    """

    identity: AuthorizationRecordId
    authorization_identity: OwnerAuthorizationId
    content: AuthorityBearingContent


class OwnerAuthorization(DomainEntity):
    """The single root of all authority inside one governed stage (`P-01`, AP-03 §4.1).

    Carries `RA-00`…`RA-09` as one indivisible whole, and is constituted by one or
    more mutually content-equivalent valid records under one identity.

    **Not carried, and not addable by a later phase** (AP-03 §4.1): any expiry, TTL,
    wall-clock bound, issuance deadline or freshness attribute; any signature or key
    material; any reference to the `EntryStateBoundary` — non-circularity, `P-09a`;
    any provider identity; any prompt or instruction text. Their absence is asserted
    structurally by `tests_gpauto`, because a comment claiming an absence is not
    evidence of one (`VP11-4`).
    """

    identity: OwnerAuthorizationId
    project: ProjectId
    stage: GovernedStageId
    contract: StageContractId
    repository_boundary: RepositoryBoundaryId
    baseline: BaselineIdentityId
    authorized_roles: tuple[Role, ...]
    authority_ceiling: AuthorityBounds
    owner_human_label: OwnerHumanLabel
    preflight_permission: BoundedPreflightPermission
    liveness: LivenessFact
    constituting_records: Annotated[tuple[AuthorizationRecordId, ...], Field(min_length=1)]


class CandidateExclusion(DomainEntity):
    """A record excluded **because it is invalid** (AP-03 §4.5, `AP03-I06`).

    Not a Refusal, and the difference is provable rather than stipulated: one invalid
    candidate alongside one valid eligible instance yields a recorded exclusion **and**
    a resolved root — the stage proceeds, and the rejection is retained as evidence
    that something invalid was seen and refused a role. Treating any invalid candidate
    as an independent halt would let an unrelated malformed record stop a correctly
    authorized stage.

    It carries no reason to prefer the remaining candidate, because there is no
    preference operation to feed (`AP03-I05`).
    """

    identity: CandidateExclusionId
    failing_attribute: RaAttribute


class DistinctMultiplicityForm(DomainValue):
    """Two or more distinct eligible live identities (`V-17a`).

    Names **every** competing identity. It names no winner: GP-AUTO refuses to resolve
    what the OWNER must resolve, and a record that recommended one would be resolving
    it (`GE-1`).
    """

    form: Literal[AmbiguityForm.DISTINCT_MULTIPLICITY] = AmbiguityForm.DISTINCT_MULTIPLICITY
    competing_identities: Annotated[tuple[OwnerAuthorizationId, ...], Field(min_length=2)]


class SameIdentityConflictForm(DomainValue):
    """One eligible identity whose visible records are not content-equivalent (`V-17b`).

    Names the identity and **the authority-bearing content classes that disagree** —
    never a winner, never a merged view. Under this form *no instance is constituted*
    (`AP03-I33`), so there are not two authorizations to choose between.
    """

    form: Literal[AmbiguityForm.SAME_IDENTITY_CONFLICT] = AmbiguityForm.SAME_IDENTITY_CONFLICT
    conflicting_identity: OwnerAuthorizationId
    disagreeing_content_classes: Annotated[
        tuple[AuthorityBearingContentClass, ...], Field(min_length=1)
    ]


class AuthorityAmbiguity(DomainEntity):
    """One entity, two forms (AP-03 §2.2, §4.6, §4.7).

    It arises **before any envelope exists** and therefore carries no envelope
    identity — a structural reason it cannot be a kind of `EnvelopeViolation`. It is
    also not a Refusal for *missing* authority: zero eligible is a different fact from
    competing authority, and collapsing them would leave the OWNER unable to see which.
    """

    identity: AuthorityAmbiguityId
    stage: GovernedStageId
    form: DistinctMultiplicityForm | SameIdentityConflictForm


class RootResolution(DomainEntity):
    """The record of one eligibility determination (AP-03 §4.5, §16.2).

    A resolution **ranges over things that already exist**: it does not bring
    authorizations into being and does not end them. It records the candidates
    considered, the exclusions made, and the outcome — and the outcome is determined
    solely by the eligible candidates remaining after exclusion. Exclusion never
    manufactures a resolution where no valid candidate remains (`AP03-I06`).

    `resolved_root` names an **instance**, never a record identity (`AP03-I33`).
    """

    identity: RootResolutionId
    stage: GovernedStageId
    candidates: tuple[AuthorizationRecordId, ...]
    exclusions: tuple[CandidateExclusionId, ...]
    outcome: RootResolutionOutcome
    resolved_root: Determined[OwnerAuthorizationId]
    ambiguity: Determined[AuthorityAmbiguityId]
