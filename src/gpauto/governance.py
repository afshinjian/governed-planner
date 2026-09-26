"""OWNER decisions, stage outcome, and the two governance-event cases.

Design basis: AP-03 §2.7 (governance-event and OWNER entities), §11.1 (two types,
produced-by), §11.2 (classification of the OWNER acts), §12 (refusal / violation /
ambiguity domain, `GE-1`…`GE-4`), §13 (`SO-1`…`SO-5`), §16.6; `AP03-I25`, `AP03-I26`,
`AP03-I28`, `AP03-I29`, `AP03-I31`, `AP03-I34`.

**`OwnerAuthorization` and `OwnerDecision` are two types, joined by *produced-by*.**
Not one type with a kind attribute, because the conversion acceptance → authorization
would then be an attribute edit — the central thing to prevent. Not a subtype, because
subtyping makes an authorization **substitutable wherever a decision is accepted**,
including the acceptance slot; the collapse would be structural rather than
accidental. The produced-by relation is required, because the alternative reading
detaches authority from the OWNER act that created it (`AP03-I25`).

**Acceptance settles the past and authorizes nothing.** There is no derivation
relation from a `StageOutcome` or an `OwnerDecision` to an `OwnerAuthorization`, and
none may be added (`SO-1`). The interval between acceptance and the next authorization
is modelled by **absence** — no live authorization — and not by a "pending next stage"
entity, because an entity existing in the interval is an entity a later phase can act
on (`SO-3`).

**A `StageOutcome` is OWNER-established only.** `established_by` is typed
`OwnerDecisionId`, so a worker verdict, a closure assessment, a structural halt or
gate arrival cannot establish one — not as a refused value, but as an unexpressible
one (`SO-4`, `AP03-I34`). Gate arrival creates nothing and is not an outcome
(`AP03-I31`).

**Case A and Case B never collapse** (`AP03-I28`). A `Refusal` says the effect **did
not occur** — GP-AUTO controlled the point of action, so refusal and prevention
coincide. An `EnvelopeViolation` says the effect **already exists** and was **not
prevented**, and names the violating activation and the boundary crossed. Describing a
refusal as a detection understates; the reverse overstates. Each carries its case as a
`Literal` with no default, so the marker is **neither optional nor inferable**
(`GE-2`), and `EnvelopeViolation` carries an explicit not-prevented marker for the same
reason.

**The five governance facts are five classes, never one class with a kind attribute.**
`Refusal` and `EnvelopeViolation` are here; `AuthorityAmbiguity` is in
`authorization.py` because it arises inside the authorization domain before any
envelope exists; `CandidateExclusion` is there for the same reason; and
`UnaccountedMutation` is in `repository.py` because it is a statement about repository
state. They are not mutually exclusive: one occurrence may require several records,
and a known-producer unaccounted mutation is recorded as **both** an
`UnaccountedMutation` and an `EnvelopeViolation` (`GE-4`).

**No record recommends a disposition** (`GE-1`). There is no severity, rank, priority,
preference or recommendation field on any structure in this module, and
`tests_gpauto` asserts the absence structurally rather than by reading. A record
states facts and asks.

**Absence of a record is not evidence that nothing occurred** (`T-23`, `AP03-I29`,
`VP11-5`). The domain records only what was observed and models no assertion of
completeness; no structure here may be read as such a claim.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from gpauto.absence import Determined, KnownAbsent, Present
from gpauto.bounds import ActionClass
from gpauto.coordination_identity import HaltOccurrenceId
from gpauto.identity import (
    AuthorityEnvelopeId,
    EnvelopeViolationId,
    FindingId,
    GovernedStageId,
    OwnerAuthorizationId,
    OwnerDecisionId,
    RefusalId,
    RemediationObligationId,
    StageOutcomeId,
    WorkerActivationId,
)
from gpauto.repository import ClassificationContext
from gpauto.schema import DomainEntity, DomainValue
from gpauto.vocabulary import (
    GitActionClass,
    GovernanceCase,
    OwnerDecisionKind,
    Role,
    StageOutcomeDisposition,
)

type ObservedActionClass = ActionClass | GitActionClass
"""An act as recorded: a general action class, or one from the **complete observable**
Git vocabulary — so an act that could never have been authorized is still recordable
(AP-03 §4.8.1)."""


class AuthorizingDecision(DomainValue):
    """An OWNER act that **produces** an `OwnerAuthorization` (AP-03 §11.2).

    Stage-entry authorization, next-stage authorization, scope change and authority
    expansion. A scope change alters `RA-03` and an authority expansion alters `RA-07`,
    and neither may be amended in place — so each takes effect as a **new**
    authorization, with the prior one invalidated by binding change.

    `produced_authorization` is `Present` here, not `Determined`: these acts are
    classified by AP-03 §11.2 as producing one, so a form of them that produced none
    would be a different act wearing their name.
    """

    kind: Literal[
        OwnerDecisionKind.STAGE_ENTRY_AUTHORIZATION,
        OwnerDecisionKind.NEXT_STAGE_AUTHORIZATION,
        OwnerDecisionKind.SCOPE_CHANGE,
        OwnerDecisionKind.AUTHORITY_EXPANSION,
    ]
    produced_authorization: Present[OwnerAuthorizationId]
    corrects: Determined[OwnerDecisionId]


class DisputeResolutionDecision(DomainValue):
    """F-4: annotate one frozen-set member (ST01C-2)."""

    kind: Literal[OwnerDecisionKind.FINDING_DISPUTE]
    member: FindingId
    produced_authorization: KnownAbsent
    corrects: Determined[OwnerDecisionId]


class ObligationExtinguishingDecision(DomainValue):
    """F-5: name the one obligation waived or deferred."""

    kind: Literal[OwnerDecisionKind.WAIVER, OwnerDecisionKind.DEFERRAL]
    obligation: RemediationObligationId
    produced_authorization: KnownAbsent
    corrects: Determined[OwnerDecisionId]


class ObligationChangeDecision(DomainValue):
    """F-6 / O6: verbatim replacement content; no correction chain (O6C-11)."""

    kind: Literal[OwnerDecisionKind.OBLIGATION_CHANGE]
    obligation: RemediationObligationId
    replacement_requirement: str = Field(min_length=1)
    produced_authorization: KnownAbsent


class RevocationDecision(DomainValue):
    """F-7: revoke an authorization instance, never its record."""

    kind: Literal[OwnerDecisionKind.REVOCATION]
    revoked: OwnerAuthorizationId
    produced_authorization: KnownAbsent
    corrects: Determined[OwnerDecisionId]


class RefusalResolutionDecision(DomainValue):
    """F-8: resolve the exact halt occurrence; this does not settle."""

    kind: Literal[OwnerDecisionKind.REFUSAL_RESOLUTION]
    halt_occurrence: HaltOccurrenceId
    produced_authorization: KnownAbsent
    corrects: Determined[OwnerDecisionId]


class StageOutcomeDecision(DomainValue):
    """F-9: one general outcome act carrying its context and explicit value."""

    kind: Literal[OwnerDecisionKind.STAGE_OUTCOME]
    context: ClassificationContext
    outcome: StageOutcomeDisposition
    produced_authorization: KnownAbsent
    corrects: Determined[OwnerDecisionId]


class ExceptionalRecoveryDecision(DomainValue):
    """F-10: non-settling restart/override; produces authority only if determined."""

    kind: Literal[OwnerDecisionKind.EXCEPTIONAL_RECOVERY]
    produced_authorization: Determined[OwnerAuthorizationId]
    corrects: Determined[OwnerDecisionId]


type DecisionAct = (
    AuthorizingDecision
    | DisputeResolutionDecision
    | ObligationExtinguishingDecision
    | ObligationChangeDecision
    | RevocationDecision
    | RefusalResolutionDecision
    | StageOutcomeDecision
    | ExceptionalRecoveryDecision
)
"""ST01C-2: ten normative cases, eight concrete variants, twelve decision kinds.

SC01_V14_IMPLEMENTATION_CLARIFICATION_ONLY: self-reference is rejected at the
RC-13 persistence boundary, not by construction-time cross-field validation.
"""


class OwnerDecision(DomainEntity):
    """The governance act record (AP-03 §2.7, §11.2).

    `act` carries the kind together with the produced-by relation, because AP-03 §11.2
    fixes them jointly: every `OwnerAuthorization` is produced by a decision, not every
    decision produces one, and **which** decisions may is not a free choice. Carrying
    the two as independent fields let them disagree, which is how a stage-outcome
    acceptance could be recorded as producing new authority.

    The entity is still one entity with kinds, never one type per kind (AP-03 §2.7),
    and it is still a separate type from `OwnerAuthorization`, joined by *produced-by*
    and never by subtyping (`AP03-I25`).
    """

    identity: OwnerDecisionId
    stage: GovernedStageId
    act: DecisionAct


class StageOutcome(DomainEntity):
    """The recorded terminal disposition of a `GovernedStage` (AP-03 §13).

    Establishes the *consumed* disposition of that stage's authorization, and with it
    the end of every envelope derived from it. Consumption is terminal and no revival
    operation exists anywhere in this package (`AP03-I26`).

    What survives a consumed authorization is stated in `SO-5` and is not undone here:
    effects, artifact productions and their content, findings, frozen sets, assessments,
    governance-event records — and the consumed `OwnerAuthorization` instance itself —
    are historical facts, not authority, and they persist (`AP03-I35`).
    """

    identity: StageOutcomeId
    disposition: StageOutcomeDisposition
    established_by: OwnerDecisionId


class Refusal(DomainEntity):
    """Case A: the effect **did not occur** (`P-05a`, AP-03 §12).

    `resolved_root` and `envelope` are `Determined` — present where one exists,
    established absent otherwise — because a refusal for missing authority legitimately
    has no root, and a refusal before derivation legitimately has no envelope. Neither
    is *unobserved*: GP-AUTO controlled the point of action, so it knows which.
    """

    identity: RefusalId
    case: Literal[GovernanceCase.CASE_A]
    stage: GovernedStageId
    branch: str
    role: Determined[Role]
    resolved_root: Determined[OwnerAuthorizationId]
    envelope: Determined[AuthorityEnvelopeId]
    condition: str
    observed_value: str
    bound_value: str
    refused_action_class: ObservedActionClass


class EnvelopeViolation(DomainEntity):
    """Case B: the effect **already exists** and was **not prevented** (`P-05b`).

    `not_prevented` is `Literal[True]` with no default, so the marker must be stated
    at construction and can never be omitted or inferred (`GE-2`). A structure that
    could quietly default it would let an honest non-prevention read as a block.

    `unexplained_portion` is the portion of repository state the expected current
    authorized state does not explain. The expected state itself is a derivation and is
    not carried (`AP03-I09`).
    """

    identity: EnvelopeViolationId
    case: Literal[GovernanceCase.CASE_B]
    envelope: AuthorityEnvelopeId
    resolved_root: OwnerAuthorizationId
    stage: GovernedStageId
    role: Role
    violating_activation: WorkerActivationId
    action_class: ObservedActionClass
    boundary_crossed: str
    unexplained_portion: tuple[str, ...]
    not_prevented: Literal[True]
