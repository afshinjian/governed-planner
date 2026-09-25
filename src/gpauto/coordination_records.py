"""The stored record shapes for `RC-14` … `RC-41` that ST-01's entities do not already give.

Design basis: AP-11 ST-03 store-realization amendment §6 (`RS11-14`…`RS11-41`), §4
(`SRB11-4`, `SRB11-7`), as modified by the ST-03 follow-on amendment §3 (`RS11-14`,
`RS11-34`, `SRF11-1`); AP-07 root-resolution clarification `RO7A-1`…`RO7A-9`; AP-07 §3.2,
§9–§14, §19.

**Where ST-01 already is the record, it is the record.** `AuthorityAmbiguity` (`RC-16`),
`UnaccountedMutation` (`RC-24`), `FrozenFindingSet` (`RC-26`), `RemediationObligation`
(`RC-27`), `StageOutcome` (`RC-36`) and the ingest classes are stored exactly as ST-01
defines them, and are not wrapped or re-declared here (`SRB11-4`). Where a frozen rule adds
a binding ST-01's entity does not carry — a `CO-5` occurrence binding, `RS7-1`'s root,
`MC-15`'s derivation key, `FZ-6`'s content binding, an append-only predecessor — the
record **contains** the ST-01 entity and adds only that binding.

**Three ST-01 fields are never persisted, and no replacement is invented** (`SRB11-7`;
follow-on §2). `WorkerActivation.completed`, `ActivationEffect.within_producing_envelope`
and `RootResolution.outcome` / `resolved_root` / `ambiguity` are each established after
their record's creating act, so a create-only record cannot hold them. Their facts live in
the authoritative decomposition instead: completion in the `C4` M3 entry and the `RC-39`
adoption record; envelope conformance per effect in `RC-39` (`RS7-10`); and a resolution's
result on its completing M1 entry (`RO7A-2`…`RO7A-5`). That is why `WorkerActivationRecord`
and `ActivationEffectRecord` restate ST-01's fields rather than containing the entity: the
entity carries the excluded field, and containing it would persist it.

**`RootResolutionRecord` is the `A1` occurrence and nothing later** (`RO7A-1`). It carries
the `MC-17`(i) attempt anchor and the candidate set it ranges over, and **no** outcome,
resolved root, ambiguity, status or current field. ST-01's `exclusions` relation is not a
field here: each `RC-15` exclusion is made while the resolution is open and names the
resolution as its parent (AP-04 §3.2), so the relation is realized by those append-only
records, never by a later write to the occurrence.

**The resolution result is carried by the completing M1 entry, and nowhere else**
(`RO7A-2`…`RO7A-5`, `AP11-I73`). `M1PositionEntry.result` is one of four values, so at most
one binding is expressible at all; which one an entry may carry is fixed by its edge in the
store's schema — `A2` the resolved-root **instance**, `A3` a reference to the `RC-30`
`Refusal`, `A4` a reference to the `RC-16` `AuthorityAmbiguity`, and every other entry the
explicit `NoResolutionResult`, never an implicit null (`CO-14`). The bound record is
referenced, never copied. Only M1 entries have a result field at all.

**No record class here has a behaviour.** These are shapes. When a record is created,
which records form one transition's unit, and what is derived from them are the owning
stages' (`SRB11-5`, `SRB11-11`).
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Literal

from pydantic import Field

from gpauto.absence import Determined, Perhaps
from gpauto.activation import InputPackage, ObjectiveProductionReference, ProviderAssignment
from gpauto.authorization import (
    CandidateExclusion,
    ConsumedDisposition,
    RevokedDisposition,
    SuspendedDisposition,
)
from gpauto.coordination_identity import (
    AuditEntryId,
    ConformanceDeterminationId,
    CycleOccurrenceId,
    DispatchRecordId,
    DispositionRecordId,
    ExecutionObservationId,
    GovernanceEventResolutionId,
    HaltOccurrenceId,
    M1PositionEntryId,
    M2PositionEntryId,
    M3PositionEntryId,
    M4PositionEntryId,
    OutcomeIngestionRecordId,
)
from gpauto.coordination_vocabulary import (
    AuditEntryClass,
    ClosureVerdictValue,
    ConformanceDeterminationClass,
    DeclaredItemClass,
    DiscoveryVerdict,
    M1Edge,
    M1Position,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
    M4Edge,
    Machine,
    ObligationDisposition,
    Quiescence,
    StructuralConformanceResult,
    TerminationValue,
    TimeoutDisposition,
)
from gpauto.envelope import AuthorityEnvelope
from gpauto.evidence import (
    ArtifactProduction,
    ObjectiveArtifactProduction,
    WorkerAuthoredArtifactProduction,
)
from gpauto.governance import EnvelopeViolation, Refusal
from gpauto.identity import (
    ActivationEffectId,
    AuthorityAmbiguityId,
    AuthorityEnvelopeId,
    AuthorizationRecordId,
    CandidateExclusionId,
    EnvelopeViolationId,
    FindingId,
    GovernedStageId,
    InputPackageId,
    OwnerAuthorizationId,
    OwnerDecisionId,
    ProjectId,
    RefusalId,
    RemediationObligationId,
    RootResolutionId,
    UnaccountedMutationId,
    WorkerActivationId,
)
from gpauto.repository import ClassificationContext, EntryStateBoundary
from gpauto.review import ClosureAssessment, Finding, PostFreezeCandidate
from gpauto.schema import DomainModel, DomainValue
from gpauto.vocabulary import AuthorizationDisposition, Provenance, Role


class StoredRecord(DomainModel):
    """The shape of a stored coordination record (AP-07 §3.2).

    A record is a **representation** of an AP-03 entity, dependent, relation or value, or
    of an AP-04/AP-05/AP-06 fact over one — never a new domain entity (`RC-5`,
    `AP07-I04`). That is why these shapes are not `DomainEntity`s: ST-01's entity
    inventory is AP-03's, and stays exactly AP-03's. Never annotate a field with this base.
    """


# --- RC-14 / RC-15: root resolution occurrence and its exclusions ------------------


class RootResolutionRecord(StoredRecord):
    """`RC-14`: the root-resolution occurrence minted at `A1`, write-once (`RO7A-1`).

    `project`, `stage` and `predecessor_terminal_entry` are the `MC-17`(i) attempt
    anchor: the predecessor is the prior attempt's terminal M1 entry, or its affirmative
    absence for the first attempt (`CO-14`). An open resolution — this record, its `A1`
    entry and its exclusions, with no completing entry — is a complete stored state.
    """

    identity: RootResolutionId
    project: ProjectId
    stage: GovernedStageId
    predecessor_terminal_entry: Determined[M1PositionEntryId]
    candidates: tuple[AuthorizationRecordId, ...]


class CandidateExclusionRecord(StoredRecord):
    """`RC-15`: append-only. The exclusion's own identity is ST-01's pair (resolution,
    record); `predecessor` is the previous exclusion of the same resolution, or its
    affirmative absence for the first (`PA-04`)."""

    exclusion: CandidateExclusion
    predecessor: Determined[CandidateExclusionId]


# --- RC-17 / RC-18 / RC-19 / RC-20 -------------------------------------------------


class EntryStateBoundaryRecord(StoredRecord):
    """`RC-17`: the fixed observation, and the resolved root it was observed for, which
    the store keys uniquely — a second boundary per root is inexpressible (`RS7-1`)."""

    boundary: EntryStateBoundary
    resolved_root: OwnerAuthorizationId


class AuthorityEnvelopeRecord(StoredRecord):
    """`RC-18`: the envelope, its `CO-5` occurrence binding, and the `MC-15` derivation
    key — subject (the envelope's root), predecessor M2 entry, target step, role."""

    envelope: AuthorityEnvelope
    cycle_occurrence: Determined[CycleOccurrenceId]
    predecessor_entry: M2PositionEntryId
    target_state: M2Position


class SessionAnnotation(DomainValue):
    """The session identifier — a zero-authority audit annotation (`MH-11`, `MH-12`)."""

    session_reference: str


class WorkerActivationRecord(StoredRecord):
    """`RC-19`: ST-01 `WorkerActivation` **without** `completed` (`PFC-ST01-1`), with the
    `MH-11` bindings. Provider and session appear on this class and on no other."""

    identity: WorkerActivationId
    envelope: AuthorityEnvelopeId
    role: Role
    input_package: InputPackageId
    provider: Perhaps[ProviderAssignment]
    session: Perhaps[SessionAnnotation]
    stage: GovernedStageId
    branch: str
    resolved_root: OwnerAuthorizationId
    cycle_occurrence: Determined[CycleOccurrenceId]


class InputPackageRecord(StoredRecord):
    """`RC-20`: the package and its `CO-5` occurrence binding. Its basis references are
    ST-01's, whose domain structurally excludes worker-authored productions (`AT-8`)."""

    package: InputPackage
    cycle_occurrence: Determined[CycleOccurrenceId]


# --- RC-22 / RC-23 -----------------------------------------------------------------


class ArtifactProductionRecord(StoredRecord):
    """`RC-22`: one production occurrence, never merged by content (`AT-3`, `ID-14`)."""

    production: ArtifactProduction[Provenance]
    cycle_occurrence: Determined[CycleOccurrenceId]


class ActivationEffectRecord(StoredRecord):
    """`RC-23`: ST-01 `ActivationEffect` **without** `within_producing_envelope`
    (`PFC-ST01-3`). Envelope conformance is an `RC-39` determination (`RS7-10`)."""

    identity: ActivationEffectId
    observed_state: tuple[str, ...]
    cycle_occurrence: Determined[CycleOccurrenceId]


# --- RC-25 / RC-28 / RC-29 / RC-30 -------------------------------------------------


class FindingRecord(StoredRecord):
    """`RC-25`: a finding and its `FZ-6` content binding to the adopted outcome's
    objective production. Creatable only with its set membership, in one unit (`WP-19`)."""

    finding: Finding
    content_binding: ObjectiveProductionReference


class ClosureAssessmentRecord(StoredRecord):
    """`RC-28`: one per (finding, closure activation), verdict fixed at assessment."""

    assessment: ClosureAssessment
    verdict: ClosureVerdictValue
    cycle_occurrence: Determined[CycleOccurrenceId]


class PostFreezeCandidateRecord(StoredRecord):
    """`RC-29`: bound to its occurrence, with no admitting relation to membership."""

    candidate: PostFreezeCandidate
    cycle_occurrence: Determined[CycleOccurrenceId]


class RefusalRecord(StoredRecord):
    """`RC-30`, case A. Two record classes, never one with a kind attribute (`GH-1`)."""

    refusal: Refusal
    cycle_occurrence: Determined[CycleOccurrenceId]


class EnvelopeViolationRecord(StoredRecord):
    """`RC-30`, case B, carrying the not-prevented marker (`GH-2`)."""

    violation: EnvelopeViolation
    cycle_occurrence: Determined[CycleOccurrenceId]


# --- RC-31 / RC-32 / RC-33 ---------------------------------------------------------

type HaltEvent = RefusalId | EnvelopeViolationId | UnaccountedMutationId
"""The governance events a `B9` halt occurs on (AP-04 §4.2)."""


class HaltOccurrence(StoredRecord):
    """`RC-31`: the event, its exact M2 source position, and at `S6`/`S7` its cycle
    occurrence (`GH-3`). Each halt is its own occurrence (`GH-4`)."""

    identity: HaltOccurrenceId
    event: HaltEvent
    source_state: M2Position
    cycle_occurrence: Determined[CycleOccurrenceId]


class GovernanceEventResolution(StoredRecord):
    """`RC-32`: names the halt occurrence it resolves and the `RC-13` decision it records."""

    identity: GovernanceEventResolutionId
    halt_occurrence: HaltOccurrenceId
    decision: OwnerDecisionId


class CycleOccurrence(StoredRecord):
    """`RC-33`: established on entry to `S6` by `B6a` or `B15`, keyed on the pre-existing
    (predecessor entry, `S6`) (`MC-16`). Envelope and activation are carried only where
    they exist, with affirmative absence otherwise (`CO-2`, `CO-14`)."""

    identity: CycleOccurrenceId
    establishing_edge: Literal[M2Edge.B6a, M2Edge.B15]
    predecessor_entry: M2PositionEntryId
    target_state: Literal[M2Position.S6_REMEDIATION_ACTIVE]
    predecessor_closure_activation: Determined[WorkerActivationId]
    envelope: Determined[AuthorityEnvelopeId]
    activation: Determined[WorkerActivationId]


# --- RC-34: position entries -------------------------------------------------------


class ResolvedRootResult(DomainValue):
    """The `A2` entry's binding: the resolved-root **instance** identity (`RO7A-3`)."""

    resolved_root: OwnerAuthorizationId


class RefusalResult(DomainValue):
    """The `A3` entry's binding: a reference to the `RC-30` `Refusal` (`RO7A-4`)."""

    refusal: RefusalId


class AmbiguityResult(DomainValue):
    """The `A4` entry's binding: a reference to the `RC-16` `AuthorityAmbiguity`."""

    ambiguity: AuthorityAmbiguityId


class NoResolutionResult(DomainValue):
    """Every other M1 entry: the affirmative absence of a binding (`RO7A-5`, `CO-14`)."""


type ResolutionResult = ResolvedRootResult | RefusalResult | AmbiguityResult | NoResolutionResult


class M1PositionEntry(StoredRecord):
    """`RC-34`, M1: append-only, on its `RootResolution` occurrence."""

    MACHINE: ClassVar[Machine] = Machine.M1

    identity: M1PositionEntryId
    state: M1Position
    edge: M1Edge
    predecessor: Determined[M1PositionEntryId]
    result: ResolutionResult


class M2PositionEntry(StoredRecord):
    """`RC-34`, M2: append-only, on its classification context; `cycle_occurrence` at
    `S6`/`S7`, `Determined`."""

    MACHINE: ClassVar[Machine] = Machine.M2

    identity: M2PositionEntryId
    state: M2Position
    edge: M2Edge
    predecessor: Determined[M2PositionEntryId]
    cycle_occurrence: Determined[CycleOccurrenceId]


class M3PositionEntry(StoredRecord):
    """`RC-34`, M3: append-only, on its envelope."""

    MACHINE: ClassVar[Machine] = Machine.M3

    identity: M3PositionEntryId
    state: M3Position
    edge: M3Edge
    predecessor: Determined[M3PositionEntryId]


class M4PositionEntry(StoredRecord):
    """`RC-34`, M4: append-only, on its authorization instance. The state value is ST-01's
    `AuthorizationDisposition`; what established it is an `RC-35` record."""

    MACHINE: ClassVar[Machine] = Machine.M4

    identity: M4PositionEntryId
    state: AuthorizationDisposition
    edge: M4Edge
    predecessor: Determined[M4PositionEntryId]


# --- RC-35 --------------------------------------------------------------------------

type EstablishedDisposition = ConsumedDisposition | RevokedDisposition | SuspendedDisposition
"""ST-01's disposition values that carry an establisher. `LiveDisposition` is excluded:
`LIVE` is the absence of an establishing record (`WP-9`), never a record."""


class DispositionEstablishingRecord(StoredRecord):
    """`RC-35`: what established consumption, revocation or suspension (`WP-9`).

    The value is ST-01's disposition type, carrying its establisher. `LIVE` is the
    absence of any such record and is never itself recorded.
    """

    identity: DispositionRecordId
    disposition: EstablishedDisposition


# --- RC-37: the durable handoff ----------------------------------------------------


class CorrelationSet(DomainValue):
    """The complete `MC-9` correlation reference set, carried by both handoff records."""

    root: OwnerAuthorizationId
    stage: GovernedStageId
    context: ClassificationContext
    step_state: M2Position
    cycle_occurrence: Determined[CycleOccurrenceId]
    envelope: AuthorityEnvelopeId
    activation: Determined[WorkerActivationId]


class DispatchRecord(StoredRecord):
    """`RC-37` dispatch — the `MH-9` set; unique on the envelope (`MH-7`)."""

    identity: DispatchRecordId
    correlation: CorrelationSet
    package: InputPackageId
    role: Role
    branch: str
    predecessor_entry: M2PositionEntryId


class DiscoveryVerdictItem(DomainValue):
    """`CA-7`."""

    item_class: Literal[DeclaredItemClass.DISCOVERY_VERDICT] = DeclaredItemClass.DISCOVERY_VERDICT
    verdict: DiscoveryVerdict


class FindingItem(DomainValue):
    """`CA-8`."""

    item_class: Literal[DeclaredItemClass.FINDING_ITEM] = DeclaredItemClass.FINDING_ITEM


class ObligationDispositionItem(DomainValue):
    """`CA-10`, with its `CA-11` referent: the objective production that is its change
    evidence."""

    item_class: Literal[DeclaredItemClass.OBLIGATION_DISPOSITION_ITEM] = (
        DeclaredItemClass.OBLIGATION_DISPOSITION_ITEM
    )
    obligation: RemediationObligationId
    disposition: ObligationDisposition
    change_evidence: ObjectiveProductionReference


class MemberClosureResultItem(DomainValue):
    """`CA-12`: a per-member closure result, carrying the `IV11-5` verdict."""

    item_class: Literal[DeclaredItemClass.MEMBER_CLOSURE_RESULT] = (
        DeclaredItemClass.MEMBER_CLOSURE_RESULT
    )
    member: FindingId
    verdict: ClosureVerdictValue


class DisputeItem(DomainValue):
    """`CA-13`."""

    item_class: Literal[DeclaredItemClass.DISPUTE_ITEM] = DeclaredItemClass.DISPUTE_ITEM


class PostFreezeCandidateItem(DomainValue):
    """`CA-14`."""

    item_class: Literal[DeclaredItemClass.POST_FREEZE_CANDIDATE_ITEM] = (
        DeclaredItemClass.POST_FREEZE_CANDIDATE_ITEM
    )


class WorkerRefusalOrExpansionItem(DomainValue):
    """`CA-15`."""

    item_class: Literal[DeclaredItemClass.WORKER_REFUSAL_OR_EXPANSION_REQUEST] = (
        DeclaredItemClass.WORKER_REFUSAL_OR_EXPANSION_REQUEST
    )


type DeclaredItem = (
    DiscoveryVerdictItem
    | FindingItem
    | ObligationDispositionItem
    | MemberClosureResultItem
    | DisputeItem
    | PostFreezeCandidateItem
    | WorkerRefusalOrExpansionItem
)
"""`IV11-8`: each item a declared class, with its `IV11-5`…`IV11-7` value and referent."""


class OutcomeIngestionRecord(StoredRecord):
    """`RC-37` outcome ingestion — unique on the activation (`MH-13`). The two capture
    channels are two typed reference sets and are never merged (`MH-14`)."""

    identity: OutcomeIngestionRecordId
    correlation: CorrelationSet
    activation: WorkerActivationId
    objective_channel: tuple[ObjectiveArtifactProduction, ...]
    worker_authored_channel: tuple[WorkerAuthoredArtifactProduction, ...]
    items: tuple[DeclaredItem, ...]


# --- RC-38 / RC-39 -----------------------------------------------------------------


class TerminationObservation(DomainValue):
    """`IV11-9`."""

    termination: TerminationValue


class TimeoutObservation(DomainValue):
    """`IV11-10`, recordable alongside a terminated class for the same process (`FC-2a`)."""

    disposition: TimeoutDisposition


class QuiescenceObservation(DomainValue):
    """`IV11-11`."""

    quiescence: Quiescence


class ExecutionObservation(StoredRecord):
    """`RC-38`: one observation per record — termination and quiescence are never one
    record (`AP07-I44`)."""

    identity: ExecutionObservationId
    observation: TerminationObservation | TimeoutObservation | QuiescenceObservation


class StructuralConformanceDetermination(DomainValue):
    """`IV11-12` structural conformance, with its `IV11-13` result."""

    determination_class: Literal[ConformanceDeterminationClass.STRUCTURAL_CONFORMANCE] = (
        ConformanceDeterminationClass.STRUCTURAL_CONFORMANCE
    )
    result: StructuralConformanceResult


class EffectEnvelopeConformance(DomainValue):
    """Whether one of the activation's own effects lies within its envelope (`RS7-10`)."""

    effect: ActivationEffectId
    within_envelope: bool


class EnvelopeConformanceDetermination(DomainValue):
    """`IV11-12` envelope conformance: per effect, and the `RC-30` violations determined
    or their affirmative absence."""

    determination_class: Literal[ConformanceDeterminationClass.ENVELOPE_CONFORMANCE] = (
        ConformanceDeterminationClass.ENVELOPE_CONFORMANCE
    )
    effects: tuple[EffectEnvelopeConformance, ...]
    violations: Determined[Annotated[tuple[EnvelopeViolationId, ...], Field(min_length=1)]]


class ResidueDetermination(DomainValue):
    """`IV11-12` residue: the `RC-24` mutations, or their affirmative absence."""

    determination_class: Literal[ConformanceDeterminationClass.RESIDUE] = (
        ConformanceDeterminationClass.RESIDUE
    )
    mutations: Determined[Annotated[tuple[UnaccountedMutationId, ...], Field(min_length=1)]]


class AdoptionDetermination(DomainValue):
    """`IV11-12` adoption: the record's existence **is** the fact (`PA-03`)."""

    determination_class: Literal[ConformanceDeterminationClass.ADOPTION] = (
        ConformanceDeterminationClass.ADOPTION
    )


class ConformanceDetermination(StoredRecord):
    """`RC-39`: four separate determination classes, never collapsed (`MH-16`)."""

    identity: ConformanceDeterminationId
    determination: (
        StructuralConformanceDetermination
        | EnvelopeConformanceDetermination
        | ResidueDetermination
        | AdoptionDetermination
    )


# --- RC-40 / RC-41 -----------------------------------------------------------------


class AuditEntry(StoredRecord):
    """`RC-40`: append-only. References the record it reports and never copies it
    (`AR-2`); ordering is `predecessor` and nothing else (`AR-3`)."""

    identity: AuditEntryId
    entry_class: AuditEntryClass
    predecessor: Determined[AuditEntryId]


class SessionRecord(StoredRecord):
    """`RC-41`: that a fresh session was constructed for exactly this activation. No
    token, transcript, memory or continuity artifact exists to store (`RC-51`)."""

    activation: WorkerActivationId
