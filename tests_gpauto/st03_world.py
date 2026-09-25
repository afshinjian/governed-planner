"""One consistent coordination record of every class `RC-10` … `RC-41` — test support.

Design basis: AP-11 ST-03 store-realization amendment §6 (`RS11-10`…`RS11-41`), §11.1
(Tests: *"each record class created once"*); AP-07 §3.2.

`world()` builds the ingest records an outside party would supply and, over them, one
creation unit per step of an epoch's record history — every coordination record class at
least once, every reference resolving. It is **not** a state machine: the order below is
the order in which referents come into existence, and nothing here evaluates a guard or
asserts that a transition is legal, which is ST-05's. Minted values come from
`minting.mint_value`, as they will in production.

`fresh_store()` creates a store in a temporary directory — outside the repository, which
is itself a placement fact the placement tests check rather than assume.
"""

from __future__ import annotations

import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel

from gpauto.absence import Carried, KnownAbsent, NotApplicable, Present
from gpauto.activation import (
    EntryStateBoundaryReference,
    InputPackage,
    ObjectiveProductionReference,
    ProviderAssignment,
    StageContractPartReference,
)
from gpauto.authorization import (
    AuthorityAmbiguity,
    AuthorityBearingContent,
    AuthorizationRecord,
    CandidateExclusion,
    ConsumedDisposition,
    DistinctMultiplicityForm,
    LiveDisposition,
    SuspendedDisposition,
)
from gpauto.bounds import (
    ActionClass,
    AuthorityBounds,
    ReadBoundary,
    ScopeFrameBounds,
    ToolCategory,
    WriteBoundary,
)
from gpauto.content_identity import identify_artifact_content, identify_stage_contract
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
from gpauto.coordination_records import (
    ActivationEffectRecord,
    AdoptionDetermination,
    ArtifactProductionRecord,
    AuditEntry,
    AuthorityEnvelopeRecord,
    CandidateExclusionRecord,
    ClosureAssessmentRecord,
    ConformanceDetermination,
    CorrelationSet,
    CycleOccurrence,
    DiscoveryVerdictItem,
    DispatchRecord,
    DispositionEstablishingRecord,
    DisputeItem,
    EffectEnvelopeConformance,
    EntryStateBoundaryRecord,
    EnvelopeConformanceDetermination,
    EnvelopeViolationRecord,
    ExecutionObservation,
    FindingItem,
    FindingRecord,
    GovernanceEventResolution,
    HaltOccurrence,
    InputPackageRecord,
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
    MemberClosureResultItem,
    NoResolutionResult,
    ObligationDispositionItem,
    OutcomeIngestionRecord,
    PostFreezeCandidateItem,
    PostFreezeCandidateRecord,
    QuiescenceObservation,
    RefusalRecord,
    ResidueDetermination,
    ResolvedRootResult,
    RootResolutionRecord,
    SessionAnnotation,
    SessionRecord,
    StructuralConformanceDetermination,
    TerminationObservation,
    TimeoutObservation,
    WorkerActivationRecord,
    WorkerRefusalOrExpansionItem,
)
from gpauto.coordination_vocabulary import (
    AuditEntryClass,
    ClosedVerdict,
    DiscoveryVerdict,
    M1Edge,
    M1Position,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
    M4Edge,
    NotClosedVerdict,
    ObligationDisposition,
    Quiescence,
    StructuralConformanceResult,
    Terminated,
    TerminatedDisposition,
    TimeoutDisposition,
)
from gpauto.envelope import AuthorityEnvelope
from gpauto.evidence import (
    ActivationAttribution,
    ArtifactProduction,
    ObjectiveArtifactProduction,
    WorkerAuthoredArtifactProduction,
)
from gpauto.governance import (
    AuthorizingDecision,
    EnvelopeViolation,
    NonAuthorizingDecision,
    OwnerDecision,
    Refusal,
    StageOutcome,
)
from gpauto.identity import (
    ActivationEffectId,
    ArtifactProductionId,
    AuthorityAmbiguityId,
    AuthorityEnvelopeId,
    AuthorizationRecordId,
    BaselineIdentityId,
    CandidateExclusionId,
    ClosureAssessmentId,
    EntryStateBoundaryId,
    EnvelopeViolationId,
    FindingId,
    FrozenFindingSetId,
    GovernedStageId,
    InputPackageId,
    OwnerAuthorizationId,
    OwnerDecisionId,
    PostFreezeCandidateId,
    ProjectId,
    RefusalId,
    RemediationObligationId,
    RepositoryBoundaryId,
    RootResolutionId,
    StageOutcomeId,
    UnaccountedMutationId,
    WorkerActivationId,
)
from gpauto.minting import mint_value
from gpauto.preimage import StageContractContent
from gpauto.repository import ClassificationContext, EntryStateBoundary, UnaccountedMutation
from gpauto.review import (
    ClosureAssessment,
    Finding,
    FrozenFindingSet,
    PostFreezeCandidate,
    RemediationObligation,
)
from gpauto.scope_frame import (
    BaselineIdentity,
    GovernedStage,
    Project,
    RepositoryBoundary,
    StageContract,
)
from gpauto.store import CoordinationStore, create_store
from gpauto.vocabulary import (
    AuthorizationDisposition,
    BoundedPreflightPermission,
    GitCapabilityClass,
    GovernanceCase,
    OwnerDecisionKind,
    Provenance,
    RaAttribute,
    Role,
    StageContractPart,
    StageOutcomeDisposition,
    WriteMode,
)
from st03_ingest import IngestRecord, ingest

ABSENT = KnownAbsent(basis="affirmatively absent for this occurrence")
BRANCH = "stage-branch"
OUTCOME_DISCRIMINATOR = "outcome-token-a"
"""The world's `StageOutcomeId` local discriminator (`ID-8`): a fixed opaque test value,
derived from nothing — no timestamp, order, epoch, authorization or stage position."""


def minted[I: BaseModel](kind: type[I]) -> I:
    return kind(value=mint_value())


def discriminator() -> str:
    return mint_value()


@dataclass
class World:
    """The ingest records, the coordination units in creation order, and handles."""

    ingest: list[IngestRecord]
    units: list[tuple[BaseModel, ...]]
    handles: dict[str, BaseModel] = field(default_factory=dict)

    def records(self) -> list[BaseModel]:
        return [record for unit in self.units for record in unit]

    def one_of(self, record_type: type[BaseModel]) -> BaseModel:
        return next(record for record in self.records() if type(record) is record_type)


@dataclass(frozen=True)
class Frame:
    project: ProjectId
    stage: GovernedStageId
    repository: RepositoryBoundaryId
    baseline: BaselineIdentityId
    contract: StageContract
    content: StageContractContent
    root: OwnerAuthorizationId
    other_root: OwnerAuthorizationId
    records: tuple[AuthorizationRecord, ...]
    accept: OwnerDecision
    resolve: OwnerDecision


def bounds(frame: Frame) -> AuthorityBounds:
    return AuthorityBounds(
        role_applicability=Role.IMPLEMENTER,
        action_classes=(ActionClass(name="edit-project-file"),),
        read_boundary=ReadBoundary(scopes=("src/",)),
        write_mode=WriteMode.WRITING,
        write_boundary=Carried[WriteBoundary](value=WriteBoundary(scopes=("src/",))),
        tool_categories=(ToolCategory(name="file-edit"),),
        external_action_classes=(),
        git_capability_class=GitCapabilityClass.NONE,
        scope_frame=ScopeFrameBounds(
            project=frame.project,
            stage=frame.stage,
            repository_boundary=frame.repository,
            baseline=frame.baseline,
        ),
        authoritative_input_designation=NotApplicable(),
        frozen_set_reference=NotApplicable(),
    )


def frame(tag: str = "") -> tuple[Frame, list[IngestRecord]]:
    """Scope-frame, authorization and decision records, as the outside party supplies."""
    project = ProjectId(value=f"project{tag}")
    stage = GovernedStageId(value=f"stage{tag}")
    repository = RepositoryBoundaryId(value=f"repository{tag}")
    baseline = BaselineIdentityId(value=f"baseline{tag}")
    content = StageContractContent(
        objective=f"objective{tag}",
        deliverable_boundary=("src/",),
        explicit_out_of_stage=("docs/",),
        implementation_instructions=("implement",),
        review_instructions=("review",),
        acceptance_criteria=("accepted when tests pass",),
    )
    identified = identify_stage_contract(content)
    contract = StageContract(identity=identified.identity, **content.model_dump())
    root = OwnerAuthorizationId(value=f"authorization{tag}")
    other_root = OwnerAuthorizationId(value=f"other-authorization{tag}")
    partial = Frame(
        project,
        stage,
        repository,
        baseline,
        contract,
        content,
        root,
        other_root,
        (),
        _decision(stage, "accept"),
        _decision(stage, "resolve"),
    )

    def record(name: str, authorization: OwnerAuthorizationId) -> AuthorizationRecord:
        return AuthorizationRecord(
            identity=AuthorizationRecordId(value=f"{name}{tag}"),
            authorization_identity=authorization,
            content=AuthorityBearingContent(
                project=project,
                stage=stage,
                contract=contract.identity,
                repository_boundary=repository,
                baseline=baseline,
                authorized_roles=(Role.IMPLEMENTER,),
                authority_ceiling=bounds(partial),
                owner_human_label_present=True,
                preflight_permission=BoundedPreflightPermission.PERMITTED,
                liveness=LiveDisposition(),
            ),
        )

    records = (record("record-a", root), record("record-b", root), record("record-c", other_root))
    result = Frame(
        project,
        stage,
        repository,
        baseline,
        contract,
        content,
        root,
        other_root,
        records,
        partial.accept,
        partial.resolve,
    )
    authorizing = OwnerDecision(
        identity=OwnerDecisionId(value=f"authorize{tag}"),
        stage=stage,
        act=AuthorizingDecision(
            kind=OwnerDecisionKind.STAGE_ENTRY_AUTHORIZATION,
            produced_authorization=Present[OwnerAuthorizationId](value=root),
        ),
    )
    supplied: list[IngestRecord] = [
        Project(identity=project),
        GovernedStage(identity=stage, project=project),
        RepositoryBoundary(identity=repository, repository_location="repository", branch=BRANCH),
        BaselineIdentity(identity=baseline, committed_history_identity="commit"),
        contract,
        *records,
        authorizing,
        result.accept,
        result.resolve,
    ]
    return result, supplied


def _decision(stage: GovernedStageId, name: str) -> OwnerDecision:
    absent = KnownAbsent(basis="settles, confers nothing")
    if name == "accept":
        act = NonAuthorizingDecision(
            kind=OwnerDecisionKind.STAGE_OUTCOME_ACCEPTANCE, produced_authorization=absent
        )
    else:
        act = NonAuthorizingDecision(
            kind=OwnerDecisionKind.REFUSAL_RESOLUTION, produced_authorization=absent
        )
    return OwnerDecision(
        identity=OwnerDecisionId(value=f"{name}-{stage.value}"), stage=stage, act=act
    )


def m1(
    resolution: RootResolutionId,
    state: M1Position,
    edge: M1Edge,
    predecessor: M1PositionEntry | None,
    result: BaseModel,
) -> M1PositionEntry:
    return M1PositionEntry(
        identity=M1PositionEntryId(resolution=resolution, discriminator=discriminator()),
        state=state,
        edge=edge,
        predecessor=Present[M1PositionEntryId](value=predecessor.identity)
        if predecessor
        else ABSENT,
        result=result,  # type: ignore[arg-type]
    )


def m2(
    root: OwnerAuthorizationId,
    state: M2Position,
    edge: M2Edge,
    predecessor: M2PositionEntry | None,
    cycle: CycleOccurrenceId | None = None,
) -> M2PositionEntry:
    return M2PositionEntry(
        identity=M2PositionEntryId(epoch_root=root, discriminator=discriminator()),
        state=state,
        edge=edge,
        predecessor=Present[M2PositionEntryId](value=predecessor.identity)
        if predecessor
        else ABSENT,
        cycle_occurrence=Present[CycleOccurrenceId](value=cycle) if cycle else ABSENT,
    )


def m3(
    envelope: AuthorityEnvelopeId,
    state: M3Position,
    edge: M3Edge,
    predecessor: M3PositionEntry | None,
) -> M3PositionEntry:
    return M3PositionEntry(
        identity=M3PositionEntryId(envelope=envelope, discriminator=discriminator()),
        state=state,
        edge=edge,
        predecessor=Present[M3PositionEntryId](value=predecessor.identity)
        if predecessor
        else ABSENT,
    )


def m4(
    authorization: OwnerAuthorizationId,
    state: AuthorizationDisposition,
    edge: M4Edge,
    predecessor: M4PositionEntry | None,
) -> M4PositionEntry:
    return M4PositionEntry(
        identity=M4PositionEntryId(authorization=authorization, discriminator=discriminator()),
        state=state,
        edge=edge,
        predecessor=Present[M4PositionEntryId](value=predecessor.identity)
        if predecessor
        else ABSENT,
    )


def world(tag: str = "") -> World:
    """Every coordination record class at least once, over one epoch's references."""
    f, supplied = frame(tag)
    units: list[tuple[BaseModel, ...]] = []
    h: dict[str, BaseModel] = {}

    units.append((identify_stage_contract(f.content),))

    # M1: resolution occurrence (A1), an exclusion while open, then A2.
    resolution = RootResolutionRecord(
        identity=minted(RootResolutionId),
        project=f.project,
        stage=f.stage,
        predecessor_terminal_entry=ABSENT,
        candidates=tuple(r.identity for r in f.records),
    )
    a1 = m1(resolution.identity, M1Position.RESOLUTION_OPEN, M1Edge.A1, None, NoResolutionResult())
    units.append((resolution, a1))
    exclusion = CandidateExclusionRecord(
        exclusion=CandidateExclusion(
            identity=CandidateExclusionId(
                parent_resolution=resolution.identity, excluded_record=f.records[2].identity
            ),
            failing_attribute=RaAttribute.RA_02_STAGE,
        ),
        predecessor=ABSENT,
    )
    units.append((exclusion,))
    a2 = m1(
        resolution.identity,
        M1Position.ROOT_RESOLVED,
        M1Edge.A2,
        a1,
        ResolvedRootResult(resolved_root=f.root),
    )
    units.append((a2,))
    h.update(resolution=resolution, a1=a1, a2=a2, exclusion=exclusion)

    # M2 opens; the boundary is fixed with the B2 entry.
    s1 = m2(f.root, M2Position.S1_EPOCH_OPENED, M2Edge.B1, None)
    units.append((s1,))
    boundary = EntryStateBoundaryRecord(
        boundary=EntryStateBoundary(
            identity=minted(EntryStateBoundaryId),
            baseline=f.baseline,
            pre_existing_working_tree_state=("M README.md",),
            pre_existing_index_state=(),
        ),
        resolved_root=f.root,
    )
    s2 = m2(f.root, M2Position.S2_ENTRY_BOUNDARY_FIXED, M2Edge.B2, s1)
    units.append((boundary, s2))
    context = ClassificationContext(authorization=f.root, entry_boundary=boundary.boundary.identity)

    # M3: envelope derived; package; dispatch; start act with its session record.
    envelope = AuthorityEnvelopeRecord(
        envelope=AuthorityEnvelope(
            identity=minted(AuthorityEnvelopeId),
            resolved_root=f.root,
            stage=f.stage,
            entry_boundary=boundary.boundary.identity,
            role=Role.IMPLEMENTER,
            bounds=bounds(f),
            declared_closed=True,
        ),
        cycle_occurrence=ABSENT,
        predecessor_entry=s2.identity,
        target_state=M2Position.S3_IMPLEMENTATION_ACTIVE,
    )
    derived = m3(envelope.envelope.identity, M3Position.ENVELOPE_DERIVED, M3Edge.C1, None)
    s3 = m2(f.root, M2Position.S3_IMPLEMENTATION_ACTIVE, M2Edge.B3, s2)
    package = InputPackageRecord(
        package=InputPackage(
            identity=minted(InputPackageId),
            authoritative_inputs=(
                EntryStateBoundaryReference(entry_boundary=boundary.boundary.identity),
                StageContractPartReference(
                    contract=f.contract.identity, part=StageContractPart.IMPLEMENTATION_INSTRUCTIONS
                ),
            ),
            non_basis_context=("repository notes",),
        ),
        cycle_occurrence=ABSENT,
    )
    units.append((envelope, derived, package, s3))
    correlation = CorrelationSet(
        root=f.root,
        stage=f.stage,
        context=context,
        step_state=M2Position.S3_IMPLEMENTATION_ACTIVE,
        cycle_occurrence=ABSENT,
        envelope=envelope.envelope.identity,
        activation=ABSENT,
    )
    dispatch = DispatchRecord(
        identity=minted(DispatchRecordId),
        correlation=correlation,
        package=package.package.identity,
        role=Role.IMPLEMENTER,
        branch=BRANCH,
        predecessor_entry=s3.identity,
    )
    units.append((dispatch,))
    activation = WorkerActivationRecord(
        identity=minted(WorkerActivationId),
        envelope=envelope.envelope.identity,
        role=Role.IMPLEMENTER,
        input_package=package.package.identity,
        provider=Present[ProviderAssignment](
            value=ProviderAssignment(provider_reference="vendor-x")
        ),
        session=Present[SessionAnnotation](value=SessionAnnotation(session_reference="session-1")),
        stage=f.stage,
        branch=BRANCH,
        resolved_root=f.root,
        cycle_occurrence=ABSENT,
    )
    running = m3(envelope.envelope.identity, M3Position.ACTIVATION_RUNNING, M3Edge.C2, derived)
    session = SessionRecord(activation=activation.identity)
    units.append((activation, running, session))
    h.update(boundary=boundary, envelope=envelope, activation=activation, s3=s3, package=package)

    # Captured output: shared content, two productions of it (ID-14), an effect.
    identified = identify_artifact_content(b"objective test output\n")
    attribution = ActivationAttribution(activation=activation.identity)
    objective_production = ObjectiveArtifactProduction(
        identity=minted(ArtifactProductionId),
        content=identified.identity,
        provenance=Provenance.OBJECTIVE,
        attributed_to=attribution,
    )
    worker_production = WorkerAuthoredArtifactProduction(
        identity=minted(ArtifactProductionId),
        content=identified.identity,
        provenance=Provenance.WORKER_AUTHORED,
        attributed_to=attribution,
    )
    objective, worker_copy = (
        ArtifactProductionRecord(
            production=ArtifactProduction[Provenance](
                identity=production.identity,
                content=production.content,
                provenance=production.provenance,
                attributed_to=production.attributed_to,
            ),
            cycle_occurrence=ABSENT,
        )
        for production in (objective_production, worker_production)
    )
    effect = ActivationEffectRecord(
        identity=ActivationEffectId(
            parent_activation=activation.identity, local_discriminator=discriminator()
        ),
        observed_state=("M src/module.py",),
        cycle_occurrence=ABSENT,
    )
    units.append((identified, objective, worker_copy, effect))
    observations = (
        ExecutionObservation(
            identity=ExecutionObservationId(
                activation=activation.identity, discriminator=discriminator()
            ),
            observation=TerminationObservation(
                termination=Terminated(disposition=TerminatedDisposition.ORDINARY_EXIT)
            ),
        ),
        ExecutionObservation(
            identity=ExecutionObservationId(
                activation=activation.identity, discriminator=discriminator()
            ),
            observation=TimeoutObservation(disposition=TimeoutDisposition.TIMEOUT),
        ),
        ExecutionObservation(
            identity=ExecutionObservationId(
                activation=activation.identity, discriminator=discriminator()
            ),
            observation=QuiescenceObservation(quiescence=Quiescence.QUIESCENT),
        ),
    )
    units.append(observations)
    h.update(objective=objective, worker_copy=worker_copy, effect=effect, content=identified)

    # The four separate determinations, then C4.
    def determination(value: BaseModel) -> ConformanceDetermination:
        return ConformanceDetermination(
            identity=ConformanceDeterminationId(
                activation=activation.identity, discriminator=discriminator()
            ),
            determination=value,  # type: ignore[arg-type]
        )

    determinations = (
        determination(
            StructuralConformanceDetermination(result=StructuralConformanceResult.CONFORMANT)
        ),
        determination(
            EnvelopeConformanceDetermination(
                effects=(EffectEnvelopeConformance(effect=effect.identity, within_envelope=True),),
                violations=ABSENT,
            )
        ),
        determination(ResidueDetermination(mutations=ABSENT)),
        determination(AdoptionDetermination()),
    )
    completed = m3(envelope.envelope.identity, M3Position.ACTIVATION_COMPLETED, M3Edge.C4, running)
    units.append((*determinations, completed))
    h.update(adoption=determinations[3])

    # The freeze unit (WP-17): findings born members, obligations, the B5 entry.
    s4 = m2(f.root, M2Position.S4_DISCOVERY_ACTIVE, M2Edge.B4, s3)
    units.append((s4,))
    finding = FindingRecord(
        finding=Finding(
            identity=minted(FindingId),
            stage=f.stage,
            originating_authorization=f.root,
            originating_activation=activation.identity,
        ),
        content_binding=ObjectiveProductionReference(production=objective_production),
    )
    frozen = FrozenFindingSet(
        identity=minted(FrozenFindingSetId),
        stage=f.stage,
        resolved_root=f.root,
        originating_activation=activation.identity,
        members=(finding.finding.identity,),
    )
    obligation = RemediationObligation(
        identity=RemediationObligationId(
            parent_frozen_set=frozen.identity, member_finding=finding.finding.identity
        )
    )
    s5 = m2(f.root, M2Position.S5_FINDING_SET_FROZEN, M2Edge.B5, s4)
    units.append((finding, frozen, obligation, s5))
    h.update(finding=finding, frozen=frozen, obligation=obligation, s5=s5)

    # The first cycle occurrence (B6a) and its S6 entry, in one unit.
    cycle = CycleOccurrence(
        identity=minted(CycleOccurrenceId),
        establishing_edge=M2Edge.B6a,
        predecessor_entry=s5.identity,
        target_state=M2Position.S6_REMEDIATION_ACTIVE,
        predecessor_closure_activation=ABSENT,
        envelope=ABSENT,
        activation=ABSENT,
    )
    s6 = m2(f.root, M2Position.S6_REMEDIATION_ACTIVE, M2Edge.B6a, s5, cycle.identity)
    units.append((cycle, s6))
    in_cycle = Present[CycleOccurrenceId](value=cycle.identity)
    assessment = ClosureAssessmentRecord(
        assessment=ClosureAssessment(
            identity=ClosureAssessmentId(
                assessed_finding=finding.finding.identity, closure_activation=activation.identity
            )
        ),
        verdict=ClosedVerdict(),
        cycle_occurrence=in_cycle,
    )
    candidate = PostFreezeCandidateRecord(
        candidate=PostFreezeCandidate(
            identity=minted(PostFreezeCandidateId),
            stage=f.stage,
            observing_activation=activation.identity,
        ),
        cycle_occurrence=in_cycle,
    )
    ingestion = OutcomeIngestionRecord(
        identity=minted(OutcomeIngestionRecordId),
        correlation=correlation.model_copy(
            update={"activation": Present[WorkerActivationId](value=activation.identity)}
        ),
        activation=activation.identity,
        objective_channel=(objective_production,),
        worker_authored_channel=(worker_production,),
        items=(
            DiscoveryVerdictItem(verdict=DiscoveryVerdict.FINDINGS_REPORTED),
            FindingItem(),
            ObligationDispositionItem(
                obligation=obligation.identity,
                disposition=ObligationDisposition.ADDRESSED,
                change_evidence=ObjectiveProductionReference(production=objective_production),
            ),
            MemberClosureResultItem(
                member=finding.finding.identity,
                verdict=NotClosedVerdict(
                    indeterminacy_reason=Present[str](value="criteria not evaluable")
                ),
            ),
            DisputeItem(),
            PostFreezeCandidateItem(),
            WorkerRefusalOrExpansionItem(),
        ),
    )
    units.append((assessment, candidate, ingestion))

    # Governance events, a halt at S6 and its resolution, and M4 dispositions.
    refusal = RefusalRecord(
        refusal=Refusal(
            identity=minted(RefusalId),
            case=GovernanceCase.CASE_A,
            stage=f.stage,
            branch=BRANCH,
            role=Present[Role](value=Role.REMEDIATOR),
            resolved_root=Present[OwnerAuthorizationId](value=f.root),
            envelope=Present[AuthorityEnvelopeId](value=envelope.envelope.identity),
            condition="write outside the write boundary",
            observed_value="docs/",
            bound_value="src/",
            refused_action_class=ActionClass(name="edit-project-file"),
        ),
        cycle_occurrence=in_cycle,
    )
    violation = EnvelopeViolationRecord(
        violation=EnvelopeViolation(
            identity=minted(EnvelopeViolationId),
            case=GovernanceCase.CASE_B,
            envelope=envelope.envelope.identity,
            resolved_root=f.root,
            stage=f.stage,
            role=Role.IMPLEMENTER,
            violating_activation=activation.identity,
            action_class=ActionClass(name="edit-project-file"),
            boundary_crossed="write boundary",
            unexplained_portion=("docs/unexpected.md",),
            not_prevented=True,
        ),
        cycle_occurrence=ABSENT,
    )
    mutation = UnaccountedMutation(
        identity=minted(UnaccountedMutationId),
        context=context,
        observed_state=("docs/unexpected.md",),
        unexplained_portion=("docs/unexpected.md",),
        affected_envelopes=(envelope.envelope.identity,),
        producing_activation=Present[WorkerActivationId](value=activation.identity),
    )
    ambiguity = AuthorityAmbiguity(
        identity=minted(AuthorityAmbiguityId),
        stage=f.stage,
        form=DistinctMultiplicityForm(competing_identities=(f.root, f.other_root)),
    )
    units.append((refusal, violation, mutation, ambiguity))
    halt = HaltOccurrence(
        identity=minted(HaltOccurrenceId),
        event=refusal.refusal.identity,
        source_state=M2Position.S6_REMEDIATION_ACTIVE,
        cycle_occurrence=in_cycle,
    )
    s9 = m2(f.root, M2Position.S9_EPOCH_HALTED, M2Edge.B9, s6)
    suspension = DispositionEstablishingRecord(
        identity=DispositionRecordId(authorization=f.root, discriminator=discriminator()),
        disposition=SuspendedDisposition(established_by_event=refusal.refusal.identity),
    )
    g1 = m4(f.root, AuthorizationDisposition.SUSPENDED, M4Edge.G1, None)
    units.append((halt, s9, suspension, g1))
    resolution_record = GovernanceEventResolution(
        identity=minted(GovernanceEventResolutionId),
        halt_occurrence=halt.identity,
        decision=f.resolve.identity,
    )
    units.append((resolution_record,))
    outcome = StageOutcome(
        identity=StageOutcomeId(parent_stage=f.stage, local_discriminator=OUTCOME_DISCRIMINATOR),
        disposition=StageOutcomeDisposition.ACCEPTED,
        established_by=f.accept.identity,
    )
    consumption = DispositionEstablishingRecord(
        identity=DispositionRecordId(authorization=f.root, discriminator=discriminator()),
        disposition=ConsumedDisposition(established_by_outcome=outcome.identity),
    )
    g3 = m4(f.root, AuthorizationDisposition.CONSUMED, M4Edge.G3, g1)
    s10 = m2(f.root, M2Position.S10_EPOCH_SETTLED, M2Edge.B11, s9)
    units.append((outcome, consumption, g3, s10))
    h.update(refusal=refusal, halt=halt, g1=g1, g3=g3, outcome=outcome, mutation=mutation)

    # The routing audit: a reported entry, then a replay entry naming its predecessor.
    first = AuditEntry(
        identity=AuditEntryId(audited=activation.identity, discriminator=discriminator()),
        entry_class=AuditEntryClass.REPORTED,
        predecessor=ABSENT,
    )
    replay = AuditEntry(
        identity=AuditEntryId(audited=a2.identity, discriminator=discriminator()),
        entry_class=AuditEntryClass.REPLAY,
        predecessor=Present[AuditEntryId](value=first.identity),
    )
    units.append((first, replay))
    h.update(first_audit=first, replay_audit=replay)

    # A later package, referencing an objective production as basis (AT-8).
    later_package = InputPackageRecord(
        package=InputPackage(
            identity=minted(InputPackageId),
            authoritative_inputs=(ObjectiveProductionReference(production=objective_production),),
            non_basis_context=(),
        ),
        cycle_occurrence=in_cycle,
    )
    units.append((later_package,))
    return World(supplied, units, h)


def populate(store: CoordinationStore, built: World) -> None:
    """Ingest as the outside party, then create every unit through the store."""
    ingest(store.path, built.ingest)
    for unit in built.units:
        store.create_unit(unit)  # type: ignore[arg-type]


@contextmanager
def fresh_store() -> Iterator[CoordinationStore]:
    """A new store in a temporary directory, closed and removed afterwards."""
    with tempfile.TemporaryDirectory(prefix="gpauto-st03-") as directory:
        store = create_store(Path(directory) / "coordination.sqlite")
        try:
            yield store
        finally:
            store.close()


@contextmanager
def populated_store(tag: str = "") -> Iterator[tuple[CoordinationStore, World]]:
    with fresh_store() as store:
        built = world(tag)
        populate(store, built)
        yield store, built


def raw(store: CoordinationStore) -> sqlite3.Connection:
    """A second connection to the store's file, outside GP-AUTO's write surface, with
    foreign keys on. It shows what the schema itself enforces; it does not stand for an
    arbitrary actor holding the file, against whom nothing is claimed."""
    connection = sqlite3.connect(store.path, isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection
