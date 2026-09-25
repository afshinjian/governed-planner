"""Constructors for one well-formed instance of every AP-03 entity.

Design basis: AP-03 §2 (entity inventory); AP-11 §16 (`GP-AUTO-ST-01` tests —
construction and round-trip of every entity).

These are builders, not fixtures with behaviour. Each returns the minimal well-formed
instance of one entity, so that a test asserting *"every entity is constructible and
round-trips"* enumerates the entities rather than re-describing them. Values are
inert placeholder tokens: nothing here asserts that a token is well-formed, because
AP-03 designs no syntax, grammar or generator for any identity (AP-03 §4.2).
"""

from __future__ import annotations

from gpauto.absence import Carried, KnownAbsent, NotApplicable, NotObserved, Present
from gpauto.activation import (
    EntryStateBoundaryReference,
    InputPackage,
    ObjectiveProductionReference,
    ProviderAssignment,
    WorkerActivation,
)
from gpauto.authorization import (
    AuthorityAmbiguity,
    AuthorityBearingContent,
    AuthorizationRecord,
    CandidateExclusion,
    ConsumedDisposition,
    DistinctMultiplicityForm,
    LiveDisposition,
    OwnerAuthorization,
    OwnerHumanLabel,
    RootResolution,
    SameIdentityConflictForm,
    SuspendedDisposition,
)
from gpauto.bounds import (
    ActionClass,
    AuthoritativeInputDesignation,
    AuthorityBounds,
    ReadBoundary,
    ScopeFrameBounds,
    ToolCategory,
    WriteBoundary,
)
from gpauto.envelope import AuthorityEnvelope
from gpauto.evidence import (
    ActivationAttribution,
    ArtifactContent,
    ObjectiveArtifactProduction,
    WorkerAuthoredArtifactProduction,
)
from gpauto.governance import (
    AuthorizingDecision,
    EnvelopeViolation,
    ExceptionalRecoveryDecision,
    NonAuthorizingDecision,
    OwnerDecision,
    Refusal,
    StageOutcome,
)
from gpauto.identity import (
    ActivationEffectId,
    ArtifactContentId,
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
    StageContractId,
    StageOutcomeId,
    UnaccountedMutationId,
    WorkerActivationId,
)
from gpauto.repository import (
    ActivationEffect,
    ClassificationContext,
    EntryStateBoundary,
    UnaccountedMutation,
)
from gpauto.review import (
    ClosureAssessment,
    Finding,
    FrozenFindingSet,
    PostFreezeCandidate,
    RemediationObligation,
)
from gpauto.schema import DomainEntity
from gpauto.scope_frame import (
    BaselineIdentity,
    GovernedStage,
    Project,
    RepositoryBoundary,
    StageContract,
)
from gpauto.vocabulary import (
    BoundedPreflightPermission,
    ExternalActionClass,
    GitCapabilityClass,
    GovernanceCase,
    OwnerDecisionKind,
    Provenance,
    RaAttribute,
    Role,
    RootResolutionOutcome,
    StageOutcomeDisposition,
    WriteMode,
)

PROJECT_ID = ProjectId(value="project-token")
STAGE_ID = GovernedStageId(value="stage-token")
CONTRACT_ID = StageContractId(value="contract-content-token")
REPOSITORY_ID = RepositoryBoundaryId(value="repository-token")
BASELINE_ID = BaselineIdentityId(value="baseline-token")
AUTHORIZATION_ID = OwnerAuthorizationId(value="authorization-token")
OTHER_AUTHORIZATION_ID = OwnerAuthorizationId(value="other-authorization-token")
RECORD_ID = AuthorizationRecordId(value="record-token")
DECISION_ID = OwnerDecisionId(value="decision-token")
RESOLUTION_ID = RootResolutionId(value="resolution-token")
BOUNDARY_ID = EntryStateBoundaryId(value="boundary-token")
ENVELOPE_ID = AuthorityEnvelopeId(value="envelope-token")
ACTIVATION_ID = WorkerActivationId(value="activation-token")
INPUT_PACKAGE_ID = InputPackageId(value="input-package-token")
CONTENT_ID = ArtifactContentId(value="content-token")
PRODUCTION_ID = ArtifactProductionId(value="production-token")
FINDING_ID = FindingId(value="finding-token")
FROZEN_SET_ID = FrozenFindingSetId(value="frozen-set-token")
CANDIDATE_ID = PostFreezeCandidateId(value="post-freeze-token")
REFUSAL_ID = RefusalId(value="refusal-token")
VIOLATION_ID = EnvelopeViolationId(value="violation-token")
AMBIGUITY_ID = AuthorityAmbiguityId(value="ambiguity-token")
MUTATION_ID = UnaccountedMutationId(value="mutation-token")


def scope_frame_bounds() -> ScopeFrameBounds:
    return ScopeFrameBounds(
        project=PROJECT_ID,
        stage=STAGE_ID,
        repository_boundary=REPOSITORY_ID,
        baseline=BASELINE_ID,
    )


def writing_bounds() -> AuthorityBounds:
    """Bounds for a writing role: the write boundary is carried."""
    return AuthorityBounds(
        role_applicability=Role.IMPLEMENTER,
        action_classes=(ActionClass(name="edit-project-file"),),
        read_boundary=ReadBoundary(scopes=("src/",)),
        write_mode=WriteMode.WRITING,
        write_boundary=Carried[WriteBoundary](value=WriteBoundary(scopes=("src/",))),
        tool_categories=(ToolCategory(name="file-edit"),),
        external_action_classes=(),
        git_capability_class=GitCapabilityClass.NONE,
        scope_frame=scope_frame_bounds(),
        authoritative_input_designation=NotApplicable(),
        frozen_set_reference=NotApplicable(),
    )


def reviewing_bounds() -> AuthorityBounds:
    """Bounds for a reviewing role: read-only, with an authoritative-input designation."""
    return AuthorityBounds(
        role_applicability=Role.DISCOVERY_REVIEWER,
        action_classes=(ActionClass(name="read-project-file"),),
        read_boundary=ReadBoundary(scopes=("src/", "tests/")),
        write_mode=WriteMode.READ_ONLY,
        write_boundary=NotApplicable(),
        tool_categories=(ToolCategory(name="file-read"),),
        external_action_classes=(ExternalActionClass.EGRESS,),
        git_capability_class=GitCapabilityClass.BOUNDED_READ,
        scope_frame=scope_frame_bounds(),
        authoritative_input_designation=Carried[AuthoritativeInputDesignation](
            value=AuthoritativeInputDesignation(designated_scopes=("src/",))
        ),
        frozen_set_reference=NotApplicable(),
    )


def authority_bearing_content() -> AuthorityBearingContent:
    return AuthorityBearingContent(
        project=PROJECT_ID,
        stage=STAGE_ID,
        contract=CONTRACT_ID,
        repository_boundary=REPOSITORY_ID,
        baseline=BASELINE_ID,
        authorized_roles=(Role.IMPLEMENTER,),
        authority_ceiling=writing_bounds(),
        owner_human_label_present=True,
        preflight_permission=BoundedPreflightPermission.PERMITTED,
        liveness=LiveDisposition(),
    )


def project() -> Project:
    return Project(identity=PROJECT_ID)


def governed_stage() -> GovernedStage:
    return GovernedStage(identity=STAGE_ID, project=PROJECT_ID)


def stage_contract() -> StageContract:
    return StageContract(
        identity=CONTRACT_ID,
        objective="objective",
        deliverable_boundary=("deliverable",),
        explicit_out_of_stage=("out-of-stage",),
        implementation_instructions=("implement",),
        review_instructions=("review",),
        acceptance_criteria=("accepted when",),
    )


def repository_boundary() -> RepositoryBoundary:
    return RepositoryBoundary(
        identity=REPOSITORY_ID, repository_location="repository", branch="branch"
    )


def baseline_identity() -> BaselineIdentity:
    return BaselineIdentity(identity=BASELINE_ID, committed_history_identity="commit-token")


def authorization_record() -> AuthorizationRecord:
    return AuthorizationRecord(
        identity=RECORD_ID,
        authorization_identity=AUTHORIZATION_ID,
        content=authority_bearing_content(),
    )


def owner_authorization() -> OwnerAuthorization:
    return OwnerAuthorization(
        identity=AUTHORIZATION_ID,
        project=PROJECT_ID,
        stage=STAGE_ID,
        contract=CONTRACT_ID,
        repository_boundary=REPOSITORY_ID,
        baseline=BASELINE_ID,
        authorized_roles=(Role.IMPLEMENTER, Role.DISCOVERY_REVIEWER),
        authority_ceiling=writing_bounds(),
        owner_human_label=OwnerHumanLabel(label="OWNER"),
        preflight_permission=BoundedPreflightPermission.PERMITTED,
        liveness=LiveDisposition(),
        constituting_records=(RECORD_ID,),
    )


def candidate_exclusion() -> CandidateExclusion:
    return CandidateExclusion(
        identity=CandidateExclusionId(
            parent_resolution=RESOLUTION_ID, excluded_record=RECORD_ID
        ),
        failing_attribute=RaAttribute.RA_05_BASELINE,
    )


def authority_ambiguity_distinct() -> AuthorityAmbiguity:
    return AuthorityAmbiguity(
        identity=AMBIGUITY_ID,
        stage=STAGE_ID,
        form=DistinctMultiplicityForm(
            competing_identities=(AUTHORIZATION_ID, OTHER_AUTHORIZATION_ID)
        ),
    )


def authority_ambiguity_same_identity() -> AuthorityAmbiguity:
    from gpauto.vocabulary import AuthorityBearingContentClass

    return AuthorityAmbiguity(
        identity=AMBIGUITY_ID,
        stage=STAGE_ID,
        form=SameIdentityConflictForm(
            conflicting_identity=AUTHORIZATION_ID,
            disagreeing_content_classes=(AuthorityBearingContentClass.AUTHORITY_CEILING,),
        ),
    )


def root_resolution() -> RootResolution:
    return RootResolution(
        identity=RESOLUTION_ID,
        stage=STAGE_ID,
        candidates=(RECORD_ID,),
        exclusions=(),
        outcome=RootResolutionOutcome.RESOLVED_ROOT,
        resolved_root=Present[OwnerAuthorizationId](value=AUTHORIZATION_ID),
        ambiguity=KnownAbsent(basis="exactly one eligible instance remained after exclusion"),
    )


def authority_envelope() -> AuthorityEnvelope:
    return AuthorityEnvelope(
        identity=ENVELOPE_ID,
        resolved_root=AUTHORIZATION_ID,
        stage=STAGE_ID,
        entry_boundary=BOUNDARY_ID,
        role=Role.IMPLEMENTER,
        bounds=writing_bounds(),
        declared_closed=True,
    )


def input_package() -> InputPackage:
    return InputPackage(
        identity=INPUT_PACKAGE_ID,
        authoritative_inputs=(
            ObjectiveProductionReference(production=artifact_production()),
            EntryStateBoundaryReference(entry_boundary=BOUNDARY_ID),
        ),
        non_basis_context=("supplied context",),
    )


def worker_activation() -> WorkerActivation:
    return WorkerActivation(
        identity=ACTIVATION_ID,
        envelope=ENVELOPE_ID,
        role=Role.IMPLEMENTER,
        input_package=INPUT_PACKAGE_ID,
        provider=Present[ProviderAssignment](
            value=ProviderAssignment(provider_reference="vendor-session-token")
        ),
        completed=True,
    )


def entry_state_boundary() -> EntryStateBoundary:
    return EntryStateBoundary(
        identity=BOUNDARY_ID,
        baseline=BASELINE_ID,
        pre_existing_working_tree_state=("M CLAUDE.md",),
        pre_existing_index_state=(),
    )


def classification_context() -> ClassificationContext:
    return ClassificationContext(authorization=AUTHORIZATION_ID, entry_boundary=BOUNDARY_ID)


def activation_effect() -> ActivationEffect:
    return ActivationEffect(
        identity=ActivationEffectId(
            parent_activation=ACTIVATION_ID, local_discriminator="effect-token"
        ),
        observed_state=("src/gpauto/identity.py written",),
        within_producing_envelope=True,
    )


def unaccounted_mutation() -> UnaccountedMutation:
    return UnaccountedMutation(
        identity=MUTATION_ID,
        context=classification_context(),
        observed_state=("unexpected file",),
        unexplained_portion=("unexpected file",),
        affected_envelopes=(ENVELOPE_ID,),
        producing_activation=NotObserved(),
    )


def artifact_content() -> ArtifactContent:
    return ArtifactContent(identity=CONTENT_ID)


def artifact_production() -> ObjectiveArtifactProduction:
    """One production occurrence, objective — AP-03 §8.3's objective evidence."""
    return ObjectiveArtifactProduction(
        identity=PRODUCTION_ID,
        content=CONTENT_ID,
        provenance=Provenance.OBJECTIVE,
        attributed_to=ActivationAttribution(activation=ACTIVATION_ID),
    )


def worker_authored_production() -> WorkerAuthoredArtifactProduction:
    """The same content, produced on a different occasion, by authorship.

    Deliberately shares `CONTENT_ID` with the objective production above: identical
    content arising from two occurrences is exactly the case `AP03-I19` exists for, and
    the copy inherits none of the measurement's standing.
    """
    return WorkerAuthoredArtifactProduction(
        identity=ArtifactProductionId(value="worker-authored-production-token"),
        content=CONTENT_ID,
        provenance=Provenance.WORKER_AUTHORED,
        attributed_to=ActivationAttribution(activation=ACTIVATION_ID),
    )


def finding() -> Finding:
    return Finding(
        identity=FINDING_ID,
        stage=STAGE_ID,
        originating_authorization=AUTHORIZATION_ID,
        originating_activation=ACTIVATION_ID,
    )


def frozen_finding_set() -> FrozenFindingSet:
    return FrozenFindingSet(
        identity=FROZEN_SET_ID,
        stage=STAGE_ID,
        resolved_root=AUTHORIZATION_ID,
        originating_activation=ACTIVATION_ID,
        members=(FINDING_ID,),
    )


def empty_frozen_finding_set() -> FrozenFindingSet:
    """A zero-finding PASS: a real, fully-identified, empty set (`AP03-I36`)."""
    return FrozenFindingSet(
        identity=FrozenFindingSetId(value="empty-frozen-set-token"),
        stage=STAGE_ID,
        resolved_root=AUTHORIZATION_ID,
        originating_activation=ACTIVATION_ID,
        members=(),
    )


def remediation_obligation() -> RemediationObligation:
    return RemediationObligation(
        identity=RemediationObligationId(
            parent_frozen_set=FROZEN_SET_ID, member_finding=FINDING_ID
        )
    )


def closure_assessment() -> ClosureAssessment:
    return ClosureAssessment(
        identity=ClosureAssessmentId(
            assessed_finding=FINDING_ID, closure_activation=ACTIVATION_ID
        )
    )


def post_freeze_candidate() -> PostFreezeCandidate:
    return PostFreezeCandidate(
        identity=CANDIDATE_ID, stage=STAGE_ID, observing_activation=ACTIVATION_ID
    )


def owner_decision() -> OwnerDecision:
    """A stage-outcome acceptance: settles the past, produces no authorization."""
    return OwnerDecision(
        identity=DECISION_ID,
        stage=STAGE_ID,
        act=NonAuthorizingDecision(
            kind=OwnerDecisionKind.STAGE_OUTCOME_ACCEPTANCE,
            produced_authorization=KnownAbsent(
                basis="acceptance settles the past and confers nothing forward"
            ),
        ),
    )


def authorizing_owner_decision() -> OwnerDecision:
    """A next-stage authorization: a separate, later act that does produce one."""
    return OwnerDecision(
        identity=OwnerDecisionId(value="next-stage-decision-token"),
        stage=STAGE_ID,
        act=AuthorizingDecision(
            kind=OwnerDecisionKind.NEXT_STAGE_AUTHORIZATION,
            produced_authorization=Present[OwnerAuthorizationId](
                value=OTHER_AUTHORIZATION_ID
            ),
        ),
    )


def exceptional_recovery_decision() -> OwnerDecision:
    """AP-03 §11.2's one conditional row: produces one *only if* it authorizes work."""
    return OwnerDecision(
        identity=OwnerDecisionId(value="recovery-decision-token"),
        stage=STAGE_ID,
        act=ExceptionalRecoveryDecision(
            produced_authorization=KnownAbsent(basis="the recovery act abandons the stage")
        ),
    )


def stage_outcome() -> StageOutcome:
    return StageOutcome(
        identity=StageOutcomeId(parent_stage=STAGE_ID, local_discriminator="outcome-token"),
        disposition=StageOutcomeDisposition.ACCEPTED,
        established_by=DECISION_ID,
    )


def refusal() -> Refusal:
    return Refusal(
        identity=REFUSAL_ID,
        case=GovernanceCase.CASE_A,
        stage=STAGE_ID,
        branch="branch",
        role=Present[Role](value=Role.IMPLEMENTER),
        resolved_root=Present[OwnerAuthorizationId](value=AUTHORIZATION_ID),
        envelope=Present[AuthorityEnvelopeId](value=ENVELOPE_ID),
        condition="write outside the write boundary",
        observed_value="docs/",
        bound_value="src/",
        refused_action_class=ActionClass(name="edit-project-file"),
    )


def envelope_violation() -> EnvelopeViolation:
    return EnvelopeViolation(
        identity=VIOLATION_ID,
        case=GovernanceCase.CASE_B,
        envelope=ENVELOPE_ID,
        resolved_root=AUTHORIZATION_ID,
        stage=STAGE_ID,
        role=Role.IMPLEMENTER,
        violating_activation=ACTIVATION_ID,
        action_class=ActionClass(name="edit-project-file"),
        boundary_crossed="write boundary",
        unexplained_portion=("docs/unexpected.md",),
        not_prevented=True,
    )


def suspended_authorization() -> OwnerAuthorization:
    """An authorization suspended by an unresolved governance event (`V-08`)."""
    return owner_authorization().model_copy(
        update={"liveness": SuspendedDisposition(established_by_event=REFUSAL_ID)}
    )


def consumed_authorization() -> OwnerAuthorization:
    """An authorization consumed by a StageOutcome, and still an instance (`AP03-I35`)."""
    return owner_authorization().model_copy(
        update={
            "liveness": ConsumedDisposition(
                established_by_outcome=StageOutcomeId(
                    parent_stage=STAGE_ID, local_discriminator="outcome-token"
                )
            )
        }
    )


EVERY_ENTITY: tuple[tuple[str, DomainEntity], ...] = (
    ("Project", project()),
    ("GovernedStage", governed_stage()),
    ("StageContract", stage_contract()),
    ("RepositoryBoundary", repository_boundary()),
    ("BaselineIdentity", baseline_identity()),
    ("AuthorizationRecord", authorization_record()),
    ("OwnerAuthorization", owner_authorization()),
    ("CandidateExclusion", candidate_exclusion()),
    ("AuthorityAmbiguity", authority_ambiguity_distinct()),
    ("RootResolution", root_resolution()),
    ("AuthorityEnvelope", authority_envelope()),
    ("InputPackage", input_package()),
    ("WorkerActivation", worker_activation()),
    ("EntryStateBoundary", entry_state_boundary()),
    ("ActivationEffect", activation_effect()),
    ("UnaccountedMutation", unaccounted_mutation()),
    ("ArtifactContent", artifact_content()),
    ("ArtifactProduction", artifact_production()),
    ("Finding", finding()),
    ("FrozenFindingSet", frozen_finding_set()),
    ("RemediationObligation", remediation_obligation()),
    ("ClosureAssessment", closure_assessment()),
    ("PostFreezeCandidate", post_freeze_candidate()),
    ("OwnerDecision", owner_decision()),
    ("StageOutcome", stage_outcome()),
    ("Refusal", refusal()),
    ("EnvelopeViolation", envelope_violation()),
)
"""Every AP-03 entity this stage implements, one well-formed instance each."""
