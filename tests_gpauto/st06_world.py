"""`GP-AUTO-ST-06` test support: authorization worlds, one defect at a time — test code only.

Design basis: AP-11 §16 `GP-AUTO-ST-06` (Tests, Negative tests); the frozen ST-06
clarification §17 (test obligations), S6G2-2, S6G3-1…S6G3-7; correction `ST06PC-1` SP6-29.

A `Scope` is one project, stage, contract, repository boundary and baseline, as the outside
party supplies them. `content()` is a **valid** authorization for it: every worker role in
`RA-06`, and one `RA-07` member per worker role, each shaped exactly as S6G2-2(c)/(d)
require — writers `WRITING` with Git `NONE`, reviewers `READ_ONLY` with Git
`BOUNDED_READ`, `E-20 ⊆ E-11`, REMEDIATOR ⊆ IMPLEMENTER. Every defect a test needs is
this value with one thing changed, so the test shows that one thing is what decides.

Ingest rows are written by `st03_ingest`, the outside-party stand-in (`SRB11-21`); every
coordination record ST-06 does not own — the M2 chain, the boundary, an activation, a
frozen set, a revocation — is written through the store here as a fixture, in the order
its referents come into existence. Nothing here evaluates a guard.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from gpauto import authority
from gpauto.absence import Carried, KnownAbsent, NotApplicable, Present
from gpauto.activation import (
    EntryStateBoundaryReference,
    InputPackage,
    ProviderAssignment,
)
from gpauto.authorization import (
    AuthorityBearingContent,
    AuthorizationRecord,
    LiveDisposition,
    RevokedDisposition,
)
from gpauto.bounds import (
    ActionClass,
    AuthoritativeInputDesignation,
    AuthorityCeilingMember,
    ReadBoundary,
    ScopeFrameBounds,
    ToolCategory,
    WriteBoundary,
)
from gpauto.content_identity import identify_stage_contract
from gpauto.coordination_identity import (
    CycleOccurrenceId,
    DispositionRecordId,
    M2PositionEntryId,
)
from gpauto.coordination_records import (
    CycleOccurrence,
    DispositionEstablishingRecord,
    EntryStateBoundaryRecord,
    InputPackageRecord,
    M2PositionEntry,
    SessionAnnotation,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import M2Edge, M2Position
from gpauto.governance import OwnerDecision, RevocationDecision
from gpauto.identity import (
    AuthorizationRecordId,
    BaselineIdentityId,
    EntryStateBoundaryId,
    FrozenFindingSetId,
    GovernedStageId,
    InputPackageId,
    OwnerAuthorizationId,
    OwnerDecisionId,
    ProjectId,
    RepositoryBoundaryId,
    WorkerActivationId,
)
from gpauto.minting import mint_value
from gpauto.preimage import StageContractContent
from gpauto.repository import EntryStateBoundary
from gpauto.review import FrozenFindingSet
from gpauto.scope_frame import (
    BaselineIdentity,
    GovernedStage,
    Project,
    RepositoryBoundary,
    StageContract,
)
from gpauto.state_machine_model import BOUNDARY_FIXED, FALSE, TRUE, UNACCOUNTED_MUTATION
from gpauto.store import CoordinationStore
from gpauto.store_schema import (
    FORMAT_COLUMN,
    Layout,
    Row,
    build_catalogue,
    child_key,
    flatten,
    table_columns,
)
from gpauto.vocabulary import (
    BoundedPreflightPermission,
    ExternalActionClass,
    GitCapabilityClass,
    OwnerDecisionKind,
    Role,
    WriteMode,
)
from st03_ingest import IngestRecord, external_connection, ingest

ABSENT = KnownAbsent(basis="affirmatively absent in this fixture")
WORKERS = (
    Role.IMPLEMENTER,
    Role.DISCOVERY_REVIEWER,
    Role.REMEDIATOR,
    Role.BOUNDED_CLOSURE_VERIFIER,
)
SUPPLIED = {BOUNDARY_FIXED.name: TRUE, UNACCOUNTED_MUTATION.name: FALSE}
"""ST-07's and ST-08's two `C1` facts, as those stages would supply them."""


@dataclass(frozen=True)
class Scope:
    """One stage's scope frame, as the outside party supplies it."""

    project: ProjectId
    stage: GovernedStageId
    contract: StageContract
    repository: RepositoryBoundaryId
    baseline: BaselineIdentityId

    def frame(self) -> ScopeFrameBounds:
        return ScopeFrameBounds(
            project=self.project,
            stage=self.stage,
            repository_boundary=self.repository,
            baseline=self.baseline,
        )

    def referents(self) -> list[IngestRecord]:
        return [
            Project(identity=self.project),
            GovernedStage(identity=self.stage, project=self.project),
            RepositoryBoundary(
                identity=self.repository, repository_location="repository", branch="main"
            ),
            BaselineIdentity(identity=self.baseline, committed_history_identity="commit"),
            self.contract,
        ]


def scope(tag: str = "") -> Scope:
    content = StageContractContent(
        objective=f"objective{tag}",
        deliverable_boundary=("src/",),
        explicit_out_of_stage=("docs/",),
        implementation_instructions=("implement",),
        review_instructions=("review",),
        acceptance_criteria=("accepted when tests pass",),
    )
    identified = identify_stage_contract(content)
    return Scope(
        project=ProjectId(value=f"project{tag}"),
        stage=GovernedStageId(value=f"stage{tag}"),
        contract=StageContract(identity=identified.identity, **content.model_dump()),
        repository=RepositoryBoundaryId(value=f"repository{tag}"),
        baseline=BaselineIdentityId(value=f"baseline{tag}"),
    )


def writer(s: Scope, role: Role = Role.IMPLEMENTER) -> AuthorityCeilingMember:
    """An S6G2-2(c) member. The REMEDIATOR's is narrower than the IMPLEMENTER's (f)."""
    narrower = role == Role.REMEDIATOR
    return AuthorityCeilingMember(
        role_applicability=role,
        action_classes=(ActionClass(name="edit"),)
        if narrower
        else (ActionClass(name="edit"), ActionClass(name="execute")),
        read_boundary=ReadBoundary(scopes=("src/",) if narrower else ("src/", "tests/")),
        write_mode=WriteMode.WRITING,
        write_boundary=Carried[WriteBoundary](
            value=WriteBoundary(scopes=("src/a/",) if narrower else ("src/a/", "src/b/"))
        ),
        tool_categories=(ToolCategory(name="file-edit"),),
        external_action_classes=(),
        git_capability_class=GitCapabilityClass.NONE,
        scope_frame=s.frame(),
        authoritative_input_designation=NotApplicable(),
    )


def reviewer(s: Scope, role: Role = Role.DISCOVERY_REVIEWER) -> AuthorityCeilingMember:
    """An S6G2-2(d) member, with `E-20 ⊆ E-11` (e)."""
    return AuthorityCeilingMember(
        role_applicability=role,
        action_classes=(ActionClass(name="read"),),
        read_boundary=ReadBoundary(scopes=("src/", "tests/")),
        write_mode=WriteMode.READ_ONLY,
        write_boundary=NotApplicable(),
        tool_categories=(ToolCategory(name="file-read"),),
        external_action_classes=(),
        git_capability_class=GitCapabilityClass.BOUNDED_READ,
        scope_frame=s.frame(),
        authoritative_input_designation=Carried[AuthoritativeInputDesignation](
            value=AuthoritativeInputDesignation(designated_scopes=("src/",))
        ),
    )


def ceiling(s: Scope) -> tuple[AuthorityCeilingMember, ...]:
    return (
        writer(s),
        reviewer(s),
        writer(s, Role.REMEDIATOR),
        reviewer(s, Role.BOUNDED_CLOSURE_VERIFIER),
    )


def member_of(members: tuple[AuthorityCeilingMember, ...], role: Role) -> AuthorityCeilingMember:
    (found,) = [m for m in members if m.role_applicability == role]
    return found


def replace_member(
    members: tuple[AuthorityCeilingMember, ...], role: Role, **changes: Any
) -> tuple[AuthorityCeilingMember, ...]:
    """The ceiling with `role`'s member changed in the named dimensions, and nothing else."""
    return tuple(
        m.model_copy(update=changes) if m.role_applicability == role else m for m in members
    )


def content(s: Scope, **changes: Any) -> AuthorityBearingContent:
    """A valid role-indexed authorization for `s`, with `changes` applied."""
    base = AuthorityBearingContent(
        project=s.project,
        stage=s.stage,
        contract=s.contract.identity,
        repository_boundary=s.repository,
        baseline=s.baseline,
        authorized_roles=WORKERS,
        authority_ceiling=ceiling(s),
        owner_human_label_present=True,
        preflight_permission=BoundedPreflightPermission.PERMITTED,
        liveness=LiveDisposition(),
    )
    return base.model_copy(update=changes)


def record(s: Scope, name: str, authorization: str = "root", **changes: Any) -> AuthorizationRecord:
    return AuthorizationRecord(
        identity=AuthorizationRecordId(value=name),
        authorization_identity=OwnerAuthorizationId(value=authorization),
        content=content(s, **changes),
    )


def root_id(name: str = "root") -> OwnerAuthorizationId:
    return OwnerAuthorizationId(value=name)


def supply(store: CoordinationStore, s: Scope, records: Iterable[IngestRecord]) -> None:
    """The outside party's ingest: the scope's referents, then the authorization records."""
    ingest(store.path, [*s.referents(), *records])


def revoke(store: CoordinationStore, s: Scope, authorization: OwnerAuthorizationId) -> None:
    """Make an instance non-live: an OWNER revocation (`RC-13`) and its `RC-35` record."""
    decision = OwnerDecision(
        identity=OwnerDecisionId(value=f"revoke-{authorization.value}"),
        stage=s.stage,
        act=RevocationDecision(
            kind=OwnerDecisionKind.REVOCATION,
            revoked=authorization,
            produced_authorization=ABSENT,
            corrects=ABSENT,
        ),
    )
    ingest(store.path, [decision])
    store.create(
        DispositionEstablishingRecord(
            identity=DispositionRecordId(authorization=authorization, discriminator=mint_value()),
            disposition=RevokedDisposition(established_by_decision=decision.identity),
        )
    )


def resolve(store: CoordinationStore, s: Scope) -> authority.Resolved | authority.StillOpen:
    """`A1` then the completing act, as a coordinator would present them."""
    opened = authority.open_resolution(store, s.project, s.stage)
    assert isinstance(opened, authority.Opened), opened
    done = authority.complete_resolution(store, opened.resolution)
    assert isinstance(done, authority.Resolved | authority.StillOpen), done
    return done


def m2(
    root: OwnerAuthorizationId,
    state: M2Position,
    edge: M2Edge,
    predecessor: M2PositionEntry | None,
    cycle: CycleOccurrenceId | None = None,
) -> M2PositionEntry:
    return M2PositionEntry(
        identity=M2PositionEntryId(epoch_root=root, discriminator=mint_value()),
        state=state,
        edge=edge,
        predecessor=Present[M2PositionEntryId](value=predecessor.identity)
        if predecessor
        else ABSENT,
        cycle_occurrence=Present[CycleOccurrenceId](value=cycle) if cycle else ABSENT,
    )


@dataclass
class Epoch:
    """A resolved root with its boundary fixed, and the M2 entries a derivation keys on."""

    store: CoordinationStore
    scope: Scope
    root: OwnerAuthorizationId
    boundary: EntryStateBoundaryRecord
    entries: dict[M2Position, M2PositionEntry] = field(default_factory=dict)
    handles: dict[str, BaseModel] = field(default_factory=dict)

    def predecessor(self, step: M2Position) -> M2PositionEntry:
        """The M2 entry a derivation for `step` names (`MC-15`): the one before it."""
        before = {
            M2Position.S3_IMPLEMENTATION_ACTIVE: M2Position.S2_ENTRY_BOUNDARY_FIXED,
            M2Position.S4_DISCOVERY_ACTIVE: M2Position.S3_IMPLEMENTATION_ACTIVE,
            M2Position.S6_REMEDIATION_ACTIVE: M2Position.S5_FINDING_SET_FROZEN,
            M2Position.S7_CLOSURE_ACTIVE: M2Position.S6_REMEDIATION_ACTIVE,
        }
        return self.entries[before[step]]

    def derive(self, role: Role, step: M2Position, root: OwnerAuthorizationId | None = None) -> Any:
        cycle = self.handles.get("cycle")
        occurrence = (
            Present[CycleOccurrenceId](value=cycle.identity)  # type: ignore[attr-defined]
            if cycle is not None
            and step in (M2Position.S6_REMEDIATION_ACTIVE, M2Position.S7_CLOSURE_ACTIVE)
            else ABSENT
        )
        return authority.record_envelope(
            self.store,
            root or self.root,
            role,
            step,
            self.predecessor(step).identity,
            occurrence,
            dict(SUPPLIED),
        )


def epoch(store: CoordinationStore, s: Scope, root: OwnerAuthorizationId) -> Epoch:
    """After `A2`: the epoch opens (`B1`) and its boundary is fixed (`B2`) — fixtures of
    ST-07's and ST-16's acts, written so a derivation has its inputs."""
    s1 = m2(root, M2Position.S1_EPOCH_OPENED, M2Edge.B1, None)
    store.create(s1)
    boundary = EntryStateBoundaryRecord(
        boundary=EntryStateBoundary(
            identity=EntryStateBoundaryId(value=mint_value()),
            baseline=s.baseline,
            pre_existing_working_tree_state=(),
            pre_existing_index_state=(),
        ),
        resolved_root=root,
    )
    s2 = m2(root, M2Position.S2_ENTRY_BOUNDARY_FIXED, M2Edge.B2, s1)
    store.create_unit((boundary, s2))
    return Epoch(
        store,
        s,
        root,
        boundary,
        {M2Position.S1_EPOCH_OPENED: s1, M2Position.S2_ENTRY_BOUNDARY_FIXED: s2},
    )


def resolved_epoch(store: CoordinationStore, s: Scope, *records: AuthorizationRecord) -> Epoch:
    """Ingest `records` (default: one valid record for `root`), resolve, and open the epoch."""
    supply(store, s, records or (record(s, "record-a"),))
    done = resolve(store, s)
    assert isinstance(done, authority.Resolved), done
    return epoch(store, s, root_id())


UNCOVERED_FORMAT = "gpauto.coordination-record/999"
"""A record format this definition does not cover: a row under it decodes as unreadable."""


def write_unreadable(store: CoordinationStore, record: BaseModel) -> None:
    """Write `record` as the outside party would, under a format this definition does not
    cover, so the store surfaces it as an `UnreadableRecord` (`VM-6`). The rows are the
    store's own flattening; only the format column differs."""
    layout = build_catalogue().by_record[type(record)]
    row, children = flatten(layout, record)
    row[FORMAT_COLUMN] = UNCOVERED_FORMAT
    with external_connection(store.path) as connection:
        _insert_row(connection, layout, row)
        for child in layout.children:
            parent = {column: row[column] for column in child_key(child)[:-1]}
            for member in children.get(child.name, []):
                _insert_row(connection, child, {**parent, **member})


def _insert_row(connection: sqlite3.Connection, layout: Layout, row: Row) -> None:
    names = [column.name for column in table_columns(layout)]
    placeholders = ", ".join("?" for _ in names)
    connection.execute(
        f"INSERT INTO {layout.name} ({', '.join(names)}) VALUES ({placeholders})",
        [row.get(name) for name in names],
    )


def to_findings_branch(
    e: Epoch, members: tuple[str, ...] = (), *, readable_set: bool = True
) -> Epoch:
    """Carry the epoch to `S6`: the IMPLEMENTER envelope derived, an activation under it,
    `S3`…`S5`, a frozen set, and the `B6a` cycle occurrence with its `S6` entry. With
    `readable_set` false, the frozen set is written under an uncovered format instead."""
    derived = e.derive(Role.IMPLEMENTER, M2Position.S3_IMPLEMENTATION_ACTIVE)
    assert isinstance(derived, authority.EnvelopeRecorded), derived
    s3 = m2(
        e.root,
        M2Position.S3_IMPLEMENTATION_ACTIVE,
        M2Edge.B3,
        e.entries[M2Position.S2_ENTRY_BOUNDARY_FIXED],
    )
    package = InputPackageRecord(
        package=InputPackage(
            identity=InputPackageId(value=mint_value()),
            authoritative_inputs=(
                EntryStateBoundaryReference(entry_boundary=e.boundary.boundary.identity),
            ),
            non_basis_context=(),
        ),
        cycle_occurrence=ABSENT,
    )
    e.store.create_unit((s3, package))
    activation = WorkerActivationRecord(
        identity=WorkerActivationId(value=mint_value()),
        envelope=derived.record.envelope.identity,
        role=Role.IMPLEMENTER,
        input_package=package.package.identity,
        provider=Present[ProviderAssignment](
            value=ProviderAssignment(provider_reference="vendor-x")
        ),
        session=Present[SessionAnnotation](value=SessionAnnotation(session_reference="s-1")),
        stage=e.scope.stage,
        branch="main",
        resolved_root=e.root,
        cycle_occurrence=ABSENT,
    )
    e.store.create(activation)
    s4 = m2(e.root, M2Position.S4_DISCOVERY_ACTIVE, M2Edge.B4, s3)
    frozen = FrozenFindingSet(
        identity=FrozenFindingSetId(value=mint_value()),
        stage=e.scope.stage,
        resolved_root=e.root,
        originating_activation=activation.identity,
        members=(),
    )
    s5 = m2(e.root, M2Position.S5_FINDING_SET_FROZEN, M2Edge.B5, s4)
    if readable_set:
        e.store.create_unit((s4, frozen, s5))
    else:
        e.store.create(s4)
        write_unreadable(e.store, frozen)
        e.store.create(s5)
    cycle = CycleOccurrence(
        identity=CycleOccurrenceId(value=mint_value()),
        establishing_edge=M2Edge.B6a,
        predecessor_entry=s5.identity,
        target_state=M2Position.S6_REMEDIATION_ACTIVE,
        predecessor_closure_activation=ABSENT,
        envelope=ABSENT,
        activation=ABSENT,
    )
    s6 = m2(e.root, M2Position.S6_REMEDIATION_ACTIVE, M2Edge.B6a, s5, cycle.identity)
    e.store.create_unit((cycle, s6))
    e.entries.update(
        {
            M2Position.S3_IMPLEMENTATION_ACTIVE: s3,
            M2Position.S4_DISCOVERY_ACTIVE: s4,
            M2Position.S5_FINDING_SET_FROZEN: s5,
            M2Position.S6_REMEDIATION_ACTIVE: s6,
        }
    )
    e.handles.update(implementer=derived.record, frozen=frozen, cycle=cycle)
    return e


EGRESS = ExternalActionClass.EGRESS
SIDE_EFFECT = ExternalActionClass.BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA
