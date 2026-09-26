"""Authoritative record sets for the ST-04 derivation tests — test support only.

Design basis: AP-11 ST-04 derivation-ownership amendment §2 (Tests, Restart/persistence
evidence cells); AP-07 §8 (`DV-12`); AP-04 §4.1, §5.2, §5.3.1, §6; AP-05 §6.2.

Two sources of records, for two different questions.

* `Epoch` builds **in-memory** record sets for the semantic cases — waivers, deferrals,
  O6 changes, completed and unadopted activations, cycles, halts, suspensions. The
  derivations are pure functions of an `AuthoritativeRecords` value, so these cases need
  no store. It is **not** a state machine: it lays records down in the order their
  referents come into existence and never evaluates a guard (ST-05's).
* `extended_world` is the ST-03 world with a second, later activation and an OWNER waiver
  added through the store's own create path and the outside party's ingest path, so the
  restart evidence runs over records that were **persisted and read back**, not built.

`rendered` turns a derivation result into a canonical, hash-seed-independent string, so a
result computed in another process can be compared with one computed here.
"""

from __future__ import annotations

import dataclasses
import enum
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel

from gpauto import derivations as dv
from gpauto.absence import Present
from gpauto.authorization import (
    ConsumedDisposition,
    RevokedDisposition,
    SuspendedDisposition,
)
from gpauto.bounds import ActionClass
from gpauto.coordination_identity import (
    ConformanceDeterminationId,
    CycleOccurrenceId,
    DispositionRecordId,
    GovernanceEventResolutionId,
    HaltOccurrenceId,
    M1PositionEntryId,
    M2PositionEntryId,
    M3PositionEntryId,
    M4PositionEntryId,
)
from gpauto.coordination_records import (
    ActivationEffectRecord,
    AdoptionDetermination,
    AuthorityEnvelopeRecord,
    ClosureAssessmentRecord,
    ConformanceDetermination,
    CycleOccurrence,
    DispositionEstablishingRecord,
    EffectEnvelopeConformance,
    EntryStateBoundaryRecord,
    EnvelopeConformanceDetermination,
    GovernanceEventResolution,
    HaltOccurrence,
    InputPackageRecord,
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
    NoResolutionResult,
    RefusalRecord,
    ResidueDetermination,
    ResolutionResult,
    RootResolutionRecord,
    SessionRecord,
    StructuralConformanceDetermination,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import (
    ClosedVerdict,
    M1Edge,
    M1Position,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
    M4Edge,
    NotClosedVerdict,
    StructuralConformanceResult,
)
from gpauto.envelope import AuthorityEnvelope
from gpauto.governance import (
    DisputeResolutionDecision,
    ObligationChangeDecision,
    ObligationExtinguishingDecision,
    OwnerDecision,
    Refusal,
    RefusalResolutionDecision,
    RevocationDecision,
    StageOutcomeDecision,
)
from gpauto.identity import (
    ActivationEffectId,
    AuthorityEnvelopeId,
    ClosureAssessmentId,
    EntryStateBoundaryId,
    FindingId,
    FrozenFindingSetId,
    InputPackageId,
    OwnerAuthorizationId,
    OwnerDecisionId,
    RefusalId,
    RemediationObligationId,
    RootResolutionId,
    StageOutcomeId,
    WorkerActivationId,
)
from gpauto.minting import mint_value
from gpauto.repository import ClassificationContext, EntryStateBoundary
from gpauto.review import ClosureAssessment, FrozenFindingSet, RemediationObligation
from gpauto.store import CoordinationStore
from gpauto.vocabulary import (
    AuthorizationDisposition,
    GovernanceCase,
    OwnerDecisionKind,
    Role,
    StageOutcomeDisposition,
)
from st03_ingest import ingest
from st03_world import ABSENT, BRANCH, Frame, World, bounds, frame, world

TEST_TREE = Path(__file__).resolve().parent

STEP_EDGE: dict[M2Position, M2Edge] = {
    M2Position.S1_EPOCH_OPENED: M2Edge.B1,
    M2Position.S2_ENTRY_BOUNDARY_FIXED: M2Edge.B2,
    M2Position.S3_IMPLEMENTATION_ACTIVE: M2Edge.B3,
    M2Position.S4_DISCOVERY_ACTIVE: M2Edge.B4,
    M2Position.S5_FINDING_SET_FROZEN: M2Edge.B5,
    M2Position.S7_CLOSURE_ACTIVE: M2Edge.B7,
    M2Position.S8_GATE_REACHED: M2Edge.B8,
    M2Position.S9_EPOCH_HALTED: M2Edge.B9,
    M2Position.S10_EPOCH_SETTLED: M2Edge.B11,
    M2Position.S11_EPOCH_AUTHORITY_ENDED: M2Edge.B12,
}
"""The edge each builder step records — a label for the fixture's entries, not a graph."""


def token() -> str:
    return mint_value()


def present[T](value: T) -> Present[T]:
    """`Present` parametrized by the value's own type, as strict validation requires."""
    generic: Any = Present
    return cast(Present[T], generic[type(value)](value=value))


@dataclass
class Epoch:
    """One epoch's records, laid down in the order their referents exist."""

    tag: str = "e"
    frame: Frame = field(init=False)
    records: list[BaseModel] = field(default_factory=list)
    head: M2PositionEntry | None = None
    decisions: int = 0

    def __post_init__(self) -> None:
        self.frame = frame(self.tag)[0]
        self.m2(M2Position.S1_EPOCH_OPENED)
        self.boundary = EntryStateBoundaryRecord(
            boundary=EntryStateBoundary(
                identity=EntryStateBoundaryId(value=token()),
                baseline=self.frame.baseline,
                pre_existing_working_tree_state=("M README.md",),
                pre_existing_index_state=("A staged.txt",),
            ),
            resolved_root=self.root,
        )
        self.records.append(self.boundary)
        self.m2(M2Position.S2_ENTRY_BOUNDARY_FIXED)

    @property
    def root(self) -> OwnerAuthorizationId:
        return self.frame.root

    def snapshot(self, *others: Epoch) -> dv.AuthoritativeRecords:
        records = [*self.records]
        for other in others:
            records.extend(other.records)
        return dv.AuthoritativeRecords(tuple(records))

    # --- M2 ----------------------------------------------------------------------------

    def m2(
        self,
        state: M2Position,
        edge: M2Edge | None = None,
        cycle: CycleOccurrenceId | None = None,
    ) -> M2PositionEntry:
        entry = M2PositionEntry(
            identity=M2PositionEntryId(epoch_root=self.root, discriminator=token()),
            state=state,
            edge=edge or STEP_EDGE[state],
            predecessor=present(self.head.identity) if self.head else ABSENT,
            cycle_occurrence=present(cycle) if cycle else ABSENT,
        )
        self.records.append(entry)
        self.head = entry
        return entry

    def cycle(self, predecessor_closure: WorkerActivationId | None) -> CycleOccurrence:
        """An `RC-33` occurrence and its `S6` entry (`B6a` first, `B15` after)."""
        assert self.head is not None
        occurrence = CycleOccurrence(
            identity=CycleOccurrenceId(value=token()),
            establishing_edge=M2Edge.B15 if predecessor_closure else M2Edge.B6a,
            predecessor_entry=self.head.identity,
            target_state=M2Position.S6_REMEDIATION_ACTIVE,
            predecessor_closure_activation=present(predecessor_closure)
            if predecessor_closure
            else ABSENT,
            envelope=ABSENT,
            activation=ABSENT,
        )
        self.records.append(occurrence)
        self.m2(M2Position.S6_REMEDIATION_ACTIVE, occurrence.establishing_edge, occurrence.identity)
        return occurrence

    # --- M3: envelope, activation, completion -------------------------------------------

    def activation(
        self,
        role: Role,
        *,
        outcome: str = "completed",
        effects: tuple[tuple[str, bool], ...] = (),
        cycle: CycleOccurrence | None = None,
    ) -> WorkerActivationRecord:
        """An envelope derived from the current M2 entry, its activation, and — per
        `outcome` — `C4` with its adoption record, `C5` closed unadopted, or running."""
        assert self.head is not None
        occurrence = present(cycle.identity) if cycle else ABSENT
        envelope = AuthorityEnvelopeRecord(
            envelope=AuthorityEnvelope(
                identity=AuthorityEnvelopeId(value=token()),
                resolved_root=self.root,
                stage=self.frame.stage,
                entry_boundary=self.boundary.boundary.identity,
                role=role,
                bounds=bounds(self.frame),
                declared_closed=True,
            ),
            cycle_occurrence=occurrence,
            predecessor_entry=self.head.identity,
            target_state=self.head.state,
        )
        activation = WorkerActivationRecord(
            identity=WorkerActivationId(value=token()),
            envelope=envelope.envelope.identity,
            role=role,
            input_package=InputPackageId(value=token()),
            provider=ABSENT,
            session=ABSENT,
            stage=self.frame.stage,
            branch=BRANCH,
            resolved_root=self.root,
            cycle_occurrence=occurrence,
        )
        derived = self.m3(envelope.envelope.identity, M3Position.ENVELOPE_DERIVED, M3Edge.C1, None)
        running = self.m3(
            envelope.envelope.identity, M3Position.ACTIVATION_RUNNING, M3Edge.C2, derived
        )
        self.records.extend((envelope, activation))
        recorded = tuple(
            ActivationEffectRecord(
                identity=ActivationEffectId(
                    parent_activation=activation.identity, local_discriminator=token()
                ),
                observed_state=(observed,),
                cycle_occurrence=occurrence,
            )
            for observed, _ in effects
        )
        self.records.extend(recorded)
        if outcome == "running":
            return activation
        self.determination(
            activation.identity,
            EnvelopeConformanceDetermination(
                effects=tuple(
                    EffectEnvelopeConformance(effect=effect.identity, within_envelope=within)
                    for effect, (_, within) in zip(recorded, effects, strict=True)
                ),
                violations=ABSENT,
            ),
        )
        if outcome == "completed":
            self.determination(activation.identity, AdoptionDetermination())
            self.m3(envelope.envelope.identity, M3Position.ACTIVATION_COMPLETED, M3Edge.C4, running)
        else:
            assert outcome == "unadopted", outcome
            self.m3(
                envelope.envelope.identity,
                M3Position.ACTIVATION_CLOSED_UNADOPTED,
                M3Edge.C5,
                running,
            )
        return activation

    def m3(
        self,
        envelope: AuthorityEnvelopeId,
        state: M3Position,
        edge: M3Edge,
        predecessor: M3PositionEntry | None,
    ) -> M3PositionEntry:
        entry = M3PositionEntry(
            identity=M3PositionEntryId(envelope=envelope, discriminator=token()),
            state=state,
            edge=edge,
            predecessor=present(predecessor.identity) if predecessor else ABSENT,
        )
        self.records.append(entry)
        return entry

    def determination(self, activation: WorkerActivationId, value: BaseModel) -> None:
        self.records.append(
            ConformanceDetermination(
                identity=ConformanceDeterminationId(activation=activation, discriminator=token()),
                determination=value,  # type: ignore[arg-type]
            )
        )

    # --- freeze, obligations, closure ---------------------------------------------------

    def freeze(
        self, discovery: WorkerActivationRecord, members: int
    ) -> tuple[FrozenFindingSet, tuple[RemediationObligation, ...]]:
        findings = tuple(FindingId(value=token()) for _ in range(members))
        frozen = FrozenFindingSet(
            identity=FrozenFindingSetId(value=token()),
            stage=self.frame.stage,
            resolved_root=self.root,
            originating_activation=discovery.identity,
            members=findings,
        )
        obligations = tuple(
            RemediationObligation(
                identity=RemediationObligationId(
                    parent_frozen_set=frozen.identity, member_finding=finding
                )
            )
            for finding in findings
        )
        self.records.extend((frozen, *obligations))
        self.m2(M2Position.S5_FINDING_SET_FROZEN)
        return frozen, obligations

    def assess(
        self,
        closure: WorkerActivationRecord,
        finding: FindingId,
        *,
        closed: bool,
        cycle: CycleOccurrence | None = None,
    ) -> ClosureAssessmentRecord:
        record = ClosureAssessmentRecord(
            assessment=ClosureAssessment(
                identity=ClosureAssessmentId(
                    assessed_finding=finding, closure_activation=closure.identity
                )
            ),
            verdict=ClosedVerdict() if closed else NotClosedVerdict(indeterminacy_reason=ABSENT),
            cycle_occurrence=present(cycle.identity) if cycle else ABSENT,
        )
        self.records.append(record)
        return record

    # --- OWNER decisions (RC-13), as the outside party supplies them ----------------------

    def decide(self, act: BaseModel) -> OwnerDecision:
        self.decisions += 1
        decision = OwnerDecision(
            identity=OwnerDecisionId(value=f"decision-{self.tag}-{self.decisions}"),
            stage=self.frame.stage,
            act=act,  # type: ignore[arg-type]
        )
        self.records.append(decision)
        return decision

    def waive(
        self,
        obligation: RemediationObligationId,
        kind: OwnerDecisionKind = OwnerDecisionKind.WAIVER,
    ) -> OwnerDecision:
        return self.decide(
            ObligationExtinguishingDecision(
                kind=kind,  # type: ignore[arg-type]
                obligation=obligation,
                produced_authorization=ABSENT,
                corrects=ABSENT,
            )
        )

    def change(self, obligation: RemediationObligationId) -> OwnerDecision:
        return self.decide(
            ObligationChangeDecision(
                kind=OwnerDecisionKind.OBLIGATION_CHANGE,
                obligation=obligation,
                replacement_requirement="the replacement requirement, verbatim",
                produced_authorization=ABSENT,
            )
        )

    def dispute(self, finding: FindingId) -> OwnerDecision:
        return self.decide(
            DisputeResolutionDecision(
                kind=OwnerDecisionKind.FINDING_DISPUTE,
                member=finding,
                produced_authorization=ABSENT,
                corrects=ABSENT,
            )
        )

    def settle(
        self, outcome: StageOutcomeDisposition = StageOutcomeDisposition.ACCEPTED
    ) -> OwnerDecision:
        return self.decide(
            StageOutcomeDecision(
                kind=OwnerDecisionKind.STAGE_OUTCOME,
                context=ClassificationContext(
                    authorization=self.root, entry_boundary=self.boundary.boundary.identity
                ),
                outcome=outcome,
                produced_authorization=ABSENT,
                corrects=ABSENT,
            )
        )

    # --- governance events, halts, dispositions -----------------------------------------

    def refusal(self) -> RefusalRecord:
        record = RefusalRecord(
            refusal=Refusal(
                identity=RefusalId(value=token()),
                case=GovernanceCase.CASE_A,
                stage=self.frame.stage,
                branch=BRANCH,
                role=present(Role.REMEDIATOR),
                resolved_root=present(self.root),
                envelope=ABSENT,
                condition="write outside the write boundary",
                observed_value="docs/",
                bound_value="src/",
                refused_action_class=ActionClass(name="edit-project-file"),
            ),
            cycle_occurrence=ABSENT,
        )
        self.records.append(record)
        return record

    def halt(self, event: RefusalId, source: M2Position) -> HaltOccurrence:
        occurrence = HaltOccurrence(
            identity=HaltOccurrenceId(value=token()),
            event=event,
            source_state=source,
            cycle_occurrence=ABSENT,
        )
        self.records.append(occurrence)
        return occurrence

    def resolve(self, halt: HaltOccurrence) -> GovernanceEventResolution:
        decision = self.decide(
            RefusalResolutionDecision(
                kind=OwnerDecisionKind.REFUSAL_RESOLUTION,
                halt_occurrence=halt.identity,
                produced_authorization=ABSENT,
                corrects=ABSENT,
            )
        )
        record = GovernanceEventResolution(
            identity=GovernanceEventResolutionId(value=token()),
            halt_occurrence=halt.identity,
            decision=decision.identity,
        )
        self.records.append(record)
        return record

    def disposition(
        self,
        authorization: OwnerAuthorizationId,
        value: ConsumedDisposition | RevokedDisposition | SuspendedDisposition,
    ) -> DispositionEstablishingRecord:
        record = DispositionEstablishingRecord(
            identity=DispositionRecordId(authorization=authorization, discriminator=token()),
            disposition=value,
        )
        self.records.append(record)
        return record

    def suspend(self, authorization: OwnerAuthorizationId, event: RefusalId) -> None:
        self.disposition(authorization, SuspendedDisposition(established_by_event=event))

    def consume(self, authorization: OwnerAuthorizationId) -> StageOutcomeId:
        outcome = StageOutcomeId(parent_stage=self.frame.stage, local_discriminator=token())
        self.disposition(authorization, ConsumedDisposition(established_by_outcome=outcome))
        return outcome

    def revoke(self, authorization: OwnerAuthorizationId) -> OwnerDecisionId:
        decision = self.decide(
            RevocationDecision(
                kind=OwnerDecisionKind.REVOCATION,
                revoked=authorization,
                produced_authorization=ABSENT,
                corrects=ABSENT,
            )
        )
        self.disposition(
            authorization, RevokedDisposition(established_by_decision=decision.identity)
        )
        return decision.identity

    def m4(
        self,
        authorization: OwnerAuthorizationId,
        state: AuthorizationDisposition,
        edge: M4Edge,
        predecessor: M4PositionEntry | None,
    ) -> M4PositionEntry:
        entry = M4PositionEntry(
            identity=M4PositionEntryId(authorization=authorization, discriminator=token()),
            state=state,
            edge=edge,
            predecessor=present(predecessor.identity) if predecessor else ABSENT,
        )
        self.records.append(entry)
        return entry

    # --- M1 ----------------------------------------------------------------------------

    def resolution(
        self, completing: tuple[M1Edge, ResolutionResult] | None
    ) -> RootResolutionRecord:
        record = RootResolutionRecord(
            identity=RootResolutionId(value=token()),
            project=self.frame.project,
            stage=self.frame.stage,
            predecessor_terminal_entry=ABSENT,
            candidates=tuple(r.identity for r in self.frame.records),
        )
        a1 = M1PositionEntry(
            identity=M1PositionEntryId(resolution=record.identity, discriminator=token()),
            state=M1Position.RESOLUTION_OPEN,
            edge=M1Edge.A1,
            predecessor=ABSENT,
            result=NoResolutionResult(),
        )
        self.records.extend((record, a1))
        if completing is not None:
            edge, result = completing
            state = {
                M1Edge.A2: M1Position.ROOT_RESOLVED,
                M1Edge.A3: M1Position.ROOT_ABSENT,
                M1Edge.A4: M1Position.ROOT_CONTESTED,
            }[edge]
            self.records.append(
                M1PositionEntry(
                    identity=M1PositionEntryId(resolution=record.identity, discriminator=token()),
                    state=state,
                    edge=edge,
                    predecessor=present(a1.identity),
                    result=result,
                )
            )
        return record


# --- a persisted world, for restart evidence -------------------------------------------


@dataclass(frozen=True)
class Subjects:
    """The subjects the restart evidence derives over, as plain values for another process."""

    root: str
    other_root: str
    resolution: str
    first_activation: str
    second_activation: str
    envelope: str
    obligation_set: str
    obligation_finding: str

    def argv(self) -> list[str]:
        return [getattr(self, f.name) for f in dataclasses.fields(self)]


def extended_world(tag: str = "") -> tuple[World, Subjects]:
    """The ST-03 world, plus a later completed activation whose prior authorized state is
    the first activation's in-envelope effect, and an OWNER waiver naming the obligation."""
    built = world(tag)
    h = built.handles
    envelope1 = h["envelope"]
    activation1 = h["activation"]
    boundary = h["boundary"]
    s3 = h["s3"]
    assert isinstance(envelope1, AuthorityEnvelopeRecord)
    assert isinstance(activation1, WorkerActivationRecord)
    assert isinstance(boundary, EntryStateBoundaryRecord)
    assert isinstance(s3, M2PositionEntry)
    package = h["package"]
    assert isinstance(package, InputPackageRecord)

    envelope2 = AuthorityEnvelopeRecord(
        envelope=envelope1.envelope.model_copy(
            update={
                "identity": AuthorityEnvelopeId(value=token()),
                "role": Role.DISCOVERY_REVIEWER,
            }
        ),
        cycle_occurrence=ABSENT,
        predecessor_entry=s3.identity,
        target_state=M2Position.S4_DISCOVERY_ACTIVE,
    )
    derived = M3PositionEntry(
        identity=M3PositionEntryId(envelope=envelope2.envelope.identity, discriminator=token()),
        state=M3Position.ENVELOPE_DERIVED,
        edge=M3Edge.C1,
        predecessor=ABSENT,
    )
    activation2 = activation1.model_copy(
        update={
            "identity": WorkerActivationId(value=token()),
            "envelope": envelope2.envelope.identity,
            "role": Role.DISCOVERY_REVIEWER,
            "input_package": package.package.identity,
        }
    )
    running = M3PositionEntry(
        identity=M3PositionEntryId(envelope=envelope2.envelope.identity, discriminator=token()),
        state=M3Position.ACTIVATION_RUNNING,
        edge=M3Edge.C2,
        predecessor=present(derived.identity),
    )
    effect = ActivationEffectRecord(
        identity=ActivationEffectId(
            parent_activation=activation2.identity, local_discriminator=token()
        ),
        observed_state=("A review-notes.md",),
        cycle_occurrence=ABSENT,
    )

    def determination(value: BaseModel) -> ConformanceDetermination:
        return ConformanceDetermination(
            identity=ConformanceDeterminationId(
                activation=activation2.identity, discriminator=token()
            ),
            determination=value,  # type: ignore[arg-type]
        )

    completed = M3PositionEntry(
        identity=M3PositionEntryId(envelope=envelope2.envelope.identity, discriminator=token()),
        state=M3Position.ACTIVATION_COMPLETED,
        edge=M3Edge.C4,
        predecessor=present(running.identity),
    )
    built.units.append((envelope2, derived))
    built.units.append((activation2, running, SessionRecord(activation=activation2.identity)))
    built.units.append((effect,))
    built.units.append(
        (
            determination(
                StructuralConformanceDetermination(result=StructuralConformanceResult.CONFORMANT)
            ),
            determination(
                EnvelopeConformanceDetermination(
                    effects=(
                        EffectEnvelopeConformance(effect=effect.identity, within_envelope=True),
                    ),
                    violations=ABSENT,
                )
            ),
            determination(ResidueDetermination(mutations=ABSENT)),
            determination(AdoptionDetermination()),
            completed,
        )
    )
    obligation = h["obligation"]
    assert isinstance(obligation, RemediationObligation)
    waiver = OwnerDecision(
        identity=OwnerDecisionId(value=f"waive-{tag or 'world'}"),
        stage=activation1.stage,
        act=ObligationExtinguishingDecision(
            kind=OwnerDecisionKind.WAIVER,
            obligation=obligation.identity,
            produced_authorization=ABSENT,
            corrects=ABSENT,
        ),
    )
    built.deferred_ingest[len(built.units)] = (waiver,)
    built.units.append(())
    resolution = h["resolution"]
    assert isinstance(resolution, RootResolutionRecord)
    subjects = Subjects(
        root=boundary.resolved_root.value,
        other_root=f"other-authorization{tag}",
        resolution=resolution.identity.value,
        first_activation=activation1.identity.value,
        second_activation=activation2.identity.value,
        envelope=envelope1.envelope.identity.value,
        obligation_set=obligation.identity.parent_frozen_set.value,
        obligation_finding=obligation.identity.member_finding.value,
    )
    return built, subjects


def populate_extended(store: CoordinationStore, built: World) -> None:
    """As `st03_world.populate`, tolerating the empty unit that carries only an ingest."""
    ingest(store.path, built.ingest)
    for index, unit in enumerate(built.units):
        ingest(store.path, built.deferred_ingest.get(index, ()))
        if unit:
            store.create_unit(unit)  # type: ignore[arg-type]


def derive_all(records: dv.AuthoritativeRecords, subjects: Subjects) -> dict[str, object]:
    """Every ST-04 derivation over the persisted world's subjects."""
    root = OwnerAuthorizationId(value=subjects.root)
    other = OwnerAuthorizationId(value=subjects.other_root)
    obligation = RemediationObligationId(
        parent_frozen_set=FrozenFindingSetId(value=subjects.obligation_set),
        member_finding=FindingId(value=subjects.obligation_finding),
    )
    first = WorkerActivationId(value=subjects.first_activation)
    second = WorkerActivationId(value=subjects.second_activation)
    resolution = RootResolutionId(value=subjects.resolution)
    return {
        "DV-1/first": dv.derive_prior_authorized_state(records, first),
        "DV-1/second": dv.derive_prior_authorized_state(records, second),
        "DV-2": dv.derive_closure_scope(records, first),
        "DV-3": dv.derive_cycle_bound(records, root),
        "DV-4/liveness/root": dv.derive_liveness(records, root),
        "DV-4/liveness/other": dv.derive_liveness(records, other),
        "DV-4/recorded-eligibility": dv.derive_recorded_eligibility(records, resolution),
        "DV-5": dv.derive_obligation_force(records, obligation),
        "DV-6/M1": dv.derive_m1_position(records, resolution),
        "DV-6/M2": dv.derive_m2_position(records, root),
        "DV-6/M3": dv.derive_m3_position(records, AuthorityEnvelopeId(value=subjects.envelope)),
        "DV-6/M4": dv.derive_m4_position(records, root),
        "DV-7": dv.derive_outstanding_halts(records),
        "DV-8": dv.derive_closure_scope_series(records, root),
    }


@contextmanager
def persisted_extended_world(
    directory: Path, tag: str = ""
) -> Iterator[tuple[CoordinationStore, World, Subjects]]:
    from gpauto.store import create_store

    store = create_store(directory / "coordination.sqlite")
    try:
        built, subjects = extended_world(tag)
        populate_extended(store, built)
        yield store, built, subjects
    finally:
        store.close()


# --- canonical rendering, independent of hash seed and read order ---------------------


def canonical(value: object) -> object:
    """A nested tuple of plain values: sets sorted, models and dataclasses by field."""
    if isinstance(value, BaseModel):
        return (
            type(value).__name__,
            tuple((name, canonical(getattr(value, name))) for name in type(value).model_fields),
        )
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__name__,
            tuple((f.name, canonical(getattr(value, f.name))) for f in dataclasses.fields(value)),
        )
    if isinstance(value, frozenset | set):
        return ("set", tuple(sorted((canonical(member) for member in value), key=repr)))
    if isinstance(value, tuple | list):
        return tuple(canonical(member) for member in value)
    if isinstance(value, dict):
        return tuple(sorted((str(k), canonical(v)) for k, v in value.items()))
    if isinstance(value, enum.Enum):
        return value.value
    assert value is None or isinstance(value, str | int | bool), type(value)
    return value


def rendered(value: object) -> str:
    return repr(canonical(value))


def main(argv: list[str]) -> int:
    """Open the store at `argv[0]` in this fresh process, derive, and print the rendering."""
    from gpauto.store import open_store

    store = open_store(Path(argv[0]))
    try:
        records = dv.read_authoritative_records(store)
        print(rendered(derive_all(records, Subjects(*argv[1:]))))
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
