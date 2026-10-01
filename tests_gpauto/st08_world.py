"""ST-08 Class A fixtures; other stages' records are explicitly fixture acts.

Design basis: ST-08 plan §12. Real ST-07 observation and ST-03 persistence are used.
M2/M3 entries, dispatch/ingestion, adoption, freeze and quiescence are fixtures of
ST-09/10/12/16, never implementations of those stages.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import st06_world as w
import st07_world as x
from gpauto import observation
from gpauto.absence import Carried, NotApplicable, Present
from gpauto.activation import EntryStateBoundaryReference, InputPackage
from gpauto.bounds import AuthorityBounds, WriteBoundary
from gpauto.coordination_identity import (
    ConformanceDeterminationId,
    CycleOccurrenceId,
    ExecutionObservationId,
)
from gpauto.coordination_records import (
    AdoptionDetermination,
    AuthorityEnvelopeRecord,
    ConformanceDetermination,
    ExecutionObservation,
    InputPackageRecord,
    M2PositionEntry,
    M3PositionEntry,
    QuiescenceObservation,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import M2Edge, M2Position, M3Edge, M3Position, Quiescence
from gpauto.envelope import AuthorityEnvelope
from gpauto.identity import (
    AuthorityEnvelopeId,
    FrozenFindingSetId,
    InputPackageId,
    WorkerActivationId,
)
from gpauto.minting import mint_value
from gpauto.store import CoordinationStore
from gpauto.vocabulary import Role
from st03_world import ABSENT, fresh_store, m3


@dataclass
class World:
    store: CoordinationStore
    repo: x.Repository
    epoch: x.Epoch
    boundary: observation.Fixed
    head: M2PositionEntry
    cycle: CycleOccurrenceId | None = None
    frozen: FrozenFindingSetId | None = None

    def envelope(
        self, role: Role = Role.IMPLEMENTER, scopes: tuple[str, ...] = ("src/",)
    ) -> AuthorityEnvelopeRecord:
        """Fixture of ST-06 derivation and ST-16 position entry; declared bounds only."""
        member = (
            w.writer(self.epoch.scope, role)
            if role in (Role.IMPLEMENTER, Role.REMEDIATOR)
            else w.reviewer(self.epoch.scope, role)
        )
        values = {
            name: getattr(member, name)
            for name in AuthorityBounds.model_fields
            if name != "frozen_set_reference"
        }
        values["frozen_set_reference"] = (
            Carried[FrozenFindingSetId](value=self.frozen)
            if self.frozen is not None and role in (Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER)
            else NotApplicable()
        )
        if role in (Role.IMPLEMENTER, Role.REMEDIATOR):
            values["write_boundary"] = Carried[WriteBoundary](value=WriteBoundary(scopes=scopes))
        step = {
            Role.IMPLEMENTER: (M2Position.S3_IMPLEMENTATION_ACTIVE, M2Edge.B3),
            Role.DISCOVERY_REVIEWER: (M2Position.S4_DISCOVERY_ACTIVE, M2Edge.B4),
            Role.REMEDIATOR: (M2Position.S6_REMEDIATION_ACTIVE, M2Edge.B6a),
            Role.BOUNDED_CLOSURE_VERIFIER: (M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7),
        }[role]
        record = AuthorityEnvelopeRecord(
            envelope=AuthorityEnvelope(
                identity=AuthorityEnvelopeId(value=mint_value()),
                resolved_root=self.epoch.root,
                stage=self.epoch.scope.stage,
                entry_boundary=self.boundary.boundary.boundary.identity,
                role=role,
                bounds=AuthorityBounds(**values),
                declared_closed=True,
            ),
            cycle_occurrence=Present[CycleOccurrenceId](value=self.cycle) if self.cycle else ABSENT,
            predecessor_entry=self.head.identity,
            target_state=step[0],
        )
        derived = m3(record.envelope.identity, M3Position.ENVELOPE_DERIVED, M3Edge.C1, None)
        reached = w.m2(self.epoch.root, step[0], step[1], self.head, self.cycle)
        self.store.create_unit((record, derived, reached))
        self.head = reached
        return record

    def dispatch(self, envelope: AuthorityEnvelopeRecord) -> WorkerActivationRecord:
        """Fixture of ST-10/16's dispatch and C2, with the real reference constraints."""
        package = InputPackageRecord(
            package=InputPackage(
                identity=InputPackageId(value=mint_value()),
                authoritative_inputs=(
                    EntryStateBoundaryReference(
                        entry_boundary=self.boundary.boundary.boundary.identity
                    ),
                ),
                non_basis_context=(),
            ),
            cycle_occurrence=envelope.cycle_occurrence,
        )
        activation = WorkerActivationRecord(
            identity=WorkerActivationId(value=mint_value()),
            envelope=envelope.envelope.identity,
            role=envelope.envelope.role,
            input_package=package.package.identity,
            provider=ABSENT,
            session=ABSENT,
            stage=self.epoch.scope.stage,
            branch="main",
            resolved_root=self.epoch.root,
            cycle_occurrence=envelope.cycle_occurrence,
        )
        entries = x.stored(self.store, M3PositionEntry)
        derived = next(e for e in entries if e.identity.envelope == activation.envelope)
        running = m3(activation.envelope, M3Position.ACTIVATION_RUNNING, M3Edge.C2, derived)
        self.store.create_unit((package, activation, running))
        return activation

    def quiesce(
        self, activation: WorkerActivationRecord, value: Quiescence = Quiescence.QUIESCENT
    ) -> None:
        """Fixture of ST-12's physical observation, independent of M3 closure."""
        self.store.create(
            ExecutionObservation(
                identity=ExecutionObservationId(
                    activation=activation.identity, discriminator=mint_value()
                ),
                observation=QuiescenceObservation(quiescence=value),
            )
        )

    def close(self, activation: WorkerActivationRecord, adopted: bool = False) -> None:
        """Fixture of ST-10/16 C4 or C5; used only where the scenario permits it."""
        running = next(
            e
            for e in x.stored(self.store, M3PositionEntry)
            if e.identity.envelope == activation.envelope and e.edge == M3Edge.C2
        )
        terminal = m3(
            activation.envelope,
            M3Position.ACTIVATION_COMPLETED if adopted else M3Position.ACTIVATION_CLOSED_UNADOPTED,
            M3Edge.C4 if adopted else M3Edge.C5,
            running,
        )
        if adopted:
            adoption = ConformanceDetermination(
                identity=ConformanceDeterminationId(
                    activation=activation.identity, discriminator=mint_value()
                ),
                determination=AdoptionDetermination(),
            )
            self.store.create_unit((adoption, terminal))
        else:
            self.store.create(terminal)


@contextmanager
def world(*, dirty: bool = False) -> Iterator[World]:
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        if dirty:
            repo.write(".coord/legacy", b"legacy unchanged\n")
            repo.write("a.txt", b"dirty entry\n")
            repo.git("add", "a.txt")
        epoch = x.epoch_at_s1(store, repo)
        fixed = observation.fix_entry_boundary(store, epoch.root)
        assert isinstance(fixed, observation.Fixed), fixed
        yield World(store, repo, epoch, fixed, fixed.entry)


def main(argv: list[str]) -> int:
    """Fresh-process replay probe; in-process brackets are deliberately lost."""
    from gpauto import attribution as a
    from gpauto.store import open_store

    store = open_store(Path(argv[0]))
    try:
        subject = WorkerActivationId(value=argv[1])
        result = a.assess_activation(store, subject, None, None)
        print(type(result).__name__)
        print(a.completion_facts(a.read_records(store), subject))
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))


def begin(s: World, role: Role = Role.IMPLEMENTER) -> tuple[WorkerActivationRecord, object]:
    from gpauto import attribution as a

    envelope = s.envelope(role)
    opening = a.take_opening_bracket(s.store, envelope.envelope.identity)
    assert isinstance(opening, a.Bracket), opening
    subject = s.dispatch(envelope)
    return subject, opening


def finish(s: World, subject: WorkerActivationRecord, opening: object) -> object:
    from gpauto import attribution as a

    assert isinstance(opening, a.Bracket)
    s.quiesce(subject)
    closing = a.take_closing_bracket(s.store, subject.identity)
    assert isinstance(closing, a.Bracket), closing
    return a.assess_activation(s.store, subject.identity, opening, closing)


def remediation(s: World) -> tuple[WorkerActivationRecord, object, object]:
    """Fixture ST-09 freeze and first cycle; preceding assessments use ST-08 itself."""
    from gpauto import attribution as a
    from gpauto.activation import ObjectiveProductionReference
    from gpauto.content_identity import identify_artifact_content
    from gpauto.coordination_records import ArtifactProductionRecord, CycleOccurrence, FindingRecord
    from gpauto.evidence import (
        ActivationAttribution,
        ArtifactProduction,
        ObjectiveArtifactProduction,
    )
    from gpauto.identity import ArtifactProductionId, FindingId, RemediationObligationId
    from gpauto.review import Finding, FrozenFindingSet, RemediationObligation
    from gpauto.vocabulary import Provenance

    for role in (Role.IMPLEMENTER, Role.DISCOVERY_REVIEWER):
        previous, opening = begin(s, role)
        assert isinstance(finish(s, previous, opening), a.Assessed)
        s.close(previous, adopted=True)
    identified = identify_artifact_content(b"finding evidence")
    production = ObjectiveArtifactProduction(
        identity=ArtifactProductionId(value=mint_value()),
        content=identified.identity,
        provenance=Provenance.OBJECTIVE,
        attributed_to=ActivationAttribution(activation=previous.identity),
    )
    recorded = ArtifactProductionRecord(
        production=ArtifactProduction[Provenance](
            **{name: getattr(production, name) for name in type(production).model_fields}
        ),
        cycle_occurrence=ABSENT,
    )
    finding = FindingRecord(
        finding=Finding(
            identity=FindingId(value=mint_value()),
            stage=s.epoch.scope.stage,
            originating_authorization=s.epoch.root,
            originating_activation=previous.identity,
        ),
        content_binding=ObjectiveProductionReference(production=production),
    )
    frozen = FrozenFindingSet(
        identity=FrozenFindingSetId(value=mint_value()),
        stage=s.epoch.scope.stage,
        resolved_root=s.epoch.root,
        originating_activation=previous.identity,
        members=(finding.finding.identity,),
    )
    obligation = RemediationObligation(
        identity=RemediationObligationId(
            parent_frozen_set=frozen.identity, member_finding=finding.finding.identity
        )
    )
    s5 = w.m2(s.epoch.root, M2Position.S5_FINDING_SET_FROZEN, M2Edge.B5, s.head)
    s.store.create_unit((identified, recorded, finding, frozen, obligation, s5))
    cycle = CycleOccurrence(
        identity=CycleOccurrenceId(value=mint_value()),
        establishing_edge=M2Edge.B6a,
        predecessor_entry=s5.identity,
        target_state=M2Position.S6_REMEDIATION_ACTIVE,
        predecessor_closure_activation=ABSENT,
        envelope=ABSENT,
        activation=ABSENT,
    )
    s.store.create(cycle)
    s.head, s.cycle, s.frozen = s5, cycle.identity, frozen.identity
    subject, opening = begin(s, Role.REMEDIATOR)
    return subject, opening, obligation.identity


def ingest_change(
    s: World,
    subject: WorkerActivationRecord,
    obligation: object,
    content: bytes,
    *,
    addressed: bool = True,
    objective_channel: bool = True,
) -> None:
    """Fixture of ST-10 objective lifecycle capture and ingestion, per 04-A."""
    from gpauto.activation import ObjectiveProductionReference
    from gpauto.content_identity import identify_artifact_content
    from gpauto.coordination_identity import OutcomeIngestionRecordId
    from gpauto.coordination_records import (
        ArtifactProductionRecord,
        CorrelationSet,
        ObligationDispositionItem,
        OutcomeIngestionRecord,
    )
    from gpauto.coordination_vocabulary import ObligationDisposition
    from gpauto.evidence import (
        ActivationAttribution,
        ArtifactProduction,
        ObjectiveArtifactProduction,
    )
    from gpauto.identity import ArtifactProductionId, RemediationObligationId
    from gpauto.repository import ClassificationContext
    from gpauto.vocabulary import Provenance

    assert isinstance(obligation, RemediationObligationId)
    identified = identify_artifact_content(content)
    production = ObjectiveArtifactProduction(
        identity=ArtifactProductionId(value=mint_value()),
        content=identified.identity,
        provenance=Provenance.OBJECTIVE,
        attributed_to=ActivationAttribution(activation=subject.identity),
    )
    recorded = ArtifactProductionRecord(
        production=ArtifactProduction[Provenance](
            **{name: getattr(production, name) for name in type(production).model_fields}
        ),
        cycle_occurrence=subject.cycle_occurrence,
    )
    ingestion = OutcomeIngestionRecord(
        identity=OutcomeIngestionRecordId(value=mint_value()),
        correlation=CorrelationSet(
            root=s.epoch.root,
            stage=s.epoch.scope.stage,
            context=ClassificationContext(
                authorization=s.epoch.root, entry_boundary=s.boundary.boundary.boundary.identity
            ),
            step_state=s.head.state,
            cycle_occurrence=subject.cycle_occurrence,
            envelope=subject.envelope,
            activation=Present[WorkerActivationId](value=subject.identity),
        ),
        activation=subject.identity,
        objective_channel=(production,) if objective_channel else (),
        worker_authored_channel=(),
        items=(
            ObligationDispositionItem(
                obligation=obligation,
                disposition=ObligationDisposition.ADDRESSED
                if addressed
                else ObligationDisposition.NOT_ADDRESSED,
                change_evidence=ObjectiveProductionReference(production=production),
            ),
        ),
    )
    s.store.create_unit((identified, recorded, ingestion))


def forbidden_mutant_violation(store: CoordinationStore, activation: WorkerActivationId) -> object:
    """Only CD-6a/CD-8/CD-9 call this deliberately unlawful mutation payload.

    It names the actual assessment subject so referential integrity cannot kill the
    mutant instead of its dedicated negative assertion. This is never evidence of
    a lawful ST-08-produced violation, and never runs on the production/control path.
    """
    from gpauto.coordination_records import EnvelopeViolationRecord
    from gpauto.governance import EnvelopeViolation
    from gpauto.identity import EnvelopeViolationId
    from st03_world import world as prior_world

    subject = next(r for r in x.stored(store, WorkerActivationRecord) if r.identity == activation)
    prototype = next(r for r in prior_world().records() if isinstance(r, EnvelopeViolationRecord))
    return EnvelopeViolationRecord(
        violation=EnvelopeViolation(
            **{
                **prototype.violation.__dict__,
                "identity": EnvelopeViolationId(value=mint_value()),
                "violating_activation": subject.identity,
                "envelope": subject.envelope,
                "resolved_root": subject.resolved_root,
                "stage": subject.stage,
                "role": subject.role,
            }
        ),
        cycle_occurrence=subject.cycle_occurrence,
    )
