"""Class A lifecycle worlds; dispatch, capture and adoption are ST-10/ST-12 fixtures.

Design basis: ST-09 accepted plan §6, §8, §11; AP-07 WP-17 and CO-1.
No worker or session runs. Upstream maps represent caller-supplied facts only.
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import BaseModel

from gpauto import derivations as dv
from gpauto.absence import Carried, Present
from gpauto.activation import (
    InputPackage,
    ObjectiveProductionReference,
    RemediationObligationReference,
)
from gpauto.coordination_identity import ConformanceDeterminationId, OutcomeIngestionRecordId
from gpauto.coordination_records import (
    AdoptionDetermination,
    ArtifactProductionRecord,
    AuthorityEnvelopeRecord,
    ConformanceDetermination,
    CorrelationSet,
    CycleOccurrence,
    DeclaredItem,
    DiscoveryVerdictItem,
    EntryStateBoundaryRecord,
    FindingItem,
    InputPackageRecord,
    M2PositionEntry,
    ObligationDispositionItem,
    OutcomeIngestionRecord,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import (
    DiscoveryVerdict,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
    ObligationDisposition,
)
from gpauto.evidence import ActivationAttribution, ArtifactProduction, ObjectiveArtifactProduction
from gpauto.identity import (
    ArtifactProductionId,
    AuthorityEnvelopeId,
    InputPackageId,
    OwnerAuthorizationId,
    RemediationObligationId,
    WorkerActivationId,
)
from gpauto.repository import ClassificationContext
from gpauto.review import FrozenFindingSet
from gpauto.store import CoordinationStore, create_store
from gpauto.vocabulary import Provenance, Role
from st03_ingest import ingest
from st03_world import ABSENT as ABSENT
from st03_world import World, m2, m3, minted
from st03_world import world as original_world
from st04_world import token

B5 = dict.fromkeys(
    (
        "BOUNDARY_FIXED",
        "ROLE_AUTHORIZED",
        "ENVELOPE_VALID",
        "BOUNDS_WITHIN_CEILING",
        "DERIVATION_TOTAL",
        "BINDINGS_MATCH",
    ),
    "TRUE",
) | {"UNACCOUNTED_MUTATION": "FALSE"}
B6A = dict.fromkeys(
    ("E14_REFERENCES_FROZEN_SET", "REMEDIATOR_BOUNDS", "BOUNDARY_FIXED", "BINDINGS_MATCH"),
    "TRUE",
) | {"UNACCOUNTED_MUTATION": "FALSE"}
CYCLE = {"BOUNDARY_FIXED": "TRUE", "BINDINGS_MATCH": "TRUE", "UNACCOUNTED_MUTATION": "FALSE"}


@dataclass
class LifecycleWorld:
    store: CoordinationStore
    built: World
    head: M2PositionEntry

    @property
    def root(self) -> OwnerAuthorizationId:
        return self.head.identity.epoch_root

    def snapshot(self) -> dv.AuthoritativeRecords:
        from gpauto.finding_lifecycle import read_lifecycle_records

        return read_lifecycle_records(self.store)

    def advance(
        self, state: M2Position, edge: M2Edge, cycle: CycleOccurrence | None = None
    ) -> M2PositionEntry:
        self.head = m2(self.root, state, edge, self.head, cycle.identity if cycle else None)
        self.store.create(self.head)
        return self.head

    def refresh(self) -> M2PositionEntry:
        reached = dv.derive_m2_position(self.snapshot(), self.root)
        assert isinstance(reached, dv.Occupancy)
        self.head = reached.reached
        return self.head

    def activation(
        self,
        role: Role,
        items: tuple[DeclaredItem, ...] = (),
        *,
        cycle: CycleOccurrence | None = None,
        outcome: str = "completed",
        adopted: bool = True,
        objectives: int = 1,
        obligations: tuple[RemediationObligationId, ...] = (),
        dispositions: tuple[RemediationObligationId, ...] | None = None,
    ) -> WorkerActivationRecord:
        """ST-10/ST-12 record fixtures; no claim about those stages' implementations."""
        base = cast(WorkerActivationRecord, self.built.handles["activation"])
        template = cast(AuthorityEnvelopeRecord, self.built.handles["envelope"])
        boundary = cast(EntryStateBoundaryRecord, self.built.handles["boundary"])
        occurrence = Present(value=cycle.identity) if cycle else ABSENT
        envelope = template.model_copy(
            update={
                "envelope": template.envelope.model_copy(
                    update={"identity": minted(AuthorityEnvelopeId), "role": role}
                ),
                "predecessor_entry": self.head.identity,
                "target_state": self.head.state,
                "cycle_occurrence": occurrence,
            }
        )
        sets = rows(self.store, FrozenFindingSet)
        if sets and role in {Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER}:
            envelope = envelope.model_copy(
                update={
                    "envelope": envelope.envelope.model_copy(
                        update={
                            "bounds": envelope.envelope.bounds.model_copy(
                                update={"frozen_set_reference": Carried(value=sets[0].identity)}
                            )
                        }
                    )
                }
            )
        package = InputPackageRecord(
            package=InputPackage(
                identity=minted(InputPackageId),
                authoritative_inputs=tuple(
                    RemediationObligationReference(obligation=o) for o in obligations
                ),
                non_basis_context=(),
            ),
            cycle_occurrence=occurrence,
        )
        run = base.model_copy(
            update={
                "identity": minted(WorkerActivationId),
                "envelope": envelope.envelope.identity,
                "role": role,
                "input_package": package.package.identity,
                "cycle_occurrence": occurrence,
                "provider": ABSENT,
                "session": ABSENT,
            }
        )
        derived = m3(run.envelope, M3Position.ENVELOPE_DERIVED, M3Edge.C1, None)
        running = m3(run.envelope, M3Position.ACTIVATION_RUNNING, M3Edge.C2, derived)
        self.store.create_unit((envelope, derived, package, run, running))
        objective = cast(ArtifactProductionRecord, self.built.handles["objective"])
        productions = tuple(
            ObjectiveArtifactProduction(
                identity=minted(ArtifactProductionId),
                content=objective.production.content,
                provenance=Provenance.OBJECTIVE,
                attributed_to=ActivationAttribution(activation=run.identity),
            )
            for _ in range(objectives)
        )
        self.store.create_unit(
            tuple(
                ArtifactProductionRecord(
                    production=ArtifactProduction[Provenance](
                        identity=p.identity,
                        content=p.content,
                        provenance=p.provenance,
                        attributed_to=p.attributed_to,
                    ),
                    cycle_occurrence=occurrence,
                )
                for p in productions
            )
        )
        if dispositions is not None:
            items = items + tuple(
                ObligationDispositionItem(
                    obligation=o,
                    disposition=ObligationDisposition.ADDRESSED,
                    change_evidence=ObjectiveProductionReference(production=productions[0]),
                )
                for o in dispositions
            )
        self.store.create(
            OutcomeIngestionRecord(
                identity=minted(OutcomeIngestionRecordId),
                activation=run.identity,
                correlation=CorrelationSet(
                    root=self.root,
                    stage=run.stage,
                    context=ClassificationContext(
                        authorization=self.root, entry_boundary=boundary.boundary.identity
                    ),
                    step_state=self.head.state,
                    cycle_occurrence=occurrence,
                    envelope=run.envelope,
                    activation=Present(value=run.identity),
                ),
                objective_channel=productions,
                worker_authored_channel=(),
                items=items,
            )
        )
        if outcome != "running":
            state, edge = (
                (M3Position.ACTIVATION_COMPLETED, M3Edge.C4)
                if outcome == "completed"
                else (M3Position.ACTIVATION_CLOSED_UNADOPTED, M3Edge.C5)
            )
            self.store.create(m3(run.envelope, state, edge, running))
        if adopted:
            self.store.create(
                ConformanceDetermination(
                    identity=ConformanceDeterminationId(
                        activation=run.identity, discriminator=token()
                    ),
                    determination=AdoptionDetermination(),
                )
            )
        return run

    def discovery(self, count: int = 2, **kwargs: object) -> WorkerActivationRecord:
        items = (
            DiscoveryVerdictItem(
                verdict=DiscoveryVerdict.FINDINGS_REPORTED
                if count
                else DiscoveryVerdict.NO_FINDINGS
            ),
            *(FindingItem() for _ in range(count)),
        )
        return self.activation(Role.DISCOVERY_REVIEWER, items, **kwargs)  # type: ignore[arg-type]


@contextmanager
def world(tag: str = "") -> Iterator[LifecycleWorld]:
    with tempfile.TemporaryDirectory(prefix="st09-") as directory:
        with create_store(Path(directory) / "coordination.sqlite") as store:
            built = original_world(tag)
            ingest(store.path, built.ingest)
            for unit in built.units:
                store.create_unit(unit)  # type: ignore[arg-type]
                entries = [
                    r
                    for r in unit
                    if isinstance(r, M2PositionEntry) and r.state == M2Position.S4_DISCOVERY_ACTIVE
                ]
                if entries:
                    yield LifecycleWorld(store, built, entries[0])
                    return
            raise AssertionError("ST-03 fixture has no S4 prefix")


def rows[R: BaseModel](store: CoordinationStore, kind: type[R]) -> tuple[R, ...]:
    found = store.enumerate(kind)
    assert all(isinstance(r, kind) for r in found)
    return cast(tuple[R, ...], found)


def freeze_enter(x: LifecycleWorld, members: int = 2) -> tuple[FrozenFindingSet, CycleOccurrence]:
    from gpauto import finding_lifecycle as f

    frozen = f.freeze(x.store, x.discovery(members).identity, B5)
    assert isinstance(frozen, f.Frozen), frozen
    entered = f.enter_first_occurrence(x.store, x.root, frozen.entry.identity, B6A)
    assert isinstance(entered, f.OccurrenceEstablished), entered
    x.refresh()
    return frozen.frozen_set, entered.occurrence


def close_cycle(
    x: LifecycleWorld,
    frozen: FrozenFindingSet,
    occurrence: CycleOccurrence,
    verdicts: tuple[bool | None, ...] = (True, False),
    *,
    persist: bool = True,
    outcome: str = "completed",
    adopted: bool = True,
) -> WorkerActivationRecord:
    from gpauto import finding_lifecycle as f
    from gpauto.coordination_records import MemberClosureResultItem
    from gpauto.coordination_vocabulary import ClosedVerdict, NotClosedVerdict

    x.activation(Role.REMEDIATOR, cycle=occurrence)
    x.advance(M2Position.S7_CLOSURE_ACTIVE, M2Edge.B7, occurrence)
    closer = x.activation(
        Role.BOUNDED_CLOSURE_VERIFIER,
        tuple(
            MemberClosureResultItem(
                member=member,
                verdict=ClosedVerdict()
                if verdict
                else NotClosedVerdict(indeterminacy_reason=ABSENT),
            )
            for member, verdict in zip(frozen.members, verdicts, strict=True)
            if verdict is not None
        ),
        cycle=occurrence,
        outcome=outcome,
        adopted=adopted,
    )
    if persist:
        assert isinstance(
            f.record_closure_assessments(x.store, closer.identity),
            f.AssessmentsRecorded | f.NothingToRecord,
        )
    return closer


def replay_state(store: CoordinationStore, root: OwnerAuthorizationId) -> str:
    """Canonical cross-process value, never a persisted derived field."""
    from gpauto import finding_lifecycle as f
    from st04_world import rendered

    records = f.read_lifecycle_records(store)
    occurrences = rows(store, CycleOccurrence)
    return rendered(
        (
            frozenset(records.records),
            f.membership_facts(records, root),
            f.b15_budget(records, root),
            f.post_freeze_candidates(records, root),
            frozenset((c.identity, f.admitted_set(records, c.identity)) for c in occurrences),
            tuple(
                sorted(
                    (
                        c.identity.value,
                        tuple(sorted(f.cycle_facts(records, c.identity, CYCLE).items())),
                    )
                    for c in occurrences
                )
            ),
        )
    )


def act(store: CoordinationStore, kind: str, root: OwnerAuthorizationId, subject: str) -> object:
    from gpauto import finding_lifecycle as f
    from gpauto.coordination_identity import M2PositionEntryId

    if kind == "freeze":
        return f.freeze(store, WorkerActivationId(value=subject), B5)
    if kind == "assessments":
        return f.record_closure_assessments(store, WorkerActivationId(value=subject))
    if kind == "candidates":
        return f.record_post_freeze_candidates(store, WorkerActivationId(value=subject))
    predecessor = M2PositionEntryId(epoch_root=root, discriminator=subject)
    if kind == "b6a":
        return f.enter_first_occurrence(store, root, predecessor, B6A)
    assert kind == "b15"
    return f.route_after_closure(store, root, predecessor, CYCLE)


def _main() -> None:
    import os
    import sys

    from gpauto import finding_lifecycle as f
    from gpauto.store import open_store
    from gpauto.store_schema import Layout
    from st04_world import rendered

    path, kind, root_value, subject, window = sys.argv[1:]
    root = OwnerAuthorizationId(value=root_value)
    if window == "before":
        os._exit(91)
    original = CoordinationStore._insert
    if window == "inside":

        def crash(self: CoordinationStore, layout: Layout, record: BaseModel) -> None:
            original(self, layout, record)
            os._exit(92)

        CoordinationStore._insert = crash  # type: ignore[method-assign]
    with open_store(Path(path)) as store:
        if window == "replay":

            def forbidden(*args: object) -> None:
                raise AssertionError("restart replay minted or wrote")

            f.mint_value = forbidden  # type: ignore[assignment, attr-defined]
            store.create_unit = forbidden  # type: ignore[assignment, method-assign]
        result = act(store, kind, root, subject)
        if window == "after":
            os._exit(93)
        print(rendered(result))
        print(replay_state(store, root))


if __name__ == "__main__":
    _main()
