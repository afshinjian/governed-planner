"""Finding lifecycle acts and record-derived cycle facts.

Design basis: AP-11 §16 GP-AUTO-ST-09; AP-05 §3–§12, §22; AP-04 amendment
§3 (B15, CE-*, CYCLE_BOUND, OP-*, BC-*), §3.5.6, §3.5.12; AP-08 §6.1,
§9 (CW-15, CW-16), §12.3; AP-07 WP-17…WP-19, FP-1…FP-17, MC-16, MC-19,
CO-1…CO-18. DG11-7 limits imports to ST-01…ST-05. Upstream facts are caller
inputs. Results are determinations, never stored records or halt acts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

from pydantic import BaseModel

from gpauto import derivations as dv
from gpauto import state_machine as sm
from gpauto import state_machine_model as model
from gpauto.absence import Carried, KnownAbsent, Present
from gpauto.activation import ObjectiveProductionReference, RemediationObligationReference
from gpauto.coordination_identity import CycleOccurrenceId, M2PositionEntryId
from gpauto.coordination_records import (
    AdoptionDetermination,
    AuthorityEnvelopeRecord,
    ClosureAssessmentRecord,
    ConformanceDetermination,
    CycleOccurrence,
    DiscoveryVerdictItem,
    DisputeItem,
    FindingItem,
    FindingRecord,
    InputPackageRecord,
    M2PositionEntry,
    M3PositionEntry,
    MemberClosureResultItem,
    ObligationDispositionItem,
    OutcomeIngestionRecord,
    PostFreezeCandidateItem,
    PostFreezeCandidateRecord,
    WorkerActivationRecord,
    WorkerRefusalOrExpansionItem,
)
from gpauto.coordination_vocabulary import (
    ClosedVerdict,
    DiscoveryVerdict,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
    NotClosedVerdict,
)
from gpauto.identity import (
    AuthorityEnvelopeId,
    ClosureAssessmentId,
    FindingId,
    FrozenFindingSetId,
    InputPackageId,
    OwnerAuthorizationId,
    PostFreezeCandidateId,
    RemediationObligationId,
    WorkerActivationId,
)
from gpauto.minting import mint_value
from gpauto.review import (
    ClosureAssessment,
    Finding,
    FrozenFindingSet,
    PostFreezeCandidate,
    RemediationObligation,
)
from gpauto.store import CoordinationStore, UnreadableRecord, WriteRefused
from gpauto.vocabulary import AuthorizationDisposition, Role

FAILURE_POLICY_IDENTITY: Final = "gp-auto.failure-policy/1"
B15_OPERATIONAL_BUDGET: Final = 1


@dataclass(frozen=True)
class FailurePolicy:
    identity: Literal["gp-auto.failure-policy/1"] = FAILURE_POLICY_IDENTITY
    b15_budget: Literal[1] = B15_OPERATIONAL_BUDGET


FAILURE_POLICY: Final = FailurePolicy()
ABSENT: Final = KnownAbsent(basis="ST-09 establishment has no such subject")
LIFECYCLE_INPUTS: Final[tuple[type[BaseModel], ...]] = tuple(
    dict.fromkeys(
        (
            *dv.DERIVATION_INPUTS,
            FindingRecord,
            PostFreezeCandidateRecord,
            OutcomeIngestionRecord,
            InputPackageRecord,
        )
    )
)
UPSTREAM_B5: Final = frozenset(
    {
        "BOUNDARY_FIXED",
        "ROLE_AUTHORIZED",
        "ENVELOPE_VALID",
        "BOUNDS_WITHIN_CEILING",
        "DERIVATION_TOTAL",
        "BINDINGS_MATCH",
        "UNACCOUNTED_MUTATION",
    }
)
UPSTREAM_B6A: Final = frozenset(
    {
        "E14_REFERENCES_FROZEN_SET",
        "REMEDIATOR_BOUNDS",
        "BOUNDARY_FIXED",
        "BINDINGS_MATCH",
        "UNACCOUNTED_MUTATION",
    }
)
UPSTREAM_CYCLE: Final = frozenset({"BOUNDARY_FIXED", "BINDINGS_MATCH", "UNACCOUNTED_MUTATION"})


class LifecycleCause(StrEnum):
    UNREADABLE_RECORDS = "UNREADABLE_RECORDS"
    INCONSISTENT_RECORDS = "INCONSISTENT_RECORDS"
    SUBJECT_NOT_FOUND = "SUBJECT_NOT_FOUND"
    WRONG_ROLE = "WRONG_ROLE"
    NOT_COMPLETED_ADOPTED = "NOT_COMPLETED_ADOPTED"
    INGESTION_MISSING = "INGESTION_MISSING"
    INGESTION_INCONSISTENT = "INGESTION_INCONSISTENT"
    OUTCOME_NONCONFORMANT = "OUTCOME_NONCONFORMANT"
    CONTENT_BINDING_INDETERMINATE = "CONTENT_BINDING_INDETERMINATE"
    EPOCH_NOT_AT_POSITION = "EPOCH_NOT_AT_POSITION"
    UPSTREAM_FACTS_INVALID = "UPSTREAM_FACTS_INVALID"
    GUARD_REFUSED = "GUARD_REFUSED"
    CONFLICT = "CONFLICT"
    WRITE_REFUSED = "WRITE_REFUSED"
    ASSESSMENTS_NOT_RECORDED = "ASSESSMENTS_NOT_RECORDED"
    EXPANSION_X08 = "EXPANSION_X08"
    NON_MEMBER_ASSESSED = "NON_MEMBER_ASSESSED"
    OUTSIDE_CLOSURE_BOUND = "OUTSIDE_CLOSURE_BOUND"
    NO_FROZEN_SET = "NO_FROZEN_SET"
    BUDGET_INDETERMINATE = "BUDGET_INDETERMINATE"


@dataclass(frozen=True)
class LifecycleIndeterminate:
    cause: LifecycleCause


@dataclass(frozen=True)
class Nonconformant:
    causes: tuple[LifecycleCause, ...]


@dataclass(frozen=True)
class DiscoveryOutcome:
    verdict: DiscoveryVerdict
    items: tuple[FindingItem, ...]
    binding_source: ObjectiveProductionReference


@dataclass(frozen=True)
class Frozen:
    frozen_set: FrozenFindingSet
    entry: M2PositionEntry


@dataclass(frozen=True)
class FreezeReplayed:
    frozen_set: FrozenFindingSet
    entry: M2PositionEntry


@dataclass(frozen=True)
class NotFrozen:
    cause: LifecycleCause
    refused: sm.Refused | None = None


def _rows[R: BaseModel](records: dv.AuthoritativeRecords, kind: type[R]) -> tuple[R, ...]:
    return tuple(r for r in records.records if isinstance(r, kind))


def _unreadable(records: dv.AuthoritativeRecords, *kinds: type[BaseModel]) -> bool:
    return bool((records.unreadable | records.unstable).intersection(kinds))


def _read_pass(store: CoordinationStore) -> dv.AuthoritativeRecords:
    found: list[BaseModel] = []
    unreadable: set[type[BaseModel]] = set()
    for kind in LIFECYCLE_INPUTS:
        for record in store.enumerate(kind):
            if isinstance(record, UnreadableRecord):
                unreadable.add(kind)
            else:
                found.append(record)
    return dv.AuthoritativeRecords(tuple(found), frozenset(unreadable))


def read_lifecycle_records(store: CoordinationStore) -> dv.AuthoritativeRecords:
    first, second = _read_pass(store), _read_pass(store)
    if (
        frozenset(first.records) != frozenset(second.records)
        or first.unreadable != second.unreadable
    ):
        return dv.AuthoritativeRecords((), unstable=frozenset(LIFECYCLE_INPUTS))
    return first


def _activation(
    records: dv.AuthoritativeRecords, identity: WorkerActivationId
) -> WorkerActivationRecord | LifecycleCause:
    if _unreadable(records, WorkerActivationRecord, AuthorityEnvelopeRecord):
        return LifecycleCause.UNREADABLE_RECORDS
    runs = [r for r in _rows(records, WorkerActivationRecord) if r.identity == identity]
    if not runs:
        return LifecycleCause.SUBJECT_NOT_FOUND
    if len(runs) != 1:
        return LifecycleCause.INCONSISTENT_RECORDS
    run = runs[0]
    envelopes = [
        e for e in _rows(records, AuthorityEnvelopeRecord) if e.envelope.identity == run.envelope
    ]
    if len(envelopes) != 1:
        return LifecycleCause.INCONSISTENT_RECORDS
    envelope = envelopes[0]
    if (
        envelope.envelope.resolved_root != run.resolved_root
        or envelope.envelope.stage != run.stage
        or envelope.envelope.role != run.role
        or envelope.cycle_occurrence != run.cycle_occurrence
    ):
        return LifecycleCause.INCONSISTENT_RECORDS
    if len([a for a in _rows(records, WorkerActivationRecord) if a.envelope == run.envelope]) != 1:
        return LifecycleCause.INCONSISTENT_RECORDS
    return run


def _completed(
    records: dv.AuthoritativeRecords, run: WorkerActivationRecord, *, adoption: bool = True
) -> bool | LifecycleCause:
    if _unreadable(records, M3PositionEntry, ConformanceDetermination):
        return LifecycleCause.UNREADABLE_RECORDS
    position = dv.derive_m3_position(records, run.envelope)
    if isinstance(position, dv.Indeterminate):
        return LifecycleCause.INCONSISTENT_RECORDS
    completed = (
        isinstance(position, dv.Occupancy)
        and position.reached.state == M3Position.ACTIVATION_COMPLETED
        and position.reached.edge == M3Edge.C4
    )
    adopted = any(
        r.identity.activation == run.identity and isinstance(r.determination, AdoptionDetermination)
        for r in _rows(records, ConformanceDetermination)
    )
    return completed and (adopted or not adoption)


def _discovery_bound(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> frozenset[WorkerActivationId] | LifecycleCause:
    if _unreadable(
        records,
        WorkerActivationRecord,
        AuthorityEnvelopeRecord,
        M3PositionEntry,
        ConformanceDetermination,
    ):
        return LifecycleCause.UNREADABLE_RECORDS
    completed: set[WorkerActivationId] = set()
    for run in _rows(records, WorkerActivationRecord):
        if run.resolved_root != root or run.role != Role.DISCOVERY_REVIEWER:
            continue
        checked = _activation(records, run.identity)
        if isinstance(checked, LifecycleCause):
            return checked
        envelopes = [
            e
            for e in _rows(records, AuthorityEnvelopeRecord)
            if e.envelope.identity == run.envelope
        ]
        if envelopes[0].target_state != M2Position.S4_DISCOVERY_ACTIVE:
            return LifecycleCause.INCONSISTENT_RECORDS
        state = _completed(records, run, adoption=False)
        if isinstance(state, LifecycleCause):
            return state
        if state:
            completed.add(run.identity)
    if len(completed) > 1:  # guard:ga_freeze_act
        return LifecycleCause.INCONSISTENT_RECORDS
    return frozenset(completed)


def _ingestion(
    records: dv.AuthoritativeRecords, run: WorkerActivationRecord
) -> OutcomeIngestionRecord | LifecycleCause:
    if _unreadable(records, OutcomeIngestionRecord):
        return LifecycleCause.UNREADABLE_RECORDS
    items = [r for r in _rows(records, OutcomeIngestionRecord) if r.activation == run.identity]
    if not items:
        return LifecycleCause.INGESTION_MISSING
    if len(items) != 1:
        return LifecycleCause.INGESTION_INCONSISTENT
    ingestion = items[0]
    c = ingestion.correlation
    if (
        c.root != run.resolved_root
        or c.stage != run.stage
        or c.envelope != run.envelope
        or c.activation != Present[WorkerActivationId](value=run.identity)
        or c.cycle_occurrence != run.cycle_occurrence
    ):
        return LifecycleCause.INGESTION_INCONSISTENT
    return ingestion


def discovery_determination(
    records: dv.AuthoritativeRecords, activation: WorkerActivationId
) -> DiscoveryOutcome | Nonconformant | LifecycleIndeterminate:
    run = _activation(records, activation)
    if isinstance(run, LifecycleCause):
        return LifecycleIndeterminate(run)
    if run.role != Role.DISCOVERY_REVIEWER:
        return Nonconformant((LifecycleCause.WRONG_ROLE,))
    bound = _discovery_bound(records, run.resolved_root)
    if isinstance(bound, LifecycleCause):
        return LifecycleIndeterminate(bound)
    ingestion = _ingestion(records, run)
    if isinstance(ingestion, LifecycleCause):
        return LifecycleIndeterminate(ingestion)
    discovery_classes = not any(
        not isinstance(i, DiscoveryVerdictItem | FindingItem | WorkerRefusalOrExpansionItem)
        for i in ingestion.items
    )
    if not discovery_classes:  # guard:ga_outcome_conformance
        return Nonconformant((LifecycleCause.OUTCOME_NONCONFORMANT,))
    verdicts = [i.verdict for i in ingestion.items if isinstance(i, DiscoveryVerdictItem)]
    findings = tuple(i for i in ingestion.items if isinstance(i, FindingItem))
    if len(verdicts) != 1:
        return Nonconformant((LifecycleCause.OUTCOME_NONCONFORMANT,))
    consistent = (verdicts[0] == DiscoveryVerdict.NO_FINDINGS) == (not findings)
    if not consistent:  # guard:ga_outcome_conformance
        return Nonconformant((LifecycleCause.OUTCOME_NONCONFORMANT,))
    if len(ingestion.objective_channel) != 1:  # guard:ga_freeze_act
        return LifecycleIndeterminate(LifecycleCause.CONTENT_BINDING_INDETERMINATE)
    return DiscoveryOutcome(
        verdicts[0],
        findings,
        ObjectiveProductionReference(production=ingestion.objective_channel[0]),
    )


def _truth(value: bool) -> str:
    return "TRUE" if value else "FALSE"


def _live_facts(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> sm.Facts:
    facts: sm.Facts = {}
    live = dv.derive_liveness(records, root)
    position = dv.derive_m4_position(records, root)
    if isinstance(live, dv.Liveness):
        facts["UNRESOLVED_EVENT"] = _truth(bool(live.suspended_by))
        if not isinstance(position, dv.Indeterminate):
            state = (
                AuthorizationDisposition.LIVE
                if isinstance(position, dv.Unoccupied)
                else position.reached.state
            )
            if live.live == (state == AuthorizationDisposition.LIVE):
                facts["M4_LIVE"] = _truth(live.live)
    return facts


def freeze_facts(records: dv.AuthoritativeRecords, activation: WorkerActivationId) -> sm.Facts:
    facts: sm.Facts = {"TRIGGER": "COORDINATOR"}
    run = _activation(records, activation)
    if isinstance(run, LifecycleCause):
        return facts
    facts.update(_live_facts(records, run.resolved_root))
    bound = _discovery_bound(records, run.resolved_root)
    completed = _completed(records, run)
    if not isinstance(bound, LifecycleCause) and isinstance(completed, bool):
        facts["STEP_ACTIVATION_COMPLETED"] = _truth(completed)
    outcome = discovery_determination(records, activation)
    if isinstance(outcome, DiscoveryOutcome):
        facts["VERDICT_SET_CONSISTENT"] = "TRUE"
    elif isinstance(outcome, Nonconformant):
        facts["VERDICT_SET_CONSISTENT"] = "FALSE"
    if not _unreadable(records, AuthorityEnvelopeRecord, M3PositionEntry):
        implementers = [
            e
            for e in _rows(records, AuthorityEnvelopeRecord)
            if e.envelope.resolved_root == run.resolved_root and e.envelope.role == Role.IMPLEMENTER
        ]
        terminal = [dv.derive_m3_position(records, e.envelope.identity) for e in implementers]
        if terminal and all(isinstance(p, dv.Occupancy) for p in terminal):
            facts["STEP_ENVELOPE_TERMINAL"] = _truth(
                all(
                    isinstance(p, dv.Occupancy)
                    and p.reached.state
                    in {
                        M3Position.ACTIVATION_COMPLETED,
                        M3Position.ACTIVATION_CLOSED_UNADOPTED,
                        M3Position.ENVELOPE_VOIDED,
                    }
                    for p in terminal
                )
            )
    return facts


def membership_facts(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> sm.Facts:
    if _unreadable(records, FrozenFindingSet):
        return {}
    sets = [s for s in _rows(records, FrozenFindingSet) if s.resolved_root == root]
    if not sets:
        return {}
    if len(sets) != 1:
        return {"FROZEN_SET_UNCHANGED": "FALSE"}
    frozen = sets[0]
    facts = {"MEMBERSHIP_EMPTY": _truth(not frozen.members)}
    if _unreadable(records, FindingRecord, RemediationObligation):
        return facts
    completed = _discovery_bound(records, root)
    if completed == LifecycleCause.UNREADABLE_RECORDS:
        return facts
    run = _activation(records, frozen.originating_activation)
    findings = [
        r.finding
        for r in _rows(records, FindingRecord)
        if r.finding.originating_authorization == root
    ]
    obligations = [
        o.identity
        for o in _rows(records, RemediationObligation)
        if o.identity.parent_frozen_set == frozen.identity
    ]
    unchanged = (
        completed == frozenset({frozen.originating_activation})
        and isinstance(run, WorkerActivationRecord)
        and _completed(records, run) is True
        and run.stage == frozen.stage
    )
    membership_agrees = len(findings) == len(frozen.members) and {
        r.identity for r in findings
    } == set(frozen.members)
    unchanged = unchanged and membership_agrees  # guard:ga_membership_immutability
    origins_agree = all(
        r.stage == frozen.stage and r.originating_activation == frozen.originating_activation
        for r in findings
    )
    unchanged = unchanged and origins_agree  # guard:ga_membership_immutability
    unchanged = (
        unchanged
        and len(frozen.members) == len(set(frozen.members))
        and len(obligations) == len(frozen.members)
        and {o.member_finding for o in obligations} == set(frozen.members)
    )
    facts["FROZEN_SET_UNCHANGED"] = _truth(unchanged)
    return facts


def _freeze_effect(
    records: dv.AuthoritativeRecords, run: WorkerActivationRecord
) -> FreezeReplayed | LifecycleCause | None:
    if _unreadable(
        records,
        FrozenFindingSet,
        FindingRecord,
        RemediationObligation,
        M2PositionEntry,
        WorkerActivationRecord,
        AuthorityEnvelopeRecord,
        M3PositionEntry,
        ConformanceDetermination,
        OutcomeIngestionRecord,
    ):
        return LifecycleCause.UNREADABLE_RECORDS
    sets = [s for s in _rows(records, FrozenFindingSet) if s.resolved_root == run.resolved_root]
    entries = [
        e
        for e in _rows(records, M2PositionEntry)
        if e.identity.epoch_root == run.resolved_root and e.edge == M2Edge.B5
    ]
    findings = [
        f
        for f in _rows(records, FindingRecord)
        if f.finding.originating_authorization == run.resolved_root
    ]
    set_ids = {s.identity for s in _rows(records, FrozenFindingSet)}
    orphan_obligation = any(
        o.identity.parent_frozen_set not in set_ids for o in _rows(records, RemediationObligation)
    )
    if not sets:
        return (
            LifecycleCause.INCONSISTENT_RECORDS
            if entries or findings or orphan_obligation
            else None
        )
    if len(sets) != 1:
        return LifecycleCause.CONFLICT
    frozen = sets[0]
    outcome = discovery_determination(records, run.identity)
    if (
        isinstance(outcome, LifecycleIndeterminate)
        and outcome.cause == LifecycleCause.UNREADABLE_RECORDS
    ):
        return outcome.cause
    if not isinstance(outcome, DiscoveryOutcome) or _completed(records, run) is not True:
        return LifecycleCause.CONFLICT
    if frozen.originating_activation != run.identity or frozen.stage != run.stage:
        return LifecycleCause.CONFLICT
    members_match = (
        len(frozen.members) == len(outcome.items)
        and membership_facts(records, run.resolved_root).get("FROZEN_SET_UNCHANGED") == "TRUE"
    )
    if not members_match:  # guard:ga_membership_immutability
        return LifecycleCause.CONFLICT
    if any(f.content_binding != outcome.binding_source for f in findings):
        return LifecycleCause.CONFLICT
    if len(entries) != 1:
        return LifecycleCause.CONFLICT
    entry = entries[0]
    predecessors = [
        e
        for e in _rows(records, M2PositionEntry)
        if isinstance(entry.predecessor, Present) and e.identity == entry.predecessor.value
    ]
    if (
        len(predecessors) != 1
        or predecessors[0].state != M2Position.S4_DISCOVERY_ACTIVE
        or predecessors[0].identity.epoch_root != run.resolved_root
        or entry.state != M2Position.S5_FINDING_SET_FROZEN
        or entry.cycle_occurrence != ABSENT
    ):
        return LifecycleCause.CONFLICT
    return FreezeReplayed(frozen, entry)


def freeze(
    store: CoordinationStore, activation: WorkerActivationId, upstream: Mapping[str, str]
) -> Frozen | FreezeReplayed | NotFrozen:
    records = read_lifecycle_records(store)
    run = _activation(records, activation)
    if isinstance(run, LifecycleCause):
        return NotFrozen(run)
    if run.role != Role.DISCOVERY_REVIEWER:
        return NotFrozen(LifecycleCause.WRONG_ROLE)
    bound = _discovery_bound(records, run.resolved_root)
    if isinstance(bound, LifecycleCause):
        return NotFrozen(bound)
    previous = _freeze_effect(records, run)  # guard:ga_lifecycle_once
    if previous is not None:
        return previous if isinstance(previous, FreezeReplayed) else NotFrozen(previous)
    completed = _completed(records, run)
    if completed is not True:  # guard:ga_freeze_act
        return NotFrozen(
            completed
            if isinstance(completed, LifecycleCause)
            else LifecycleCause.NOT_COMPLETED_ADOPTED
        )
    outcome = discovery_determination(records, activation)
    if isinstance(outcome, Nonconformant):
        return NotFrozen(outcome.causes[0])
    if isinstance(outcome, LifecycleIndeterminate):
        return NotFrozen(outcome.cause)
    position = dv.derive_m2_position(records, run.resolved_root)
    if (
        not isinstance(position, dv.Occupancy)
        or position.reached.state != M2Position.S4_DISCOVERY_ACTIVE
    ):
        return NotFrozen(LifecycleCause.EPOCH_NOT_AT_POSITION)
    if not set(upstream) <= UPSTREAM_B5:  # guard:ga_freeze_act
        return NotFrozen(LifecycleCause.UPSTREAM_FACTS_INVALID)
    evaluated = sm.evaluate(
        M2Edge.B5, position.reached.state, freeze_facts(records, activation) | dict(upstream)
    )
    if isinstance(evaluated, sm.Refused):  # guard:ga_freeze_act
        return NotFrozen(LifecycleCause.GUARD_REFUSED, evaluated)
    members = tuple(FindingId(value=mint_value()) for _ in outcome.items)  # guard:ga_freeze_act
    frozen = FrozenFindingSet(
        identity=FrozenFindingSetId(value=mint_value()),
        stage=run.stage,
        resolved_root=run.resolved_root,
        originating_activation=activation,
        members=members,
    )
    findings = tuple(
        FindingRecord(
            finding=Finding(
                identity=member,
                stage=run.stage,
                originating_authorization=run.resolved_root,
                originating_activation=activation,
            ),
            content_binding=outcome.binding_source,
        )
        for member in members
    )
    obligations = tuple(
        RemediationObligation(
            identity=RemediationObligationId(
                parent_frozen_set=frozen.identity, member_finding=member
            )
        )
        for member in members
    )  # guard:ga_freeze_act
    entry = M2PositionEntry(
        identity=M2PositionEntryId(epoch_root=run.resolved_root, discriminator=mint_value()),
        state=M2Position.S5_FINDING_SET_FROZEN,
        edge=M2Edge.B5,
        predecessor=Present[M2PositionEntryId](value=position.reached.identity),
        cycle_occurrence=ABSENT,
    )
    try:
        store.create_unit((frozen, *findings, *obligations, entry))  # guard:ga_freeze_act
    except WriteRefused:
        previous = _freeze_effect(read_lifecycle_records(store), run)  # guard:ga_freeze_act
        if isinstance(previous, FreezeReplayed):
            return previous
        return NotFrozen(previous or LifecycleCause.WRITE_REFUSED)
    return Frozen(frozen, entry)


@dataclass(frozen=True)
class Admissible:
    disputes: tuple[DisputeItem, ...] = ()
    worker_requests: tuple[WorkerRefusalOrExpansionItem, ...] = ()


@dataclass(frozen=True)
class Expansion:
    items: tuple[ObligationDispositionItem, ...]
    cause: LifecycleCause = LifecycleCause.EXPANSION_X08


@dataclass(frozen=True)
class OutsideClosureBound:
    members: frozenset[FindingId]
    cause: LifecycleCause = LifecycleCause.OUTSIDE_CLOSURE_BOUND


@dataclass(frozen=True)
class AdmittedSet:
    occurrence: CycleOccurrenceId
    obligations: frozenset[RemediationObligationId]


@dataclass(frozen=True)
class BudgetAvailable:
    used: int


@dataclass(frozen=True)
class BudgetExhausted:
    used: int


@dataclass(frozen=True)
class BudgetIndeterminate:
    cause: LifecycleCause


@dataclass(frozen=True)
class OccurrenceEstablished:
    occurrence: CycleOccurrence
    entry: M2PositionEntry


@dataclass(frozen=True)
class OccurrenceReplayed:
    occurrence: CycleOccurrence
    entry: M2PositionEntry


@dataclass(frozen=True)
class NotEntered:
    cause: LifecycleCause
    refused: sm.Refused | None = None


@dataclass(frozen=True)
class NotRouted:
    cause: LifecycleCause
    b15: sm.Refused | None = None
    b8: sm.Refused | None = None


@dataclass(frozen=True)
class GateDue:
    admitted: sm.Admitted


@dataclass(frozen=True)
class AssessmentsRecorded:
    assessments: tuple[ClosureAssessmentRecord, ...]


@dataclass(frozen=True)
class AssessmentsReplayed:
    assessments: frozenset[ClosureAssessmentRecord]


@dataclass(frozen=True)
class CandidatesRecorded:
    candidates: tuple[PostFreezeCandidateRecord, ...]


@dataclass(frozen=True)
class CandidatesReplayed:
    candidates: frozenset[PostFreezeCandidateRecord]


@dataclass(frozen=True)
class NothingToRecord:
    pass


@dataclass(frozen=True)
class NotRecorded:
    cause: LifecycleCause


def _frozen(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> FrozenFindingSet | LifecycleCause:
    if _unreadable(records, FrozenFindingSet):
        return LifecycleCause.UNREADABLE_RECORDS
    sets = [s for s in _rows(records, FrozenFindingSet) if s.resolved_root == root]
    if not sets:
        return LifecycleCause.NO_FROZEN_SET
    if len(sets) != 1:
        return LifecycleCause.INCONSISTENT_RECORDS
    return sets[0]


def _occurrence(
    records: dv.AuthoritativeRecords, identity: CycleOccurrenceId
) -> CycleOccurrence | LifecycleCause:
    if _unreadable(records, CycleOccurrence):
        return LifecycleCause.UNREADABLE_RECORDS
    found = [c for c in _rows(records, CycleOccurrence) if c.identity == identity]
    if len(found) != 1:
        return LifecycleCause.INCONSISTENT_RECORDS
    return found[0]


def _closer(
    records: dv.AuthoritativeRecords, occurrence: CycleOccurrence
) -> WorkerActivationRecord | LifecycleCause | None:
    if _unreadable(
        records,
        WorkerActivationRecord,
        AuthorityEnvelopeRecord,
        M3PositionEntry,
        ConformanceDetermination,
    ):
        return LifecycleCause.UNREADABLE_RECORDS
    completed: list[WorkerActivationRecord] = []
    for role in (Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER):
        runs: list[WorkerActivationRecord] = []
        for run in _rows(records, WorkerActivationRecord):
            if (
                run.cycle_occurrence != Present[CycleOccurrenceId](value=occurrence.identity)
                or run.role != role
            ):
                continue
            checked = _activation(records, run.identity)
            if isinstance(checked, LifecycleCause):
                return checked
            if run.resolved_root != occurrence.predecessor_entry.epoch_root:
                return LifecycleCause.INCONSISTENT_RECORDS
            state = _completed(records, run, adoption=False)
            if isinstance(state, LifecycleCause):
                return state
            if state:
                runs.append(run)
        if len(runs) > 1:
            return LifecycleCause.INCONSISTENT_RECORDS
        if role == Role.BOUNDED_CLOSURE_VERIFIER:
            completed = runs
    if completed and _completed(records, completed[0]) is True:
        return completed[0]
    return None


def _closure_items(
    records: dv.AuthoritativeRecords, run: WorkerActivationRecord
) -> tuple[MemberClosureResultItem, ...] | LifecycleCause:
    ingestion = _ingestion(records, run)
    if isinstance(ingestion, LifecycleCause):
        return ingestion
    closure_classes = not any(
        not isinstance(
            i,
            MemberClosureResultItem
            | DisputeItem
            | PostFreezeCandidateItem
            | WorkerRefusalOrExpansionItem,
        )
        for i in ingestion.items
    )
    if not closure_classes:  # guard:ga_outcome_conformance
        return LifecycleCause.OUTCOME_NONCONFORMANT
    items = tuple(i for i in ingestion.items if isinstance(i, MemberClosureResultItem))
    frozen = _frozen(records, run.resolved_root)
    if isinstance(frozen, LifecycleCause):
        return frozen
    foreign_member = any(i.member not in frozen.members for i in items)
    if foreign_member:  # guard:ga_closure_scope_within_membership
        return LifecycleCause.NON_MEMBER_ASSESSED
    if len(items) != len({i.member for i in items}):
        return LifecycleCause.OUTCOME_NONCONFORMANT
    return items


def _assessment_effect(
    records: dv.AuthoritativeRecords, run: WorkerActivationRecord, occurrence: CycleOccurrence
) -> LifecycleCause | None:
    """Structural ingestion/effect check, independent of force and cycle derivations."""
    if _unreadable(records, ClosureAssessmentRecord, OutcomeIngestionRecord, FrozenFindingSet):
        return LifecycleCause.UNREADABLE_RECORDS
    items = _closure_items(records, run)
    if isinstance(items, LifecycleCause):
        return items
    bound = Present[CycleOccurrenceId](value=occurrence.identity)
    assessments = [
        r
        for r in _rows(records, ClosureAssessmentRecord)
        if r.assessment.identity.closure_activation == run.identity
    ]
    if any(
        r.cycle_occurrence == bound and r.assessment.identity.closure_activation != run.identity
        for r in _rows(records, ClosureAssessmentRecord)
    ):
        return LifecycleCause.INCONSISTENT_RECORDS
    if not assessments and items:
        return LifecycleCause.ASSESSMENTS_NOT_RECORDED
    expected = frozenset((i.member, i.verdict) for i in items)
    actual = frozenset((r.assessment.identity.assessed_finding, r.verdict) for r in assessments)
    effect_equal = (
        len(assessments) == len(items)
        and actual == expected
        and all(r.cycle_occurrence == bound for r in assessments)
    )
    if not effect_equal:  # guard:ga_outcome_conformance
        return LifecycleCause.INCONSISTENT_RECORDS
    return None


def _predecessor(
    records: dv.AuthoritativeRecords,
    root: OwnerAuthorizationId,
    predecessor: M2PositionEntryId,
    edge: M2Edge,
) -> M2PositionEntry | LifecycleCause:
    if _unreadable(records, M2PositionEntry):
        return LifecycleCause.UNREADABLE_RECORDS
    found = [e for e in _rows(records, M2PositionEntry) if e.identity == predecessor]
    expected = (
        M2Position.S5_FINDING_SET_FROZEN if edge == M2Edge.B6a else M2Position.S7_CLOSURE_ACTIVE
    )
    if len(found) != 1 or predecessor.epoch_root != root or found[0].state != expected:
        return LifecycleCause.EPOCH_NOT_AT_POSITION
    return found[0]


def _occurrence_effect(
    records: dv.AuthoritativeRecords, predecessor: M2PositionEntry, edge: M2Edge
) -> OccurrenceReplayed | LifecycleCause | None:
    if _unreadable(records, CycleOccurrence, M2PositionEntry):
        return LifecycleCause.UNREADABLE_RECORDS
    occurrences = [
        c
        for c in _rows(records, CycleOccurrence)
        if c.predecessor_entry == predecessor.identity
        and c.target_state == M2Position.S6_REMEDIATION_ACTIVE
    ]
    entries = [
        e
        for e in _rows(records, M2PositionEntry)
        if e.predecessor == Present[M2PositionEntryId](value=predecessor.identity)
        and e.edge in {M2Edge.B6a, M2Edge.B15}
    ]
    if not occurrences:
        return LifecycleCause.INCONSISTENT_RECORDS if entries else None
    if len(occurrences) != 1 or len(entries) != 1:
        return LifecycleCause.CONFLICT
    occurrence, entry = occurrences[0], entries[0]
    closure: KnownAbsent | Present[WorkerActivationId] = ABSENT
    if edge == M2Edge.B15:
        if not isinstance(predecessor.cycle_occurrence, Present):
            return LifecycleCause.CONFLICT
        prior = _occurrence(records, predecessor.cycle_occurrence.value)
        if isinstance(prior, LifecycleCause):
            return prior
        closer = _closer(records, prior)
        if closer == LifecycleCause.UNREADABLE_RECORDS:
            return closer
        if not isinstance(closer, WorkerActivationRecord):
            return LifecycleCause.CONFLICT
        effect = _assessment_effect(records, closer, prior)
        if effect:
            return (
                effect if effect == LifecycleCause.UNREADABLE_RECORDS else LifecycleCause.CONFLICT
            )
        closure = Present[WorkerActivationId](value=closer.identity)
    valid = (
        occurrence.establishing_edge == edge
        and occurrence.predecessor_closure_activation == closure
        and occurrence.envelope == ABSENT
        and occurrence.activation == ABSENT
        and entry.identity.epoch_root == predecessor.identity.epoch_root
        and entry.edge == edge
        and entry.state == M2Position.S6_REMEDIATION_ACTIVE
        and entry.cycle_occurrence == Present[CycleOccurrenceId](value=occurrence.identity)
        and [
            e
            for e in _rows(records, M2PositionEntry)
            if e.predecessor == entry.predecessor  # guard:ga_lifecycle_once
        ]
        == [entry]
        and [
            e
            for e in _rows(records, M2PositionEntry)
            if e.edge in {M2Edge.B6a, M2Edge.B15}  # guard:ga_lifecycle_once
            and e.cycle_occurrence == Present[CycleOccurrenceId](value=occurrence.identity)
        ]
        == [entry]
    )
    if not valid:  # guard:ga_lifecycle_once
        return LifecycleCause.CONFLICT
    return OccurrenceReplayed(occurrence, entry)


def _occurrence_chain(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> tuple[CycleOccurrence, ...] | LifecycleCause:
    if _unreadable(records, CycleOccurrence, M2PositionEntry):
        return LifecycleCause.UNREADABLE_RECORDS
    occurrences = [
        c for c in _rows(records, CycleOccurrence) if c.predecessor_entry.epoch_root == root
    ]
    entries = [
        e
        for e in _rows(records, M2PositionEntry)
        if e.identity.epoch_root == root and e.edge in {M2Edge.B6a, M2Edge.B15}
    ]
    if len(entries) != len(occurrences):  # guard:ga_cycle_budget
        return LifecycleCause.INCONSISTENT_RECORDS
    if not occurrences:
        return ()
    firsts = [c for c in occurrences if c.establishing_edge == M2Edge.B6a]
    if len(firsts) != 1:
        return LifecycleCause.INCONSISTENT_RECORDS
    walked: list[CycleOccurrence] = []
    current = firsts[0]
    while current not in walked:
        predecessor = _predecessor(
            records, root, current.predecessor_entry, current.establishing_edge
        )
        if isinstance(predecessor, LifecycleCause):
            return predecessor
        effect = _occurrence_effect(records, predecessor, current.establishing_edge)
        if not isinstance(effect, OccurrenceReplayed):
            return effect or LifecycleCause.INCONSISTENT_RECORDS
        walked.append(current)
        following = [
            c
            for c in occurrences
            if c.establishing_edge == M2Edge.B15
            and any(
                e.identity == c.predecessor_entry
                and e.cycle_occurrence == Present[CycleOccurrenceId](value=current.identity)
                for e in _rows(records, M2PositionEntry)
            )
        ]
        if not following:
            break
        if len(following) != 1:
            return LifecycleCause.INCONSISTENT_RECORDS
        current = following[0]
    if len(walked) != len(occurrences):
        return LifecycleCause.INCONSISTENT_RECORDS
    return tuple(walked)


def admitted_set(
    records: dv.AuthoritativeRecords, occurrence: CycleOccurrenceId
) -> AdmittedSet | LifecycleIndeterminate:
    current = _occurrence(records, occurrence)
    if isinstance(current, LifecycleCause):
        return LifecycleIndeterminate(current)
    root = current.predecessor_entry.epoch_root
    frozen = _frozen(records, root)
    if isinstance(frozen, LifecycleCause):
        return LifecycleIndeterminate(frozen)
    chain = _occurrence_chain(records, root)
    if isinstance(chain, LifecycleCause):
        return LifecycleIndeterminate(chain)
    if _unreadable(records, RemediationObligation):
        return LifecycleIndeterminate(LifecycleCause.UNREADABLE_RECORDS)
    applicable: set[RemediationObligationId] = set()
    for member in frozen.members:
        obligation = RemediationObligationId(
            parent_frozen_set=frozen.identity, member_finding=member
        )
        force = dv.derive_obligation_force(records, obligation)
        if isinstance(force, dv.Indeterminate):
            return LifecycleIndeterminate(
                LifecycleCause.UNREADABLE_RECORDS
                if force.cause
                in {dv.IndeterminacyCause.UNREADABLE_INPUT, dv.IndeterminacyCause.UNSTABLE_READ}
                else LifecycleCause.INCONSISTENT_RECORDS
            )
        if not isinstance(force, dv.ObligationForce):
            return LifecycleIndeterminate(LifecycleCause.INCONSISTENT_RECORDS)
        if force.in_force:  # guard:ga_strict_shrink
            applicable.add(obligation)
    closed: set[FindingId] = set()
    for prior in chain:
        if prior.identity == occurrence:  # guard:ga_strict_shrink
            break
        closer = _closer(records, prior)
        if not isinstance(closer, WorkerActivationRecord):
            return LifecycleIndeterminate(closer or LifecycleCause.INCONSISTENT_RECORDS)
        effect = _assessment_effect(records, closer, prior)
        if effect:
            return LifecycleIndeterminate(effect)
        closed.update(
            r.assessment.identity.assessed_finding
            for r in _rows(records, ClosureAssessmentRecord)
            if r.assessment.identity.closure_activation == closer.identity
            and isinstance(r.verdict, ClosedVerdict)
        )
    return AdmittedSet(
        occurrence, frozenset(o for o in applicable if o.member_finding not in closed)
    )


def b15_budget(
    records: dv.AuthoritativeRecords,
    root: OwnerAuthorizationId,
    policy: FailurePolicy | None = FAILURE_POLICY,
) -> BudgetAvailable | BudgetExhausted | BudgetIndeterminate:
    if policy is None:  # guard:ga_cycle_budget
        return BudgetIndeterminate(LifecycleCause.BUDGET_INDETERMINATE)  # guard:ga_cycle_budget
    chain = _occurrence_chain(records, root)  # guard:ga_cycle_budget
    if isinstance(chain, LifecycleCause):  # guard:ga_cycle_budget
        return BudgetIndeterminate(chain)  # guard:ga_cycle_budget
    used = sum(c.establishing_edge == M2Edge.B15 for c in chain)  # guard:ga_cycle_budget
    return BudgetAvailable(used) if used < policy.b15_budget else BudgetExhausted(used)


def remediation_admissibility(
    records: dv.AuthoritativeRecords, activation: WorkerActivationId
) -> Admissible | Expansion | Nonconformant | LifecycleIndeterminate:
    run = _activation(records, activation)
    if isinstance(run, LifecycleCause):
        return LifecycleIndeterminate(run)
    if run.role != Role.REMEDIATOR:
        return Nonconformant((LifecycleCause.WRONG_ROLE,))
    if not isinstance(run.cycle_occurrence, Present):
        return LifecycleIndeterminate(LifecycleCause.INCONSISTENT_RECORDS)
    admitted = admitted_set(records, run.cycle_occurrence.value)
    if isinstance(admitted, LifecycleIndeterminate):
        return admitted
    ingestion = _ingestion(records, run)
    if isinstance(ingestion, LifecycleCause):
        return LifecycleIndeterminate(ingestion)
    remediation_classes = not any(
        not isinstance(
            i,
            ObligationDispositionItem
            | DisputeItem
            | PostFreezeCandidateItem
            | WorkerRefusalOrExpansionItem,
        )
        for i in ingestion.items
    )
    if not remediation_classes:  # guard:ga_outcome_conformance
        return Nonconformant((LifecycleCause.OUTCOME_NONCONFORMANT,))
    items = tuple(i for i in ingestion.items if isinstance(i, ObligationDispositionItem))
    outside = tuple(i for i in items if i.obligation not in admitted.obligations)
    if outside:  # guard:ga_obligation_admissibility OA-1
        return Expansion(outside)
    dispositions_complete = (
        len(items) == len(admitted.obligations)
        and {i.obligation for i in items} == admitted.obligations
    )
    if not dispositions_complete:  # guard:ga_outcome_conformance
        return Nonconformant((LifecycleCause.OUTCOME_NONCONFORMANT,))
    if any(i.change_evidence.production not in ingestion.objective_channel for i in items):
        return Nonconformant((LifecycleCause.OUTCOME_NONCONFORMANT,))
    return Admissible(
        tuple(i for i in ingestion.items if isinstance(i, DisputeItem)),
        tuple(i for i in ingestion.items if isinstance(i, WorkerRefusalOrExpansionItem)),
    )


def closure_admissibility(
    records: dv.AuthoritativeRecords, activation: WorkerActivationId
) -> Admissible | OutsideClosureBound | Nonconformant | LifecycleIndeterminate:
    run = _activation(records, activation)
    if isinstance(run, LifecycleCause):
        return LifecycleIndeterminate(run)
    if run.role != Role.BOUNDED_CLOSURE_VERIFIER:
        return Nonconformant((LifecycleCause.WRONG_ROLE,))
    if not isinstance(run.cycle_occurrence, Present):
        return LifecycleIndeterminate(LifecycleCause.INCONSISTENT_RECORDS)
    items = _closure_items(records, run)
    if items == LifecycleCause.UNREADABLE_RECORDS:  # guard:ga_outcome_conformance
        return LifecycleIndeterminate(items)
    if isinstance(items, LifecycleCause):
        return Nonconformant((items,))
    bound = admitted_set(records, run.cycle_occurrence.value)
    if isinstance(bound, LifecycleIndeterminate):
        return bound
    outside = frozenset(i.member for i in items) - {o.member_finding for o in bound.obligations}
    if outside:  # guard:ga_obligation_admissibility OA-3
        return OutsideClosureBound(outside)
    ingestion = _ingestion(records, run)
    if isinstance(ingestion, LifecycleCause):
        return LifecycleIndeterminate(ingestion)
    return Admissible(
        tuple(i for i in ingestion.items if isinstance(i, DisputeItem)),
        tuple(i for i in ingestion.items if isinstance(i, WorkerRefusalOrExpansionItem)),
    )


def admitted_obligations_fact(
    records: dv.AuthoritativeRecords, envelope: AuthorityEnvelopeId, package: InputPackageId
) -> sm.Facts:
    if _unreadable(records, AuthorityEnvelopeRecord, InputPackageRecord):
        return {}
    envelopes = [
        e for e in _rows(records, AuthorityEnvelopeRecord) if e.envelope.identity == envelope
    ]
    packages = [p for p in _rows(records, InputPackageRecord) if p.package.identity == package]
    if len(envelopes) != 1:
        return {}
    e = envelopes[0]
    reference = e.envelope.bounds.frozen_set_reference
    if not isinstance(reference, Carried):
        return {"ADMITTED_OBLIGATIONS_AGREE": "NOT_APPLICABLE"}
    if len(packages) != 1 or not isinstance(e.cycle_occurrence, Present):
        return {}
    bound = admitted_set(records, e.cycle_occurrence.value)
    frozen = _frozen(records, e.envelope.resolved_root)
    if (
        isinstance(bound, LifecycleIndeterminate)
        or isinstance(frozen, LifecycleCause)
        or reference.value != frozen.identity
    ):
        return {}
    p = packages[0]
    obligations = tuple(
        r.obligation
        for r in p.package.authoritative_inputs
        if isinstance(r, RemediationObligationReference)
    )
    agrees = (
        p.cycle_occurrence == e.cycle_occurrence
        and len(obligations) == len(set(obligations))
        and frozenset(obligations) == bound.obligations
    )
    agreement = "EQUAL" if agrees else "UNEQUAL"  # guard:ga_obligation_admissibility
    return {"ADMITTED_OBLIGATIONS_AGREE": agreement}


def closure_scope_facts(
    records: dv.AuthoritativeRecords, occurrence: CycleOccurrenceId
) -> sm.Facts:
    current = _occurrence(records, occurrence)
    if isinstance(current, LifecycleCause):
        return {}
    frozen = _frozen(records, current.predecessor_entry.epoch_root)
    if isinstance(frozen, LifecycleCause):
        return {}
    closer = _closer(records, current)
    if isinstance(closer, LifecycleCause):
        return {}
    if closer is None:
        bound = admitted_set(records, occurrence)
        if isinstance(bound, LifecycleIndeterminate):
            return {}
        members = frozenset(o.member_finding for o in bound.obligations)
    else:
        scope = dv.derive_closure_scope(records, closer.identity)
        if isinstance(scope, dv.Indeterminate):
            return {}
        members = scope.members
    within = _truth(members <= set(frozen.members))  # guard:ga_closure_scope_within_membership
    return {"CLOSURE_SCOPE_WITHIN_MEMBERSHIP": within}


def _conjunction(*components: str | None) -> str | None:
    if "FALSE" in components:
        return "FALSE"
    if all(c == "TRUE" for c in components):
        return "TRUE"
    return None


def _closure_history_integrity(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> LifecycleCause | None:
    """Reconcile every completed adopted closure that root-scoped DV-3 can consult."""
    chain = _occurrence_chain(records, root)
    if isinstance(chain, LifecycleCause):
        return chain
    for run in _rows(records, WorkerActivationRecord):
        if run.resolved_root != root or run.role != Role.BOUNDED_CLOSURE_VERIFIER:
            continue
        state = _completed(records, run)
        if isinstance(state, LifecycleCause):
            return state
        if not state:
            continue
        if not isinstance(run.cycle_occurrence, Present):
            return LifecycleCause.INCONSISTENT_RECORDS
        occurrence = _occurrence(records, run.cycle_occurrence.value)
        if isinstance(occurrence, LifecycleCause):
            return occurrence
        if occurrence not in chain or _closer(records, occurrence) != run:
            return LifecycleCause.INCONSISTENT_RECORDS
        effect = _assessment_effect(records, run, occurrence)
        if effect:
            return effect
    return None


def cycle_facts(
    records: dv.AuthoritativeRecords,
    occurrence: CycleOccurrenceId,
    upstream: Mapping[str, str],
    policy: FailurePolicy | None = FAILURE_POLICY,
) -> sm.Facts:
    facts: sm.Facts = {"TRIGGER": "COORDINATOR"}
    if not set(upstream) <= UPSTREAM_CYCLE:
        return facts
    current = _occurrence(records, occurrence)
    if isinstance(current, LifecycleCause):
        return facts
    root = current.predecessor_entry.epoch_root
    live = _live_facts(records, root)
    live_component = live.get("M4_LIVE")  # guard:ga_cycle_facts
    boundary_component = upstream.get("BOUNDARY_FIXED")  # guard:ga_cycle_facts
    bindings_component = upstream.get("BINDINGS_MATCH")  # guard:ga_cycle_facts
    ce0b = _conjunction(live_component, boundary_component, bindings_component)
    event = live.get("UNRESOLVED_EVENT")
    um = upstream.get("UNACCOUNTED_MUTATION")
    event_clear = {"FALSE": "TRUE", "TRUE": "FALSE"}.get(event or "")  # guard:ga_cycle_facts
    um_clear = {"FALSE": "TRUE", "TRUE": "FALSE"}.get(um or "")  # guard:ga_cycle_facts
    ce0c = _conjunction(event_clear, um_clear)  # guard:ga_cycle_facts
    if ce0b is not None:
        facts[model.CE_0B.name] = ce0b  # guard:ga_cycle_facts
    if ce0c is not None:
        facts[model.CE_0C.name] = ce0c  # guard:ga_cycle_facts
    unchanged = membership_facts(records, root).get("FROZEN_SET_UNCHANGED")
    if unchanged is not None:
        facts[model.CE_0D.name] = unchanged  # guard:ga_cycle_facts
    closer = _closer(records, current)
    if isinstance(closer, LifecycleCause):
        return facts
    facts[model.CE_0A.name] = _truth(closer is not None)  # guard:ga_cycle_facts
    budget = b15_budget(records, root, policy)
    if not isinstance(budget, BudgetIndeterminate):
        facts[model.CE_6.name] = _truth(isinstance(budget, BudgetAvailable))  # guard:ga_cycle_facts
    if closer is None:
        return facts
    if _assessment_effect(records, closer, current):
        return facts
    scope = dv.derive_closure_scope(records, closer.identity)
    frozen = _frozen(records, root)
    bound = admitted_set(records, occurrence)
    if (
        isinstance(scope, dv.Indeterminate)
        or isinstance(frozen, LifecycleCause)
        or isinstance(bound, LifecycleIndeterminate)
    ):
        return facts
    assessments = [
        r
        for r in _rows(records, ClosureAssessmentRecord)
        if r.assessment.identity.closure_activation == closer.identity
    ]
    facts.update(closure_scope_facts(records, occurrence))
    nonempty_scope = bool(scope.members) and scope.members <= set(frozen.members)
    facts[model.CE_1.name] = _truth(nonempty_scope)  # guard:ga_cycle_facts
    unattested = any(isinstance(r.verdict, NotClosedVerdict) for r in assessments)
    facts[model.CE_2.name] = _truth(unattested)  # guard:ga_cycle_facts
    attests = any(isinstance(r.verdict, ClosedVerdict) for r in assessments)
    facts[model.CE_3.name] = _truth(attests)  # guard:ga_strict_shrink
    applicable_members = {o.member_finding for o in bound.obligations}
    same_scope = scope.members == applicable_members  # guard:ga_strict_shrink
    facts[model.CE_4.name] = _truth(same_scope)  # guard:ga_cycle_facts
    if _closure_history_integrity(records, root):
        return facts
    next_bound = dv.derive_cycle_bound(records, root)
    if isinstance(next_bound, dv.CycleBound):
        facts[model.CE_5.name] = _truth(bool(next_bound.members))  # guard:ga_cycle_facts
    return facts


def _establish(
    store: CoordinationStore,
    predecessor: M2PositionEntry,
    edge: Literal[M2Edge.B6a, M2Edge.B15],
    closer: WorkerActivationId | None,
) -> OccurrenceEstablished | OccurrenceReplayed | LifecycleCause:
    occurrence = CycleOccurrence(
        identity=CycleOccurrenceId(value=mint_value()),
        establishing_edge=edge,
        predecessor_entry=predecessor.identity,
        target_state=M2Position.S6_REMEDIATION_ACTIVE,
        predecessor_closure_activation=Present[WorkerActivationId](value=closer)
        if closer
        else ABSENT,
        envelope=ABSENT,
        activation=ABSENT,
    )
    entry = M2PositionEntry(
        identity=M2PositionEntryId(
            epoch_root=predecessor.identity.epoch_root, discriminator=mint_value()
        ),
        state=M2Position.S6_REMEDIATION_ACTIVE,
        edge=edge,
        predecessor=Present[M2PositionEntryId](value=predecessor.identity),
        cycle_occurrence=Present[CycleOccurrenceId](value=occurrence.identity),
    )
    try:
        store.create_unit((occurrence, entry))
    except WriteRefused:
        fresh = read_lifecycle_records(store)
        named = _predecessor(fresh, predecessor.identity.epoch_root, predecessor.identity, edge)
        if named == LifecycleCause.UNREADABLE_RECORDS:
            return named
        if named != predecessor:
            return LifecycleCause.CONFLICT
        effect = _occurrence_effect(fresh, predecessor, edge)
        return effect or LifecycleCause.WRITE_REFUSED
    return OccurrenceEstablished(occurrence, entry)


def enter_first_occurrence(
    store: CoordinationStore,
    root: OwnerAuthorizationId,
    predecessor_entry: M2PositionEntryId,
    upstream: Mapping[str, str],
) -> OccurrenceEstablished | OccurrenceReplayed | NotEntered:
    records = read_lifecycle_records(store)
    predecessor = _predecessor(records, root, predecessor_entry, M2Edge.B6a)
    if isinstance(predecessor, LifecycleCause):
        return NotEntered(predecessor)
    previous = _occurrence_effect(records, predecessor, M2Edge.B6a)  # guard:ga_lifecycle_once
    if previous is not None:
        return previous if isinstance(previous, OccurrenceReplayed) else NotEntered(previous)
    position = dv.derive_m2_position(records, root)
    if not isinstance(position, dv.Occupancy) or position.reached != predecessor:
        return NotEntered(LifecycleCause.EPOCH_NOT_AT_POSITION)
    if not set(upstream) <= UPSTREAM_B6A:
        return NotEntered(LifecycleCause.UPSTREAM_FACTS_INVALID)
    facts = (
        {"TRIGGER": "COORDINATOR"}
        | _live_facts(records, root)
        | membership_facts(records, root)
        | dict(upstream)
    )
    evaluated = sm.evaluate(M2Edge.B6a, predecessor.state, facts)
    if isinstance(evaluated, sm.Refused):
        return NotEntered(LifecycleCause.GUARD_REFUSED, evaluated)
    result = _establish(store, predecessor, M2Edge.B6a, None)
    return NotEntered(result) if isinstance(result, LifecycleCause) else result


def route_after_closure(
    store: CoordinationStore,
    root: OwnerAuthorizationId,
    predecessor_entry: M2PositionEntryId,
    upstream: Mapping[str, str],
    policy: FailurePolicy | None = FAILURE_POLICY,
) -> OccurrenceEstablished | OccurrenceReplayed | GateDue | NotRouted:
    records = read_lifecycle_records(store)
    predecessor = _predecessor(records, root, predecessor_entry, M2Edge.B15)
    if isinstance(predecessor, LifecycleCause):
        return NotRouted(predecessor)
    previous = _occurrence_effect(records, predecessor, M2Edge.B15)  # guard:ga_lifecycle_once
    if previous is not None:
        return previous if isinstance(previous, OccurrenceReplayed) else NotRouted(previous)
    position = dv.derive_m2_position(records, root)
    if not isinstance(position, dv.Occupancy) or position.reached != predecessor:
        return NotRouted(LifecycleCause.EPOCH_NOT_AT_POSITION)
    if not isinstance(predecessor.cycle_occurrence, Present):
        return NotRouted(LifecycleCause.INCONSISTENT_RECORDS)
    current = _occurrence(records, predecessor.cycle_occurrence.value)
    if isinstance(current, LifecycleCause):
        return NotRouted(current)
    closer = _closer(records, current)
    if isinstance(closer, LifecycleCause):
        return NotRouted(closer)
    if closer is not None:
        effect = _assessment_effect(records, closer, current)
        if effect is not None:
            return NotRouted(effect)
        admission = closure_admissibility(records, closer.identity)
        if not isinstance(admission, Admissible):
            cause = admission.causes[0] if isinstance(admission, Nonconformant) else admission.cause
            return NotRouted(cause)
    if not set(upstream) <= UPSTREAM_CYCLE:
        return NotRouted(LifecycleCause.UPSTREAM_FACTS_INVALID)
    integrity = _closure_history_integrity(records, root)
    if integrity:
        return NotRouted(integrity)
    facts = cycle_facts(records, current.identity, upstream, policy)
    b15 = sm.evaluate(M2Edge.B15, predecessor.state, facts)
    b8 = sm.evaluate(M2Edge.B8, predecessor.state, facts)
    if isinstance(b15, sm.Admitted) and isinstance(b8, sm.Admitted):  # guard:ga_tier_ordering
        return NotRouted(LifecycleCause.INCONSISTENT_RECORDS)
    if isinstance(b15, sm.Admitted):  # guard:ga_tier_ordering
        if closer is None:
            return NotRouted(LifecycleCause.INCONSISTENT_RECORDS)
        result = _establish(store, predecessor, M2Edge.B15, closer.identity)
        return NotRouted(result) if isinstance(result, LifecycleCause) else result
    if isinstance(b8, sm.Admitted):  # guard:ga_tier_ordering
        return GateDue(b8)
    return NotRouted(LifecycleCause.GUARD_REFUSED, b15, b8)


def record_closure_assessments(
    store: CoordinationStore, activation: WorkerActivationId
) -> AssessmentsRecorded | AssessmentsReplayed | NothingToRecord | NotRecorded:
    records = read_lifecycle_records(store)
    run = _activation(records, activation)
    if isinstance(run, LifecycleCause):
        return NotRecorded(run)
    if run.role != Role.BOUNDED_CLOSURE_VERIFIER:
        return NotRecorded(LifecycleCause.WRONG_ROLE)
    state = _completed(records, run)
    if state is not True:
        return NotRecorded(
            state if isinstance(state, LifecycleCause) else LifecycleCause.NOT_COMPLETED_ADOPTED
        )
    if not isinstance(run.cycle_occurrence, Present):
        return NotRecorded(LifecycleCause.INCONSISTENT_RECORDS)
    occurrence = _occurrence(records, run.cycle_occurrence.value)
    if isinstance(occurrence, LifecycleCause):
        return NotRecorded(occurrence)
    items = _closure_items(records, run)
    if isinstance(items, LifecycleCause):
        return NotRecorded(items)
    if _unreadable(records, ClosureAssessmentRecord):
        return NotRecorded(LifecycleCause.UNREADABLE_RECORDS)
    previous = tuple(
        r
        for r in _rows(records, ClosureAssessmentRecord)
        if r.assessment.identity.closure_activation == activation
    )  # guard:ga_lifecycle_once
    effect = _assessment_effect(records, run, occurrence)
    if not previous and effect not in {None, LifecycleCause.ASSESSMENTS_NOT_RECORDED}:
        return NotRecorded(effect)
    if previous:  # guard:ga_lifecycle_once LO-3
        if effect:
            return NotRecorded(
                effect if effect == LifecycleCause.UNREADABLE_RECORDS else LifecycleCause.CONFLICT
            )
        return AssessmentsReplayed(frozenset(previous))
    admission = closure_admissibility(records, activation)
    if not isinstance(admission, Admissible):
        cause = admission.causes[0] if isinstance(admission, Nonconformant) else admission.cause
        return NotRecorded(cause)
    if not items:
        return NothingToRecord()
    assessments = tuple(
        ClosureAssessmentRecord(
            assessment=ClosureAssessment(
                identity=ClosureAssessmentId(
                    assessed_finding=i.member, closure_activation=activation
                )
            ),
            verdict=i.verdict,
            cycle_occurrence=run.cycle_occurrence,
        )
        for i in items
    )
    try:
        store.create_unit(assessments)
    except WriteRefused:
        fresh = read_lifecycle_records(store)
        effect = _assessment_effect(fresh, run, occurrence)
        if effect == LifecycleCause.ASSESSMENTS_NOT_RECORDED:
            return NotRecorded(LifecycleCause.WRITE_REFUSED)
        if effect:
            return NotRecorded(
                effect if effect == LifecycleCause.UNREADABLE_RECORDS else LifecycleCause.CONFLICT
            )
        return AssessmentsReplayed(
            frozenset(
                r
                for r in _rows(fresh, ClosureAssessmentRecord)
                if r.assessment.identity.closure_activation == activation
            )
        )
    return AssessmentsRecorded(assessments)


def record_post_freeze_candidates(
    store: CoordinationStore, activation: WorkerActivationId
) -> CandidatesRecorded | CandidatesReplayed | NothingToRecord | NotRecorded:
    records = read_lifecycle_records(store)
    run = _activation(records, activation)
    if isinstance(run, LifecycleCause):
        return NotRecorded(run)
    if run.role not in {Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER}:
        return NotRecorded(LifecycleCause.WRONG_ROLE)
    state = _completed(records, run)
    if state is not True:  # guard:ga_candidate_record
        return NotRecorded(
            state if isinstance(state, LifecycleCause) else LifecycleCause.NOT_COMPLETED_ADOPTED
        )
    if not isinstance(run.cycle_occurrence, Present):
        return NotRecorded(LifecycleCause.INCONSISTENT_RECORDS)
    occurrence = _occurrence(records, run.cycle_occurrence.value)
    if isinstance(occurrence, LifecycleCause):
        return NotRecorded(occurrence)
    ingestion = _ingestion(records, run)
    if isinstance(ingestion, LifecycleCause):
        return NotRecorded(ingestion)
    if _unreadable(records, PostFreezeCandidateRecord):
        return NotRecorded(LifecycleCause.UNREADABLE_RECORDS)
    count = sum(isinstance(i, PostFreezeCandidateItem) for i in ingestion.items)
    previous = tuple(
        r
        for r in _rows(records, PostFreezeCandidateRecord)
        if r.candidate.observing_activation == activation
    )  # guard:ga_lifecycle_once
    if previous:  # guard:ga_lifecycle_once LO-4
        if len(previous) != count or any(
            r.cycle_occurrence != run.cycle_occurrence or r.candidate.stage != run.stage
            for r in previous
        ):
            return NotRecorded(LifecycleCause.CONFLICT)
        return CandidatesReplayed(frozenset(previous))
    if not count:
        return NothingToRecord()
    candidates = tuple(
        PostFreezeCandidateRecord(
            candidate=PostFreezeCandidate(
                identity=PostFreezeCandidateId(value=mint_value()),
                stage=run.stage,
                observing_activation=activation,
            ),
            cycle_occurrence=run.cycle_occurrence,
        )
        for _ in range(count)
    )
    try:
        store.create_unit(candidates)  # guard:ga_candidate_record
    except WriteRefused:
        fresh = read_lifecycle_records(store)
        if _unreadable(fresh, PostFreezeCandidateRecord):
            return NotRecorded(LifecycleCause.UNREADABLE_RECORDS)
        prior = tuple(
            r
            for r in _rows(fresh, PostFreezeCandidateRecord)
            if r.candidate.observing_activation == activation
        )
        if len(prior) == count and all(
            r.cycle_occurrence == run.cycle_occurrence and r.candidate.stage == run.stage
            for r in prior
        ):
            return CandidatesReplayed(frozenset(prior))
        return NotRecorded(LifecycleCause.CONFLICT if prior else LifecycleCause.WRITE_REFUSED)
    return CandidatesRecorded(candidates)


def post_freeze_candidates(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> frozenset[PostFreezeCandidateId] | LifecycleIndeterminate:
    if _unreadable(records, PostFreezeCandidateRecord, WorkerActivationRecord, CycleOccurrence):
        return LifecycleIndeterminate(LifecycleCause.UNREADABLE_RECORDS)
    result: set[PostFreezeCandidateId] = set()
    for record in _rows(records, PostFreezeCandidateRecord):
        run = _activation(records, record.candidate.observing_activation)
        if isinstance(run, LifecycleCause):
            return LifecycleIndeterminate(run)
        if run.resolved_root != root:
            continue
        if record.cycle_occurrence != run.cycle_occurrence or not isinstance(
            record.cycle_occurrence, Present
        ):
            return LifecycleIndeterminate(LifecycleCause.INCONSISTENT_RECORDS)
        occurrence = _occurrence(records, record.cycle_occurrence.value)
        if (
            isinstance(occurrence, LifecycleCause)
            or occurrence.predecessor_entry.epoch_root != root
        ):
            return LifecycleIndeterminate(LifecycleCause.INCONSISTENT_RECORDS)
        result.add(record.candidate.identity)
    return frozenset(result)
