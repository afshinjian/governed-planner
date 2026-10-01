"""Design basis: AP-11 §16 GP-AUTO-ST-08; AP-09 §8 (AT9-0…AT9-9,
DC9-1…DC9-17); AP-04 §5.3.1 (ST-1…ST-5), CP-4, RP-1…RP-3, V-06;
AP-02 §4.2.3; AP-07 RC-23, RC-24, RC-30, RC-39, RS7-6…RS7-14.

OWNER decisions 01-A, 03-B, 04-A and PA-01-A/PA-02-A/PA-03-B apply;
accepted AP-09 producer-attribution amendment PA9-1…PA9-4 (§9, §13.3),
and accepted AP-11 PA03-B amendment qualify the frozen contracts.

The full AT9-1b conjunction is the sole attribution basis. External writes
inside the declared boundary with no other indication are indistinguishable
from the subject's work (AT9-1d); exclusive causation is not established.
Brackets are transient. Determinations are durable. Scheduling, halt units,
closure edges and adoption belong to their later stages.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from gpauto import authority, observation
from gpauto import derivations as dv
from gpauto import state_machine as sm
from gpauto import state_machine_model as model
from gpauto.absence import Carried, KnownAbsent, NotObserved, Present
from gpauto.coordination_identity import ConformanceDeterminationId, HaltOccurrenceId
from gpauto.coordination_records import (
    ActivationEffectRecord,
    AuthorityEnvelopeRecord,
    ConformanceDetermination,
    EffectEnvelopeConformance,
    EnvelopeConformanceDetermination,
    EnvelopeViolationRecord,
    ExecutionObservation,
    HaltOccurrence,
    ObligationDispositionItem,
    OutcomeIngestionRecord,
    QuiescenceObservation,
    ResidueDetermination,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import M3Position, ObligationDisposition, Quiescence
from gpauto.identity import (
    ActivationEffectId,
    AuthorityEnvelopeId,
    OwnerAuthorizationId,
    RefusalId,
    UnaccountedMutationId,
    WorkerActivationId,
)
from gpauto.minting import mint_value
from gpauto.repository import UnaccountedMutation
from gpauto.store import CoordinationStore, UnreadableRecord, WriteRefused
from gpauto.vocabulary import Role, WriteMode


class AssessmentCause(StrEnum):
    UNREADABLE_RECORDS = "UNREADABLE_RECORDS"
    INCONSISTENT_RECORDS = "INCONSISTENT_RECORDS"
    SUBJECT_NOT_FOUND = "SUBJECT_NOT_FOUND"
    SUBJECT_NOT_ASSESSABLE = "SUBJECT_NOT_ASSESSABLE"
    ENVELOPE_NOT_DERIVED = "ENVELOPE_NOT_DERIVED"
    ENVELOPE_POSITION_MISMATCH = "ENVELOPE_POSITION_MISMATCH"
    BOUNDARY_NOT_FIXED = "BOUNDARY_NOT_FIXED"
    WRITE_DOMAIN_NOT_EXCLUSIVE = "WRITE_DOMAIN_NOT_EXCLUSIVE"
    PREDECESSOR_NOT_CLOSED = "PREDECESSOR_NOT_CLOSED"
    PREDECESSOR_NOT_DETERMINED = "PREDECESSOR_NOT_DETERMINED"
    QUIESCENCE_NOT_OBSERVED = "QUIESCENCE_NOT_OBSERVED"
    OPENING_BRACKET_MISSING = "OPENING_BRACKET_MISSING"
    CLOSING_BRACKET_MISSING = "CLOSING_BRACKET_MISSING"
    BRACKET_MISMATCH = "BRACKET_MISMATCH"
    OBSERVATION_INDETERMINATE = "OBSERVATION_INDETERMINATE"
    PRIOR_STATE_INDETERMINATE = "PRIOR_STATE_INDETERMINATE"
    REFERENTS_UNAVAILABLE = "REFERENTS_UNAVAILABLE"
    CORRESPONDENCE_UNREADABLE = "CORRESPONDENCE_UNREADABLE"
    WRITE_REFUSED = "WRITE_REFUSED"


class BracketEnd(StrEnum):
    OPENING = "OPENING"
    CLOSING = "CLOSING"


class Row(StrEnum):
    DC9_1 = "DC9-1"
    DC9_2 = "DC9-2"
    DC9_3 = "DC9-3"
    DC9_4 = "DC9-4"
    DC9_5 = "DC9-5"
    DC9_6 = "DC9-6"
    DC9_7 = "DC9-7"
    DC9_8 = "DC9-8"
    DC9_9 = "DC9-9"
    PENDING = "PENDING"


@dataclass(frozen=True)
class Bracket:
    end: BracketEnd
    root: OwnerAuthorizationId
    envelope: AuthorityEnvelopeId
    activation: WorkerActivationId | None
    observation: observation.Observation


@dataclass(frozen=True)
class BracketIndeterminate:
    cause: AssessmentCause
    observation_causes: tuple[observation.ObservationCause, ...] = ()


@dataclass(frozen=True)
class NotAssessed:
    cause: AssessmentCause
    row: Row = Row.DC9_9


@dataclass(frozen=True)
class NotRecorded:
    cause: AssessmentCause


@dataclass(frozen=True)
class Replayed:
    determinations: tuple[ConformanceDetermination, ...] = ()
    mutations: tuple[UnaccountedMutation, ...] = ()


@dataclass(frozen=True)
class Difference:
    subject: str
    key: str
    elements: tuple[str, ...]
    at_opening: bool


@dataclass(frozen=True)
class Classified:
    difference: Difference
    row: Row


@dataclass(frozen=True)
class Classification:
    differences: tuple[Classified, ...]
    unchanged: tuple[tuple[str, Row], ...]
    defeats: frozenset[str]


@dataclass(frozen=True)
class Assessed:
    classification: Classification
    determinations: tuple[ConformanceDetermination, ...]
    effects: tuple[ActivationEffectRecord, ...]
    mutations: tuple[UnaccountedMutation, ...]


@dataclass(frozen=True)
class Recorded:
    mutation: UnaccountedMutation


@dataclass(frozen=True)
class NothingToRecord:
    pass


@dataclass(frozen=True)
class RecordedClassification:
    identity: ActivationEffectId | UnaccountedMutationId
    row: Row


EXTRA_INPUTS = (
    UnaccountedMutation,
    EnvelopeViolationRecord,
    ExecutionObservation,
    OutcomeIngestionRecord,
)
TERMINAL = frozenset({M3Position.ACTIVATION_COMPLETED, M3Position.ACTIVATION_CLOSED_UNADOPTED})
ABSENT = KnownAbsent(basis="ST-08 determination: none in this assessment")


def read_records(store: CoordinationStore) -> dv.AuthoritativeRecords:
    """Stable records including RC-24/30/37/38, through existing read surfaces."""
    passes = []
    for _ in range(2):
        base = authority.read_authority_records(store)
        records = list(base.derivable.records) + list(base.records)
        unreadable = set(base.derivable.unreadable) | {k for k, _ in base.unreadable}
        unstable = set(base.derivable.unstable)
        for kind in EXTRA_INPUTS:
            for record in store.enumerate(kind):
                if isinstance(record, UnreadableRecord):
                    unreadable.add(kind)
                else:
                    records.append(record)
        if base.unstable:
            unstable.update(authority.AUTHORITY_INPUTS)
        passes.append(
            dv.AuthoritativeRecords(tuple(records), frozenset(unreadable), frozenset(unstable))
        )
    if passes[0] != passes[1]:
        return dv.AuthoritativeRecords(
            (),
            unstable=frozenset((*dv.DERIVATION_INPUTS, *EXTRA_INPUTS, *authority.AUTHORITY_INPUTS)),
        )
    return passes[0]


def _of[T](records: dv.AuthoritativeRecords, kind: type[T]) -> tuple[T, ...]:
    return tuple(r for r in records.records if isinstance(r, kind))


def _subject(
    records: dv.AuthoritativeRecords, activation: WorkerActivationId
) -> WorkerActivationRecord | None:
    found = [r for r in _of(records, WorkerActivationRecord) if r.identity == activation]
    return found[0] if len(found) == 1 else None


def _envelope(
    records: dv.AuthoritativeRecords, envelope: AuthorityEnvelopeId
) -> AuthorityEnvelopeRecord | None:
    found = [r for r in _of(records, AuthorityEnvelopeRecord) if r.envelope.identity == envelope]
    return found[0] if len(found) == 1 else None


def _bound(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> observation.Referents | None:
    if (records.unreadable | records.unstable) & set(authority.AUTHORITY_INPUTS):
        return None
    return observation.bound_referents(
        authority.AuthorityRecords(records, records.records, (), False), root
    )


def _key(
    records: dv.AuthoritativeRecords, activation: WorkerActivationId
) -> Replayed | NotAssessed | None:
    needed = {ConformanceDetermination, ActivationEffectRecord, UnaccountedMutation}
    if needed & (records.unreadable | records.unstable):
        return NotAssessed(AssessmentCause.UNREADABLE_RECORDS)
    determinations = tuple(
        r
        for r in _of(records, ConformanceDetermination)
        if r.identity.activation == activation
        and isinstance(r.determination, (EnvelopeConformanceDetermination, ResidueDetermination))
    )
    kinds = [type(r.determination) for r in determinations]
    if (
        kinds.count(EnvelopeConformanceDetermination) == 1
        and kinds.count(ResidueDetermination) == 1
    ):
        return Replayed(determinations)
    effects = [
        r
        for r in _of(records, ActivationEffectRecord)
        if r.identity.parent_activation == activation
    ]
    named = [
        r
        for r in _of(records, UnaccountedMutation)
        if r.producing_activation == Present[WorkerActivationId](value=activation)
    ]
    if determinations or effects or named:
        return NotAssessed(AssessmentCause.INCONSISTENT_RECORDS)
    return None


def observed_quiescent(
    records: dv.AuthoritativeRecords, activation: WorkerActivationId
) -> bool | None:
    if ExecutionObservation in (records.unreadable | records.unstable):
        return None
    return any(
        r.identity.activation == activation
        and isinstance(r.observation, QuiescenceObservation)
        and r.observation.quiescence == Quiescence.QUIESCENT  # guard:ga_bracket_exclusivity
        for r in _of(records, ExecutionObservation)
    )


def _closing_cause(
    records: dv.AuthoritativeRecords, subject: WorkerActivationRecord
) -> AssessmentCause | None:
    if (records.unreadable | records.unstable) - {OutcomeIngestionRecord}:
        return AssessmentCause.UNREADABLE_RECORDS
    position = dv.derive_m3_position(records, subject.envelope)
    assessable = TERMINAL | {M3Position.ACTIVATION_RUNNING}  # guard:ga_stratified_assessment
    if not isinstance(position, dv.Occupancy) or position.reached.state not in assessable:
        return AssessmentCause.SUBJECT_NOT_ASSESSABLE
    if observed_quiescent(records, subject.identity) is not True:  # guard:ga_bracket_exclusivity
        return AssessmentCause.QUIESCENCE_NOT_OBSERVED
    for envelope in _of(records, AuthorityEnvelopeRecord):
        if (
            envelope.envelope.resolved_root != subject.resolved_root
            or envelope.envelope.identity == subject.envelope
        ):
            continue
        other = dv.derive_m3_position(records, envelope.envelope.identity)
        if (
            not isinstance(other, dv.Occupancy)
            or other.reached.state == M3Position.ACTIVATION_RUNNING
        ):
            return AssessmentCause.WRITE_DOMAIN_NOT_EXCLUSIVE  # guard:ga_bracket_exclusivity
    return None


def _observe(
    records: dv.AuthoritativeRecords,
    envelope: AuthorityEnvelopeRecord,
    end: BracketEnd,
    activation: WorkerActivationId | None,
    reader: observation.Reader,
) -> Bracket | BracketIndeterminate:
    root = envelope.envelope.resolved_root
    bound = _bound(records, root)
    if bound is None:
        return BracketIndeterminate(AssessmentCause.REFERENTS_UNAVAILABLE)
    found = observation.observe(bound.location, reader)
    if isinstance(found, observation.Indeterminate):
        return BracketIndeterminate(AssessmentCause.OBSERVATION_INDETERMINATE, found.causes)
    return Bracket(end, root, envelope.envelope.identity, activation, found.observation)


def take_opening_bracket(
    store: CoordinationStore,
    envelope: AuthorityEnvelopeId,
    reader: observation.Reader = observation.FILESYSTEM,
) -> Bracket | BracketIndeterminate:
    records = read_records(store)
    if records.unreadable or records.unstable:
        return BracketIndeterminate(AssessmentCause.UNREADABLE_RECORDS)
    subject = _envelope(records, envelope)
    if subject is None:
        return BracketIndeterminate(AssessmentCause.SUBJECT_NOT_FOUND)
    position = dv.derive_m3_position(records, envelope)
    if (
        not isinstance(position, dv.Occupancy)
        or position.reached.state != M3Position.ENVELOPE_DERIVED
    ):
        return BracketIndeterminate(AssessmentCause.ENVELOPE_NOT_DERIVED)  # guard:ga_bracket_exclusivity  # noqa: E501  # fmt: skip
    root = subject.envelope.resolved_root
    epoch = dv.derive_m2_position(records, root)
    if not isinstance(epoch, dv.Occupancy) or epoch.reached.state != subject.target_state:
        return BracketIndeterminate(AssessmentCause.ENVELOPE_POSITION_MISMATCH)
    if observation.boundary_facts(records, root).get(model.BOUNDARY_FIXED.name) != model.TRUE:
        return BracketIndeterminate(AssessmentCause.BOUNDARY_NOT_FIXED)
    for other in _of(records, AuthorityEnvelopeRecord):
        if other.envelope.resolved_root == root:
            state = dv.derive_m3_position(records, other.envelope.identity)
            if (
                not isinstance(state, dv.Occupancy)
                or state.reached.state == M3Position.ACTIVATION_RUNNING
            ):
                return BracketIndeterminate(AssessmentCause.WRITE_DOMAIN_NOT_EXCLUSIVE)
    for previous in _of(records, WorkerActivationRecord):
        if previous.resolved_root != root:
            continue
        prior = dv.derive_m3_position(records, previous.envelope)
        if (
            not isinstance(prior, dv.Occupancy)
            or prior.reached.state not in TERMINAL
            or observed_quiescent(records, previous.identity) is not True
        ):
            return BracketIndeterminate(AssessmentCause.PREDECESSOR_NOT_CLOSED)  # guard:ga_bracket_exclusivity  # noqa: E501  # fmt: skip
        if not isinstance(_key(records, previous.identity), Replayed):
            return BracketIndeterminate(AssessmentCause.PREDECESSOR_NOT_DETERMINED)  # guard:ga_bracket_exclusivity  # noqa: E501  # fmt: skip
    return _observe(records, subject, BracketEnd.OPENING, None, reader)


def take_closing_bracket(
    store: CoordinationStore,
    activation: WorkerActivationId,
    reader: observation.Reader = observation.FILESYSTEM,
) -> Bracket | BracketIndeterminate:
    records = read_records(store)
    subject = _subject(records, activation)
    if subject is None:
        cause = (
            AssessmentCause.UNREADABLE_RECORDS
            if records.unreadable or records.unstable
            else AssessmentCause.SUBJECT_NOT_FOUND
        )
        return BracketIndeterminate(cause)
    closing_cause = _closing_cause(records, subject)
    if closing_cause is not None:
        return BracketIndeterminate(closing_cause)
    envelope = _envelope(records, subject.envelope)
    if envelope is None:
        return BracketIndeterminate(AssessmentCause.SUBJECT_NOT_FOUND)
    return _observe(records, envelope, BracketEnd.CLOSING, activation, reader)


def within_write_boundary(path: bytes, tokens: tuple[str, ...]) -> bool:
    """03-B; a path relation, separate from SP6-16's token equality."""
    try:
        decoded = path.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    for token in tokens:
        matches = decoded.startswith(token) if token.endswith("/") else decoded == token  # guard:ga_attribution_conjunction  # noqa: E501  # fmt: skip
        if matches:
            return True
    return False


def _elements(elements: tuple[str, ...], index: bool = False) -> dict[str, str]:
    return {(e.split()[-1] + (":" + e.split()[2] if index else "")): e for e in elements}


def _expected(prior: dv.PriorAuthorizedState) -> dict[str, str]:
    state = _elements(prior.boundary.pre_existing_working_tree_state)
    for term in prior.terms:  # guard:ga_stratified_assessment
        for effect in term.effects:
            element = effect.observed_state[0]
            path = element.split()[-1]
            if element.startswith("absent "):
                state.pop(path, None)
            else:
                state[path] = element
    return state


def _differences(
    prior: dv.PriorAuthorizedState,
    bound: observation.Referents,
    opening: observation.Observation,
    closing: observation.Observation,
) -> tuple[tuple[Difference, ...], tuple[tuple[str, Row], ...]]:
    expected = _expected(prior)  # guard:ga_stratified_assessment
    index = _elements(prior.boundary.pre_existing_index_state, True)
    found: list[Difference] = []
    unchanged: list[tuple[str, Row]] = []
    inherited = set(_elements(prior.boundary.pre_existing_working_tree_state)) - {
        effect.observed_state[0].split()[-1] for term in prior.terms for effect in term.effects
    }
    for subject, baseline, first, last in (
        ("tree", expected, _elements(opening.working_tree), _elements(closing.working_tree)),
        ("index", index, _elements(opening.index, True), _elements(closing.index, True)),
    ):
        for key in sorted(baseline.keys() | first.keys() | last.keys()):  # inert presentation order
            absent = f"absent - - {key.split(':')[0]}"
            reference = baseline.get(key, absent)
            start, end = first.get(key, absent), last.get(key, absent)
            values = tuple(dict.fromkeys(e for e in (start, end) if e != reference))
            if values:
                elements = tuple(f"index {e}" for e in values) if subject == "index" else values
                found.append(Difference(subject, key, elements, start != reference))
            elif key in baseline and (subject == "index" or key in inherited):
                unchanged.append((reference, Row.DC9_1))
    for subject, expected_values, first_value, last_value in (
        (
            "branch",
            (bound.branch.encode().hex(),),
            opening.branch.hex() if opening.branch is not None else "-",
            closing.branch.hex() if closing.branch is not None else "-",
        ),
        ("baseline", bound.commits, opening.baseline or "-", closing.baseline or "-"),
        (
            "committed-history",
            bound.commits,
            opening.committed_history or "-",
            closing.committed_history or "-",
        ),
    ):
        values = tuple(
            dict.fromkeys(
                f"{subject} {e}" for e in (first_value, last_value) if e not in expected_values
            )
        )
        if values:
            found.append(Difference(subject, subject, values, first_value not in expected_values))
    return tuple(found), tuple(unchanged)


def _corresponds(
    element: str, ingestion: OutcomeIngestionRecord | None, admitted: dv.CycleBound | dv.NoFrozenSet
) -> bool:
    if ingestion is None or not isinstance(admitted, dv.CycleBound):
        return False
    if element.startswith("absent "):
        return False
    identity = element.split()[2]
    return any(
        isinstance(item, ObligationDispositionItem)
        and item.obligation in admitted.members  # guard:ga_attribution_conjunction
        and item.disposition == ObligationDisposition.ADDRESSED
        and item.change_evidence.production in ingestion.objective_channel
        and item.change_evidence.production.content.value == identity
        for item in ingestion.items
    )


def classify(
    prior: dv.PriorAuthorizedState,
    bound: observation.Referents,
    envelope: AuthorityEnvelopeRecord,
    opening: observation.Observation,
    closing: observation.Observation,
    exclusive: bool,
    ingestion: OutcomeIngestionRecord | None = None,
    admitted: dv.CycleBound | dv.NoFrozenSet | None = None,
) -> Classification:
    """Two passes; P(N,e) implies C(N,e). No completion input or producer search."""
    differences, unchanged = _differences(prior, bound, opening, closing)
    defeats: set[str] = set()
    bounds = envelope.envelope.bounds
    writing = bounds.write_mode == WriteMode.WRITING  # guard:ga_attribution_conjunction
    tokens = (
        bounds.write_boundary.value.scopes if isinstance(bounds.write_boundary, Carried) else ()
    )
    if not exclusive:  # guard:ga_attribution_conjunction
        defeats.add("interval")
    for difference in differences:
        if difference.subject != "tree":
            defeats.add("b")  # guard:ga_attribution_defeat
            continue
        if difference.at_opening:  # guard:ga_attribution_defeat
            defeats.add("opening")
        if not writing:  # guard:ga_attribution_defeat
            defeats.add("c")
        contained = within_write_boundary(bytes.fromhex(difference.key), tokens)
        if not contained:  # guard:ga_attribution_conjunction
            defeats.add("a")  # guard:ga_attribution_defeat
        if (
            envelope.envelope.role == Role.REMEDIATOR
            and not all(  # guard:ga_attribution_conjunction
                _corresponds(e, ingestion, admitted or dv.NoFrozenSet(prior.context.authorization))
                for e in difference.elements
            )
        ):
            defeats.add("f")  # guard:ga_attribution_defeat
    classified = []
    for difference in differences:
        if difference.subject in {"branch", "baseline", "committed-history"}:  # guard:ga_classification_dispatch  # noqa: E501  # fmt: skip
            row = Row.DC9_7  # guard:ga_classification_dispatch
        elif difference.subject == "index":
            row = Row.DC9_6  # guard:ga_classification_dispatch
        elif defeats:  # guard:ga_classification_dispatch
            row = Row.DC9_8
        else:
            row = Row.PENDING
        classified.append(Classified(difference, row))
    return Classification(tuple(classified), unchanged, frozenset(defeats))


def _exclusive(records: dv.AuthoritativeRecords, subject: WorkerActivationRecord) -> bool:
    epoch = dv.derive_m2_position(records, subject.resolved_root)
    if not isinstance(epoch, dv.Occupancy):
        return False
    strata = {e.identity: place for place, e in enumerate(epoch.chain)}
    envelope = _envelope(records, subject.envelope)
    if envelope is None or envelope.predecessor_entry not in strata:
        return False
    before = strata[envelope.predecessor_entry]
    for other in _of(records, WorkerActivationRecord):
        if other.resolved_root != subject.resolved_root or other.identity == subject.identity:
            continue
        prior = _envelope(records, other.envelope)
        position = dv.derive_m3_position(records, other.envelope)
        if prior is None or strata.get(prior.predecessor_entry, before) >= before:
            return False
        if (
            not isinstance(position, dv.Occupancy)
            or position.reached.state not in TERMINAL
            or observed_quiescent(records, other.identity) is not True
        ):
            return False
    return True


def _affected(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> tuple[AuthorityEnvelopeId, ...]:
    found = []
    for envelope in _of(records, AuthorityEnvelopeRecord):
        if envelope.envelope.resolved_root != root:
            continue
        position = dv.derive_m3_position(records, envelope.envelope.identity)
        if isinstance(position, dv.Occupancy) and position.reached.state in {
            M3Position.ENVELOPE_DERIVED,
            M3Position.ACTIVATION_RUNNING,
        }:
            found.append(envelope.envelope.identity)
    return tuple(sorted(found, key=lambda e: e.value))  # inert presentation order


def _determination(
    activation: WorkerActivationId, value: EnvelopeConformanceDetermination | ResidueDetermination
) -> ConformanceDetermination:
    return ConformanceDetermination(
        identity=ConformanceDeterminationId(activation=activation, discriminator=mint_value()),
        determination=value,
    )


def assess_activation(
    store: CoordinationStore,
    activation: WorkerActivationId,
    opening: Bracket | None,
    closing: Bracket | None,
) -> Assessed | Replayed | NotAssessed:
    records = read_records(store)
    previous = _key(records, activation)
    if previous is not None:  # guard:ga_assessment_once_per_activation
        return previous
    if opening is None:
        return NotAssessed(AssessmentCause.OPENING_BRACKET_MISSING)  # guard:ga_attribution_conjunction  # noqa: E501  # fmt: skip
    if closing is None:
        return NotAssessed(AssessmentCause.CLOSING_BRACKET_MISSING)
    subject = _subject(records, activation)
    if subject is None:
        return NotAssessed(AssessmentCause.SUBJECT_NOT_FOUND)
    mismatch = (
        opening.end != BracketEnd.OPENING
        or closing.end != BracketEnd.CLOSING
        or opening.activation is not None
        or closing.activation != activation
        or opening.envelope != subject.envelope
        or closing.envelope != subject.envelope
        or opening.root != subject.resolved_root
        or closing.root != subject.resolved_root
    )
    if mismatch:  # guard:ga_attribution_conjunction
        return NotAssessed(AssessmentCause.BRACKET_MISMATCH)
    cause = _closing_cause(records, subject)
    if cause is not None:
        return NotAssessed(cause)
    prior = dv.derive_prior_authorized_state(records, activation)
    if isinstance(prior, dv.Indeterminate):
        return NotAssessed(AssessmentCause.PRIOR_STATE_INDETERMINATE)
    bound = _bound(records, subject.resolved_root)
    if bound is None or not bound.commits:
        return NotAssessed(AssessmentCause.REFERENTS_UNAVAILABLE)
    envelope = _envelope(records, subject.envelope)
    if envelope is None:
        return NotAssessed(AssessmentCause.SUBJECT_NOT_ASSESSABLE)
    ingestion = None
    admitted: dv.CycleBound | dv.NoFrozenSet | None = None
    if envelope.envelope.role == Role.REMEDIATOR:
        if OutcomeIngestionRecord in records.unreadable | records.unstable:
            return NotAssessed(AssessmentCause.CORRESPONDENCE_UNREADABLE)
        ingestions = [r for r in _of(records, OutcomeIngestionRecord) if r.activation == activation]
        if len(ingestions) > 1:
            return NotAssessed(AssessmentCause.CORRESPONDENCE_UNREADABLE)
        ingestion = ingestions[0] if ingestions else None
        cycle = dv.derive_cycle_bound(records, subject.resolved_root)
        if isinstance(cycle, dv.Indeterminate):
            return NotAssessed(AssessmentCause.CORRESPONDENCE_UNREADABLE)
        admitted = cycle
    result = classify(
        prior,
        bound,
        envelope,
        opening.observation,
        closing.observation,
        _exclusive(records, subject),
        ingestion,
        admitted,
    )
    effects: list[ActivationEffectRecord] = []
    mutations: list[UnaccountedMutation] = []
    for item in result.differences:
        if item.row == Row.PENDING:  # guard:ga_classification_dispatch
            effects.append(
                ActivationEffectRecord(
                    identity=ActivationEffectId(
                        parent_activation=activation, local_discriminator=mint_value()
                    ),
                    observed_state=item.difference.elements,
                    cycle_occurrence=subject.cycle_occurrence,
                )
            )
        else:
            mutations.append(
                UnaccountedMutation(
                    identity=UnaccountedMutationId(value=mint_value()),
                    context=prior.context,
                    observed_state=item.difference.elements,
                    unexplained_portion=item.difference.elements,
                    affected_envelopes=_affected(records, subject.resolved_root),
                    producing_activation=NotObserved(),  # guard:ga_classification_dispatch
                )
            )
    conformance = _determination(
        activation,
        EnvelopeConformanceDetermination(
            effects=tuple(
                EffectEnvelopeConformance(effect=e.identity, within_envelope=True) for e in effects
            ),
            violations=ABSENT,
        ),
    )
    residue = _determination(
        activation,
        ResidueDetermination(
            mutations=Present[tuple[UnaccountedMutationId, ...]](
                value=tuple(r.identity for r in mutations)
            )
            if mutations
            else ABSENT,
        ),
    )
    try:
        store.create_unit((*effects, *mutations, conformance, residue))  # guard:ga_classification_dispatch  # guard:ga_assessment_once_per_activation  # noqa: E501  # fmt: skip
    except WriteRefused:
        reread = _key(read_records(store), activation)
        return (
            reread if isinstance(reread, Replayed) else NotAssessed(AssessmentCause.WRITE_REFUSED)
        )
    return Assessed(result, (conformance, residue), tuple(effects), tuple(mutations))


def record_non_completed_residue(
    store: CoordinationStore, activation: WorkerActivationId
) -> Recorded | Replayed | NothingToRecord | NotRecorded:
    records = read_records(store)
    if records.unreadable or records.unstable:
        return NotRecorded(AssessmentCause.UNREADABLE_RECORDS)
    subject = _subject(records, activation)
    if subject is None:
        return NotRecorded(AssessmentCause.SUBJECT_NOT_FOUND)
    position = dv.derive_m3_position(records, subject.envelope)
    if (
        not isinstance(position, dv.Occupancy)
        or position.reached.state != M3Position.ACTIVATION_CLOSED_UNADOPTED
    ):
        return NotRecorded(AssessmentCause.SUBJECT_NOT_ASSESSABLE)
    key = _key(records, activation)
    if not isinstance(key, Replayed):
        return NotRecorded(AssessmentCause.INCONSISTENT_RECORDS)
    judgments = {
        i.effect
        for d in key.determinations
        if isinstance(d.determination, EnvelopeConformanceDetermination)
        for i in d.determination.effects
        if i.within_envelope
    }
    effects = [r for r in _of(records, ActivationEffectRecord) if r.identity in judgments]
    elements = tuple(
        sorted({e for r in effects for e in r.observed_state})
    )  # inert presentation order
    if not elements:
        return NothingToRecord()
    prior = dv.derive_prior_authorized_state(records, activation)
    if isinstance(prior, dv.Indeterminate):
        return NotRecorded(AssessmentCause.PRIOR_STATE_INDETERMINATE)
    for mutation in _of(records, UnaccountedMutation):
        if mutation.producing_activation != Present[WorkerActivationId](value=activation):
            continue
        same = mutation.context == prior.context and set(mutation.unexplained_portion) == set(
            elements
        )
        if same:  # guard:ga_assessment_once_per_activation
            return Replayed(mutations=(mutation,))
        if set(mutation.unexplained_portion) & set(elements):
            return NotRecorded(AssessmentCause.INCONSISTENT_RECORDS)
    mutation = UnaccountedMutation(
        identity=UnaccountedMutationId(value=mint_value()),
        context=prior.context,
        observed_state=elements,
        unexplained_portion=elements,
        affected_envelopes=_affected(records, subject.resolved_root),
        producing_activation=Present[WorkerActivationId](value=activation),
    )
    try:
        store.create_unit((mutation,))  # guard:ga_classification_dispatch
    except WriteRefused:
        return NotRecorded(AssessmentCause.WRITE_REFUSED)
    return Recorded(mutation)


def _truth(value: bool) -> str:
    return model.TRUE if value else model.FALSE


def violation_facts(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> sm.Facts:
    if {UnaccountedMutation, EnvelopeViolationRecord} & (  # guard:ga_determination_facts
        records.unreadable | records.unstable
    ):
        return {}
    mutations = any(
        r.context.authorization == root  # guard:ga_determination_facts
        for r in _of(records, UnaccountedMutation)
    )
    violations = any(
        r.violation.resolved_root == root for r in _of(records, EnvelopeViolationRecord)
    )
    return {
        model.UNACCOUNTED_MUTATION.name: _truth(mutations),
        model.RP_1.name: _truth(not mutations),
        model.RP_2.name: _truth(not violations),  # guard:ga_determination_facts
    }


def completion_facts(records: dv.AuthoritativeRecords, activation: WorkerActivationId) -> sm.Facts:
    if {UnaccountedMutation, EnvelopeViolationRecord, ConformanceDetermination} & (
        records.unreadable | records.unstable
    ):
        return {}
    mutation = any(
        r.producing_activation == Present[WorkerActivationId](value=activation)
        for r in _of(records, UnaccountedMutation)
    )
    violation = any(
        r.violation.violating_activation == activation
        for r in _of(records, EnvelopeViolationRecord)
    )
    if mutation or violation:  # guard:ga_determination_facts
        return {model.CP_4.name: model.FALSE}
    if not isinstance(_key(records, activation), Replayed):  # guard:ga_determination_facts
        return {}
    return {model.CP_4.name: model.TRUE}


def halt_cause_facts(records: dv.AuthoritativeRecords, halt: HaltOccurrenceId) -> sm.Facts:
    if HaltOccurrence in records.unreadable | records.unstable:
        return {}
    found = [r for r in _of(records, HaltOccurrence) if r.identity == halt]
    if len(found) != 1:
        return {}
    case_a = isinstance(found[0].event, RefusalId)  # guard:ga_determination_facts
    return {model.RP_3.name: _truth(case_a)}


def classify_recorded(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> tuple[RecordedClassification, ...] | dv.Indeterminate:
    if records.unreadable or records.unstable:
        return dv.Indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "classification inputs")
    result: list[RecordedClassification] = []
    for subject in _of(records, WorkerActivationRecord):
        if subject.resolved_root != root:
            continue
        key = _key(records, subject.identity)
        if not isinstance(key, Replayed):
            continue
        position = dv.derive_m3_position(records, subject.envelope)
        if not isinstance(position, dv.Occupancy):
            return dv.Indeterminate(dv.IndeterminacyCause.INCONSISTENT_RECORDS, "M3 position")
        row = {
            M3Position.ACTIVATION_COMPLETED: Row.DC9_2,
            M3Position.ACTIVATION_CLOSED_UNADOPTED: Row.DC9_4,
        }.get(position.reached.state, Row.PENDING)
        for determination in key.determinations:
            if isinstance(determination.determination, EnvelopeConformanceDetermination):
                result.extend(
                    RecordedClassification(e.effect, row)
                    for e in determination.determination.effects
                    if e.within_envelope
                )
    for mutation in _of(records, UnaccountedMutation):
        if mutation.context.authorization != root or not isinstance(
            mutation.producing_activation, NotObserved
        ):
            continue
        try:
            prefix = mutation.unexplained_portion[0].split()[0]
        except IndexError:
            return dv.Indeterminate(
                dv.IndeterminacyCause.INCONSISTENT_RECORDS, "RC-24 unexplained portion"
            )
        row = (
            Row.DC9_7
            if prefix in {"branch", "baseline", "committed-history"}
            else Row.DC9_6
            if prefix == "index"
            else Row.DC9_8
        )
        result.append(RecordedClassification(mutation.identity, row))
    return tuple(result)
