"""The derivations engine: facts recomputed from authoritative records, and stored nowhere.

Design basis: AP-07 §8 (`DV-1`…`DV-8`, `DV-12`…`DV-14`) as allocated by the AP-11 ST-04
derivation-ownership amendment (`DO11-1`…`DO11-6`, `AP11-I74`); AP-04 §3, §4.1, §5.3.1
(stratification), §6 (M4); the AP-04 amendment §3.3 (`CYCLE_BOUND`, `OP-1`…`OP-4`, `OP-9`);
AP-05 §6.2 (obligation force), §8.2 (`SC-1`), §8.4 (`SC-9`, `SC-10`); AP-07 §3.2, `WP-9`,
`AP07-I18`, `GH-5`…`GH-7`, `GH-11`, `RS7-10`, `RS7-11`, `CO-3`, `CO-9`, `CO-18`; AP-07
root-resolution clarification `RO7A-6`, `RO7A-9`; ST-03 follow-on `SRF11-1`; `ST01C-2` F-5,
F-6, `SC01-4`, `SC01-6`; O6 clarification `O6C-2`, `O6C-13`.

**What this module derives, and what it does not** (`DO11-1`, `DO11-2`, `AP11-I74`):

| Row | Derivation | Here |
|---|---|---|
| `DV-1` | prior authorized state for an assessed activation | `derive_prior_authorized_state` |
| `DV-2` | closure scope of one closure activation | `derive_closure_scope` |
| `DV-3` | `CYCLE_BOUND` of one epoch | `derive_cycle_bound` |
| `DV-4` | liveness of one authorization instance | `derive_liveness` |
| `DV-4` | eligibility **as recorded**, per resolution | `derive_recorded_eligibility` |
| `DV-5` | force of one obligation | `derive_obligation_force` |
| `DV-6` | the M1 … M4 position of one subject | `derive_m1_position` … `derive_m4_position` |
| `DV-7` | the outstanding halt occurrences | `derive_outstanding_halts` |
| `DV-8` | the closure-scope series of one epoch | `derive_closure_scope_series` |

**Not here, by allocation.** `DV-9` (decision package) and `DV-10` (mirror) are ST-15's
(`DO11-4`). `DV-11` (equivalence) is ST-02's `equivalence.py`, and this module holds no
comparator of any kind (`DO11-6`); none of the derivations below needs one. ST-06's portion
of `DV-4` — eligibility evaluation over `RA-00`…`RA-09`, binding match, candidate validity,
exactly-one selection — is not performed here: no `AuthorizationRecord`, `RC-15` exclusion
or authority-bearing content is read, and recorded eligibility only **reads** the `A2`,
`A3` or `A4` entry ST-06 will have produced (`DO11-2`, `DO11-3`). Liveness reads no M1
entry at all, which is why ST-06 can consume it without a cycle (`RO7A-9`).

**Purity** (`DV-12`, `DV-14`). Every derivation is a function of an `AuthoritativeRecords`
value and its arguments, and of nothing else: no clock, no repository, no worker, no
environment, no randomness, and no state kept between calls. Nothing is written — this
module has no write path, no cache, no materialized view and no gate snapshot — and each
result is a frozen dataclass, never a record model, so the store has no write operation
that could accept one. `read_authoritative_records` only reads.

**No storage order, no row identifier, no insertion order** (`NV11-11`, `PA-04`,
`RS7-11`). Sets of identities are returned as `frozenset`s. The only sequences returned —
a position chain, the stratified effect terms, the closure-scope series — are ordered by
recorded **predecessor references**, walked here, never by the order records were read in.
Every derivation gives the same result for any permutation of its input records.

**Indeterminacy is an enumerated result, never an exception sink** (`RC-4`, `P-04`).
Where a required record is absent, unreadable, not read as one consistent set, or
inconsistent with the frozen graph — a forked or broken chain, a completion entry without
its adoption record, two determinations disagreeing about one effect — the result is
`Indeterminate` with one of `IndeterminacyCause`'s causes. Nothing else is caught:
an ordinary defect propagates. Indeterminate is unauthorized; no derivation defaults it to
either side.

**Definitions are frozen architecture** (`DV-13`, `VM-4`). No version, format marker or
configuration is read, and no derivation's meaning depends on one.

Guard identifier fixed where each input-selection guard is written (`MU11-3`):
`ga_derivation_input`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from pydantic import BaseModel

from gpauto.absence import KnownAbsent, Present
from gpauto.authorization import ConsumedDisposition, RevokedDisposition, SuspendedDisposition
from gpauto.coordination_identity import CycleOccurrenceId, HaltOccurrenceId, M1PositionEntryId
from gpauto.coordination_records import (
    ActivationEffectRecord,
    AdoptionDetermination,
    AuthorityEnvelopeRecord,
    ClosureAssessmentRecord,
    ConformanceDetermination,
    CycleOccurrence,
    DispositionEstablishingRecord,
    EntryStateBoundaryRecord,
    EnvelopeConformanceDetermination,
    GovernanceEventResolution,
    HaltEvent,
    HaltOccurrence,
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
    ResolutionResult,
    RootResolutionRecord,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import ClosedVerdict, M1Edge, M2Position, M3Edge, Machine
from gpauto.governance import ObligationExtinguishingDecision, OwnerDecision
from gpauto.identity import (
    ActivationEffectId,
    AuthorityEnvelopeId,
    FindingId,
    FrozenFindingSetId,
    OwnerAuthorizationId,
    OwnerDecisionId,
    RemediationObligationId,
    RootResolutionId,
    StageOutcomeId,
    WorkerActivationId,
)
from gpauto.repository import ClassificationContext, EntryStateBoundary
from gpauto.review import FrozenFindingSet, RemediationObligation
from gpauto.store import CoordinationStore, UnreadableRecord
from gpauto.vocabulary import Role

TERMINAL_EPOCH_STATES: Final[frozenset[M2Position]] = frozenset(
    {M2Position.S10_EPOCH_SETTLED, M2Position.S11_EPOCH_AUTHORITY_ENDED}
)
"""AP-04 §4.1's two **terminal** M2 states. Everything else is non-terminal — progressing
`S1`…`S7` or waiting `S8`, `S9` — which is AP-05 §6.2 condition 3 for force."""

COMPLETING_EDGES: Final[frozenset[M1Edge]] = frozenset({M1Edge.A2, M1Edge.A3, M1Edge.A4})
"""The M1 edges that complete a resolution and carry its result (`RO7A-2`, `SRF11-1`)."""

DERIVATION_INPUTS: Final[tuple[type[BaseModel], ...]] = (
    RootResolutionRecord,
    EntryStateBoundaryRecord,
    AuthorityEnvelopeRecord,
    WorkerActivationRecord,
    ActivationEffectRecord,
    FrozenFindingSet,
    RemediationObligation,
    ClosureAssessmentRecord,
    HaltOccurrence,
    GovernanceEventResolution,
    CycleOccurrence,
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
    DispositionEstablishingRecord,
    ConformanceDetermination,
    OwnerDecision,
)
"""Every record class a derivation here reads — and no `RC-12`, `RC-15` or `RC-16` class,
which only ST-06's evaluation reads (`DO11-2`)."""


# --- inputs and indeterminacy -------------------------------------------------------


@dataclass(frozen=True)
class AuthoritativeRecords:
    """The authoritative records a derivation ranges over, and nothing derived from them.

    `unreadable` names every class of which at least one stored record could not be
    interpreted. A derivation that needs such a class is indeterminate rather than
    computed over the readable remainder, since the unreadable record might be the one
    that decides it (`RC-4`, `VM-6`).

    `unstable` names every class whose records could not be read as one consistent set:
    the records decoded, but two reads of the store disagreed. It is a different fact
    from `unreadable` — nothing failed to decode — with the same consequence.
    """

    records: tuple[BaseModel, ...]
    unreadable: frozenset[type[BaseModel]] = frozenset()
    unstable: frozenset[type[BaseModel]] = frozenset()


class IndeterminacyCause(StrEnum):
    """The closed set of reasons a derivation cannot be computed (`RC-4`)."""

    UNREADABLE_INPUT = "UNREADABLE_INPUT"
    UNSTABLE_READ = "UNSTABLE_READ"
    MISSING_RECORD = "MISSING_RECORD"
    BROKEN_CHAIN = "BROKEN_CHAIN"
    INCONSISTENT_RECORDS = "INCONSISTENT_RECORDS"


@dataclass(frozen=True)
class Indeterminate:
    """A derivation that could not be computed. Unauthorized; never read as either value."""

    cause: IndeterminacyCause
    detail: str


class _Indeterminacy(Exception):
    """Internal signal for `Indeterminate`, caught only at a derivation's own boundary."""

    def __init__(self, cause: IndeterminacyCause, detail: str) -> None:
        super().__init__(detail)
        self.outcome = Indeterminate(cause, detail)


def read_authoritative_records(store: CoordinationStore) -> AuthoritativeRecords:
    """Every record of every class in `DERIVATION_INPUTS`, read and never written.

    Each class is read in its own read transaction, so the whole read is taken twice and
    kept only if both passes agree: the store is create-only, so a unit committed while
    the first pass ran shows up as a difference in the second. On disagreement no record
    is kept and every class is reported **unstable** — a read-consistency failure, not a
    decoding one. There is no retry here, and whether to read again is not this module's
    to decide (AP-08).
    """
    passes = [_read_pass(store), _read_pass(store)]
    if passes[0] != passes[1]:  # guard:ga_derivation_input
        return AuthoritativeRecords((), unstable=frozenset(DERIVATION_INPUTS))
    return passes[0]


def _read_pass(store: CoordinationStore) -> AuthoritativeRecords:
    found: list[BaseModel] = []
    unreadable: set[type[BaseModel]] = set()
    for kind in DERIVATION_INPUTS:
        for item in store.enumerate(kind):
            if isinstance(item, UnreadableRecord):  # guard:ga_derivation_input
                unreadable.add(kind)
            else:
                found.append(item)
    return AuthoritativeRecords(tuple(found), frozenset(unreadable))


def _of[R: BaseModel](records: AuthoritativeRecords, kind: type[R]) -> tuple[R, ...]:
    """The records of exactly `kind`, or indeterminacy if that class is unreadable or
    was not read as one consistent set."""
    if kind in records.unreadable:  # guard:ga_derivation_input
        raise _Indeterminacy(IndeterminacyCause.UNREADABLE_INPUT, kind.__name__)
    if kind in records.unstable:  # guard:ga_derivation_input
        raise _Indeterminacy(
            IndeterminacyCause.UNSTABLE_READ, f"{kind.__name__}: the two read passes differ"
        )
    return tuple(record for record in records.records if type(record) is kind)


def _one[R](found: list[R], what: str) -> R:
    """The single record `what` names: none is missing, several is inconsistent."""
    if not found:
        raise _Indeterminacy(IndeterminacyCause.MISSING_RECORD, what)
    if len(found) > 1:
        raise _Indeterminacy(IndeterminacyCause.INCONSISTENT_RECORDS, f"more than one {what}")
    return found[0]


# --- DV-6: position, walked by predecessor reference --------------------------------


@dataclass(frozen=True)
class Occupancy[E]:
    """`DV-6`: a subject's chain, first entry to `reached` — the one entry no other entry
    of the chain names as its predecessor. Order is the recorded references' own."""

    machine: Machine
    chain: tuple[E, ...]
    reached: E


@dataclass(frozen=True)
class Unoccupied:
    """`DV-6`: no entry exists for the subject — an affirmative absence, not unknown."""

    machine: Machine


def _walk[E: (M1PositionEntry, M2PositionEntry, M3PositionEntry, M4PositionEntry)](
    subject_entries: tuple[E, ...],
) -> tuple[E, ...]:
    """One subject's entries in chain order, followed by predecessor reference only.

    The chain must have exactly one first entry, must not fork, and must reach every
    entry: anything else is a record set the frozen append-only rule does not produce
    (`PA-04`, `MC-2`), and is indeterminate rather than read by any tie-break.
    """
    if not subject_entries:
        return ()
    firsts = [entry for entry in subject_entries if isinstance(entry.predecessor, KnownAbsent)]
    if len(firsts) != 1:
        raise _Indeterminacy(IndeterminacyCause.BROKEN_CHAIN, f"{len(firsts)} first entries")
    successor: dict[object, E] = {}
    for entry in subject_entries:
        if isinstance(entry.predecessor, Present):
            if entry.predecessor.value in successor:
                raise _Indeterminacy(IndeterminacyCause.BROKEN_CHAIN, "the chain forks")
            successor[entry.predecessor.value] = entry
    walked = [firsts[0]]
    while walked[-1].identity in successor and len(walked) <= len(subject_entries):
        walked.append(successor[walked[-1].identity])
    if len(walked) != len(subject_entries):
        raise _Indeterminacy(IndeterminacyCause.BROKEN_CHAIN, "an entry is unreachable")
    return tuple(walked)


def _m1_chain(
    records: AuthoritativeRecords, resolution: RootResolutionId
) -> tuple[M1PositionEntry, ...]:
    return _walk(
        tuple(
            e
            for e in _of(records, M1PositionEntry)
            if e.identity.resolution == resolution  # guard:ga_derivation_input
        )
    )


def _m2_chain(
    records: AuthoritativeRecords, root: OwnerAuthorizationId
) -> tuple[M2PositionEntry, ...]:
    return _walk(
        tuple(
            e
            for e in _of(records, M2PositionEntry)
            if e.identity.epoch_root == root  # guard:ga_derivation_input
        )
    )


def _m3_chain(
    records: AuthoritativeRecords, envelope: AuthorityEnvelopeId
) -> tuple[M3PositionEntry, ...]:
    return _walk(
        tuple(
            e
            for e in _of(records, M3PositionEntry)
            if e.identity.envelope == envelope  # guard:ga_derivation_input
        )
    )


def _m4_chain(
    records: AuthoritativeRecords, authorization: OwnerAuthorizationId
) -> tuple[M4PositionEntry, ...]:
    return _walk(
        tuple(
            e
            for e in _of(records, M4PositionEntry)
            if e.identity.authorization == authorization  # guard:ga_derivation_input
        )
    )


def derive_m1_position(
    records: AuthoritativeRecords, resolution: RootResolutionId
) -> Occupancy[M1PositionEntry] | Unoccupied | Indeterminate:
    """`DV-6`, M1: the position of one `RootResolution` occurrence."""
    try:
        chain = _m1_chain(records, resolution)
        return Occupancy(Machine.M1, chain, chain[-1]) if chain else Unoccupied(Machine.M1)
    except _Indeterminacy as found:
        return found.outcome


def derive_m2_position(
    records: AuthoritativeRecords, epoch_root: OwnerAuthorizationId
) -> Occupancy[M2PositionEntry] | Unoccupied | Indeterminate:
    """`DV-6`, M2: the position of one epoch, its classification context named by its root."""
    try:
        chain = _m2_chain(records, epoch_root)
        return Occupancy(Machine.M2, chain, chain[-1]) if chain else Unoccupied(Machine.M2)
    except _Indeterminacy as found:
        return found.outcome


def derive_m3_position(
    records: AuthoritativeRecords, envelope: AuthorityEnvelopeId
) -> Occupancy[M3PositionEntry] | Unoccupied | Indeterminate:
    """`DV-6`, M3: the position of one envelope."""
    try:
        chain = _m3_chain(records, envelope)
        return Occupancy(Machine.M3, chain, chain[-1]) if chain else Unoccupied(Machine.M3)
    except _Indeterminacy as found:
        return found.outcome


def derive_m4_position(
    records: AuthoritativeRecords, authorization: OwnerAuthorizationId
) -> Occupancy[M4PositionEntry] | Unoccupied | Indeterminate:
    """`DV-6`, M4: the position of one authorization instance."""
    try:
        chain = _m4_chain(records, authorization)
        return Occupancy(Machine.M4, chain, chain[-1]) if chain else Unoccupied(Machine.M4)
    except _Indeterminacy as found:
        return found.outcome


# --- completion: the C4 entry and the adoption record ---------------------------------


def _completed(records: AuthoritativeRecords, activation: WorkerActivationRecord) -> bool:
    """Whether an activation is completed: its envelope's M3 chain reached `C4`, and its
    `RC-39` adoption record exists — the two authoritative homes of completion
    (`PFC-ST01-1`), created in one unit. One without the other is inconsistent."""
    chain = _m3_chain(records, activation.envelope)
    c4_entries = [entry for entry in chain if entry.edge == M3Edge.C4]
    adoptions = [
        d
        for d in _of(records, ConformanceDetermination)
        if d.identity.activation == activation.identity  # guard:ga_derivation_input
        and isinstance(d.determination, AdoptionDetermination)
    ]
    if len(c4_entries) > 1 or len(adoptions) > 1:
        raise _Indeterminacy(IndeterminacyCause.INCONSISTENT_RECORDS, "completion recorded twice")
    if c4_entries and chain[-1] is not c4_entries[0]:
        raise _Indeterminacy(IndeterminacyCause.INCONSISTENT_RECORDS, "an entry follows C4")
    if bool(c4_entries) != bool(adoptions):
        raise _Indeterminacy(
            IndeterminacyCause.INCONSISTENT_RECORDS, "C4 and the adoption record disagree"
        )
    return bool(c4_entries)


# --- DV-1: the prior authorized state ------------------------------------------------


@dataclass(frozen=True)
class AuthorizedEffects:
    """One completed activation's term: its in-envelope effects (`RS7-10`, `CN-3`)."""

    activation: WorkerActivationId
    effects: frozenset[ActivationEffectRecord]


@dataclass(frozen=True)
class PriorAuthorizedState:
    """`DV-1`: *fixed `EntryStateBoundary` + Σ `ActivationEffect`s of the activations
    completed strictly before the assessed one* (AP-04 §5.3.1), within one classification
    context. The sum is kept as its terms, in stratified order; combining observed states
    is AP-09's, and no term is dropped or merged here."""

    assessed: WorkerActivationId
    context: ClassificationContext
    boundary: EntryStateBoundary
    terms: tuple[AuthorizedEffects, ...]


def _stratum(
    activation: WorkerActivationRecord,
    envelopes: dict[AuthorityEnvelopeId, AuthorityEnvelopeRecord],
    strata: dict[object, int],
) -> int:
    """Where an activation stands in its epoch: the place in the M2 chain of the entry
    its envelope was derived from (`MC-15`) — a walk over references (`RS7-11`)."""
    envelope = envelopes.get(activation.envelope)  # guard:ga_derivation_input
    if envelope is None:
        raise _Indeterminacy(IndeterminacyCause.MISSING_RECORD, "an activation's envelope")
    if envelope.predecessor_entry not in strata:
        raise _Indeterminacy(
            IndeterminacyCause.INCONSISTENT_RECORDS, "an envelope outside its epoch's chain"
        )
    return strata[envelope.predecessor_entry]  # guard:ga_derivation_input


def _authorized_effects(
    records: AuthoritativeRecords, activation: WorkerActivationRecord
) -> AuthorizedEffects:
    """One activation's in-envelope effects, from **every** envelope-conformance
    determination recorded for it (`RS7-10`).

    `RC-39` admits several such records per activation, and a record may name one effect
    more than once, so each effect's judgements are collected as a set, never keyed by
    last write. Agreeing judgements are one judgement. Disagreeing ones make the term —
    and so `DV-1` — indeterminate: no judgement is chosen by position, recency or read
    order, and none carries precedence (`DV-12`, `RC-4`).
    """
    effects = [
        e
        for e in _of(records, ActivationEffectRecord)
        if e.identity.parent_activation == activation.identity  # guard:ga_derivation_input
    ]
    determinations = [
        c.determination
        for c in _of(records, ConformanceDetermination)
        if c.identity.activation == activation.identity  # guard:ga_derivation_input
        and isinstance(c.determination, EnvelopeConformanceDetermination)
    ]
    if not determinations:
        raise _Indeterminacy(
            IndeterminacyCause.MISSING_RECORD, "envelope-conformance determination"
        )
    judged: dict[ActivationEffectId, set[bool]] = {}
    for conformance in determinations:
        for item in conformance.effects:
            judged.setdefault(item.effect, set()).add(item.within_envelope)
    if set(judged) != {effect.identity for effect in effects}:
        raise _Indeterminacy(
            IndeterminacyCause.INCONSISTENT_RECORDS,
            "the conformance determinations and the recorded effects disagree",
        )
    if any(len(judgements) > 1 for judgements in judged.values()):  # guard:ga_derivation_input
        raise _Indeterminacy(
            IndeterminacyCause.INCONSISTENT_RECORDS,
            "conflicting envelope-conformance determinations for one effect",
        )
    return AuthorizedEffects(
        activation.identity,
        frozenset(e for e in effects if judged[e.identity] == {True}),  # guard:ga_derivation_input
    )


def derive_prior_authorized_state(
    records: AuthoritativeRecords, assessed: WorkerActivationId
) -> PriorAuthorizedState | Indeterminate:
    """`DV-1` for the assessed activation; its own effects are never a term (`ST-1`)."""
    try:
        activations = _of(records, WorkerActivationRecord)
        subject = _one(
            [
                a
                for a in activations
                if a.identity == assessed  # guard:ga_derivation_input
            ],
            "assessed activation",
        )
        root = subject.resolved_root
        boundaries = [
            b
            for b in _of(records, EntryStateBoundaryRecord)
            if b.resolved_root == root  # guard:ga_derivation_input
        ]
        boundary = _one(
            boundaries,
            "entry-state boundary",
        ).boundary
        strata: dict[object, int] = {
            entry.identity: place for place, entry in enumerate(_m2_chain(records, root))
        }
        envelopes = {r.envelope.identity: r for r in _of(records, AuthorityEnvelopeRecord)}
        before = _stratum(subject, envelopes, strata)
        terms: dict[int, AuthorizedEffects] = {}
        for other in activations:
            if other.resolved_root != root:  # guard:ga_derivation_input
                continue
            place = _stratum(other, envelopes, strata)
            if not place < before:  # guard:ga_derivation_input
                continue
            if not _completed(records, other):  # guard:ga_derivation_input
                continue
            if place in terms:
                raise _Indeterminacy(
                    IndeterminacyCause.INCONSISTENT_RECORDS,
                    "two completed activations share a step",
                )
            terms[place] = _authorized_effects(records, other)
        return PriorAuthorizedState(
            assessed,
            ClassificationContext(authorization=root, entry_boundary=boundary.identity),
            boundary,
            tuple(terms[place] for place in sorted(terms)),
        )
    except _Indeterminacy as found:
        return found.outcome


# --- DV-2: closure scope --------------------------------------------------------------


@dataclass(frozen=True)
class ClosureScope:
    """`DV-2`: the findings the closure activation's `ClosureAssessment`s name (`SC-1`)."""

    closure_activation: WorkerActivationId
    members: frozenset[FindingId]


def _closure_scope(
    records: AuthoritativeRecords, closure_activation: WorkerActivationId
) -> ClosureScope:
    members: set[FindingId] = set()
    for record in _of(records, ClosureAssessmentRecord):
        assessed = record.assessment.identity
        if assessed.closure_activation == closure_activation:  # guard:ga_derivation_input
            members.add(assessed.assessed_finding)
    return ClosureScope(closure_activation, frozenset(members))


def derive_closure_scope(
    records: AuthoritativeRecords, closure_activation: WorkerActivationId
) -> ClosureScope | Indeterminate:
    """`DV-2`. An empty scope is a scope; nothing is inferred from absence (`SC-5`)."""
    try:
        return _closure_scope(records, closure_activation)
    except _Indeterminacy as found:
        return found.outcome


# --- DV-5: obligation force -----------------------------------------------------------


@dataclass(frozen=True)
class NotEstablished:
    """`DV-5` condition 1 fails: no such obligation was established at the freeze for a
    member of a frozen set. Not in force — and not an obligation to extinguish."""

    obligation: RemediationObligationId


@dataclass(frozen=True)
class ObligationForce:
    """`DV-5` over an established obligation (AP-05 §6.2): in force iff no waiver or
    deferral names it and its epoch is non-terminal. The deciding records are carried."""

    obligation: RemediationObligationId
    in_force: bool
    extinguished_by: frozenset[OwnerDecisionId]
    epoch_terminal: bool


def _obligation_force(
    records: AuthoritativeRecords, obligation: RemediationObligationId
) -> ObligationForce | NotEstablished:
    """AP-05 §6.2's three conditions, exactly.

    (2) is the **existence** of an `OwnerDecision` of kind waiver or deferral naming this
    obligation — every such decision, with no latest-wins, no precedence and no reading of
    `corrects`, which carries none (`SC01-6`). An `OBLIGATION_CHANGE` (O6) decision is a
    different form and extinguishes nothing (`O6C-2`); a decision naming another
    obligation, or none, is not one naming this one.
    """
    recorded = [
        o
        for o in _of(records, RemediationObligation)
        if o.identity == obligation  # guard:ga_derivation_input
    ]
    sets = [
        s
        for s in _of(records, FrozenFindingSet)
        if s.identity == obligation.parent_frozen_set  # guard:ga_derivation_input
    ]
    if not recorded or not sets:
        return NotEstablished(obligation)
    frozen = _one(sets, "frozen finding set")
    if obligation.member_finding not in frozen.members:  # guard:ga_derivation_input
        return NotEstablished(obligation)
    extinguished_by = frozenset(
        decision.identity
        for decision in _of(records, OwnerDecision)
        if isinstance(decision.act, ObligationExtinguishingDecision)  # guard:ga_derivation_input
        and decision.act.obligation == obligation  # guard:ga_derivation_input
    )
    epoch = _m2_chain(records, frozen.resolved_root)
    if not epoch:
        raise _Indeterminacy(IndeterminacyCause.MISSING_RECORD, "the frozen set's epoch")
    terminal = epoch[-1].state in TERMINAL_EPOCH_STATES  # guard:ga_derivation_input
    return ObligationForce(
        obligation, not extinguished_by and not terminal, extinguished_by, terminal
    )


def derive_obligation_force(
    records: AuthoritativeRecords, obligation: RemediationObligationId
) -> ObligationForce | NotEstablished | Indeterminate:
    """`DV-5`: force, computed and never stored (`OB-7`, `AP05-I16`)."""
    try:
        return _obligation_force(records, obligation)
    except _Indeterminacy as found:
        return found.outcome


# --- DV-3: CYCLE_BOUND ----------------------------------------------------------------


@dataclass(frozen=True)
class NoFrozenSet:
    """The epoch has no frozen set — never the same fact as an empty one (`FP-1`)."""

    root: OwnerAuthorizationId


@dataclass(frozen=True)
class CycleBound:
    """`DV-3`: the applicable obligation set minus every member attested closed by a
    completed, adopted closure activation of this epoch (AP-04 amendment §3.3)."""

    root: OwnerAuthorizationId
    frozen_set: FrozenFindingSetId
    applicable: frozenset[RemediationObligationId]
    attested: frozenset[FindingId]
    members: frozenset[RemediationObligationId]


def _cycle_bound(
    records: AuthoritativeRecords, root: OwnerAuthorizationId
) -> CycleBound | NoFrozenSet:
    """The applicable obligation set is the in-force set (`DV-5`, AP-05 `RM-5`): one
    obligation per member (`OP-1`), leaving it only by waiver or deferral (`OP-3`). An
    O6 change leaves it in the set (`O6C-2`). Subtraction is a record-existence test on a
    `CLOSED` verdict (`OP-4`), from this epoch's completed, adopted closure activations."""
    sets = [
        s
        for s in _of(records, FrozenFindingSet)
        if s.resolved_root == root  # guard:ga_derivation_input
    ]
    if not sets:
        return NoFrozenSet(root)
    frozen = _one(sets, "frozen finding set of the epoch")
    applicable: set[RemediationObligationId] = set()
    for obligation in _of(records, RemediationObligation):
        if obligation.identity.parent_frozen_set != frozen.identity:  # guard:ga_derivation_input
            continue
        force = _obligation_force(records, obligation.identity)
        if isinstance(force, ObligationForce) and force.in_force:  # guard:ga_derivation_input
            applicable.add(obligation.identity)
    closers = frozenset(
        a.identity
        for a in _of(records, WorkerActivationRecord)
        if a.resolved_root == root  # guard:ga_derivation_input
        and a.role == Role.BOUNDED_CLOSURE_VERIFIER  # guard:ga_derivation_input
        and _completed(records, a)  # guard:ga_derivation_input
    )
    attested = frozenset(
        r.assessment.identity.assessed_finding
        for r in _of(records, ClosureAssessmentRecord)
        if r.assessment.identity.closure_activation in closers  # guard:ga_derivation_input
        and isinstance(r.verdict, ClosedVerdict)  # guard:ga_derivation_input
    )
    return CycleBound(
        root,
        frozen.identity,
        frozenset(applicable),
        attested,
        frozenset(
            o
            for o in applicable
            if o.member_finding not in attested  # guard:ga_derivation_input
        ),
    )


def derive_cycle_bound(
    records: AuthoritativeRecords, root: OwnerAuthorizationId
) -> CycleBound | NoFrozenSet | Indeterminate:
    """`DV-3` for the epoch governed by `root`: computed, never stored (`OP-9`, `CO-9`)."""
    try:
        return _cycle_bound(records, root)
    except _Indeterminacy as found:
        return found.outcome


# --- DV-4, ST-04's portion: liveness, and eligibility as recorded ----------------------


@dataclass(frozen=True)
class Liveness:
    """`DV-4` liveness: live iff no consumption record, no revocation record and no
    unresolved suspending event exists for the instance (`WP-9`, `AP07-I18`). Each
    establishing fact found is carried; none is chosen over another."""

    authorization: OwnerAuthorizationId
    live: bool
    consumed_by: frozenset[StageOutcomeId]
    revoked_by: frozenset[OwnerDecisionId]
    suspended_by: frozenset[HaltEvent]


def _still_suspending(
    event: HaltEvent, halts: tuple[HaltOccurrence, ...], resolved: frozenset[HaltOccurrenceId]
) -> bool:
    """A suspending event is resolved only through an `RC-32` record naming a halt
    occurrence on it (`WP-9`, `GH-5`). It stays unresolved while it has no halt occurrence,
    or while any of its occurrences is outstanding (`DV-7`) — never resolved by default."""
    occurrences = [h.identity for h in halts if h.event == event]  # guard:ga_derivation_input
    outstanding = [o for o in occurrences if o not in resolved]  # guard:ga_derivation_input
    return not occurrences or bool(outstanding)


def derive_liveness(
    records: AuthoritativeRecords, authorization: OwnerAuthorizationId
) -> Liveness | Indeterminate:
    """`DV-4` liveness of one instance, from `RC-35`, the suspending `RC-30`/`RC-24` events'
    `RC-31` occurrences and their `RC-32` resolutions (`DO11-2`, `RO7A-9`).

    It reads no M1 entry, no `AuthorizationRecord` and no ST-06 output (`DO11-3`), and
    `AuthorityAmbiguity` is never a suspension cause — the stored suspension admits none
    (`SC01-4`, `M4-5`), and no `RC-16` record is read.
    """
    try:
        held = [
            r.disposition
            for r in _of(records, DispositionEstablishingRecord)
            if r.identity.authorization == authorization  # guard:ga_derivation_input
        ]
        halts = _of(records, HaltOccurrence)
        resolved = frozenset(r.halt_occurrence for r in _of(records, GovernanceEventResolution))
        consumed = frozenset(
            d.established_by_outcome for d in held if isinstance(d, ConsumedDisposition)
        )
        revoked = frozenset(
            d.established_by_decision for d in held if isinstance(d, RevokedDisposition)
        )
        suspended = frozenset(
            d.established_by_event
            for d in held
            if isinstance(d, SuspendedDisposition)
            and _still_suspending(  # guard:ga_derivation_input
                d.established_by_event, halts, resolved
            )
        )
        return Liveness(
            authorization, not (consumed or revoked or suspended), consumed, revoked, suspended
        )
    except _Indeterminacy as found:
        return found.outcome


@dataclass(frozen=True)
class OpenResolution:
    """The resolution's M1 chain ends at its `A1` entry: no result exists yet (`SRF11-1`)."""

    resolution: RootResolutionId


@dataclass(frozen=True)
class CompletedResolution:
    """The result **as recorded** on the completing `A2`/`A3`/`A4` entry (`RO7A-2`), read by
    reference and never re-evaluated: ST-06 produced it; this only reads it."""

    resolution: RootResolutionId
    completing_entry: M1PositionEntryId
    edge: M1Edge
    result: ResolutionResult


def derive_recorded_eligibility(
    records: AuthoritativeRecords, resolution: RootResolutionId
) -> OpenResolution | CompletedResolution | Indeterminate:
    """`DV-4` eligibility as recorded, per `RootResolution`, read from its completing M1
    entry followed by predecessor reference (`SRF11-1`, `RO7A-6`(b)). No `RA-00`…`RA-09`
    attribute, candidate, exclusion or binding is evaluated (`DO11-2`)."""
    try:
        occurrences = [
            r
            for r in _of(records, RootResolutionRecord)
            if r.identity == resolution  # guard:ga_derivation_input
        ]
        _one(occurrences, "RC-14 occurrence")
        chain = _m1_chain(records, resolution)
        if not chain:
            raise _Indeterminacy(IndeterminacyCause.MISSING_RECORD, "the resolution's A1 entry")
        completing = [
            entry
            for entry in chain
            if entry.edge in COMPLETING_EDGES  # guard:ga_derivation_input
        ]
        if not completing:
            return OpenResolution(resolution)
        if len(completing) > 1 or chain[-1] is not completing[0]:
            raise _Indeterminacy(
                IndeterminacyCause.INCONSISTENT_RECORDS, "the completing entry is not final"
            )
        entry = completing[0]
        return CompletedResolution(resolution, entry.identity, entry.edge, entry.result)
    except _Indeterminacy as found:
        return found.outcome


# --- DV-7: outstanding halt occurrences -------------------------------------------------


@dataclass(frozen=True)
class OutstandingHalts:
    """`DV-7`: every halt occurrence no `RC-32` names — never a count (`GH-6`, `GE-4`)."""

    occurrences: frozenset[HaltOccurrenceId]


def derive_outstanding_halts(records: AuthoritativeRecords) -> OutstandingHalts | Indeterminate:
    """`DV-7`: resolved occurrences persist as history and are simply not outstanding
    (`GH-7`)."""
    try:
        named = frozenset(r.halt_occurrence for r in _of(records, GovernanceEventResolution))
        return OutstandingHalts(
            frozenset(
                h.identity
                for h in _of(records, HaltOccurrence)
                if h.identity not in named  # guard:ga_derivation_input
            )
        )
    except _Indeterminacy as found:
        return found.outcome


# --- DV-8: the closure-scope series -------------------------------------------------------


@dataclass(frozen=True)
class NoCompletedClosure:
    """The occurrence has no completed, adopted closure activation — an affirmative
    absence, so its place in the series carries no scope (`CO-14`)."""


@dataclass(frozen=True)
class SeriesStep:
    """One cycle occurrence of the series and the `DV-2` scope of its closure activation."""

    cycle_occurrence: CycleOccurrenceId
    closure: ClosureScope | NoCompletedClosure


@dataclass(frozen=True)
class ClosureScopeSeries:
    """`DV-8`: the epoch's closure scopes, walked from the first `RC-33` occurrence by
    predecessor references (`CO-3`). `strictly_decreasing` is the `CO-18` subset test over
    member identities — each later scope a **proper** subset of the one before — never a
    comparison of counts (`SC-10`). It is derived here and recorded nowhere."""

    root: OwnerAuthorizationId
    steps: tuple[SeriesStep, ...]
    strictly_decreasing: bool


def _closing_activation(
    records: AuthoritativeRecords, occurrence: CycleOccurrence
) -> WorkerActivationId | None:
    bound = [
        run.identity
        for run in _of(records, WorkerActivationRecord)
        if isinstance(run.cycle_occurrence, Present)
        and run.cycle_occurrence.value == occurrence.identity  # guard:ga_derivation_input
        and run.role == Role.BOUNDED_CLOSURE_VERIFIER  # guard:ga_derivation_input
        and _completed(records, run)  # guard:ga_derivation_input
    ]
    if len(bound) > 1:
        raise _Indeterminacy(
            IndeterminacyCause.INCONSISTENT_RECORDS, "two completed closures in one occurrence"
        )
    return bound[0] if bound else None


def derive_closure_scope_series(
    records: AuthoritativeRecords, root: OwnerAuthorizationId
) -> ClosureScopeSeries | Indeterminate:
    """`DV-8` for the epoch governed by `root`."""
    try:
        occurrences = [
            c
            for c in _of(records, CycleOccurrence)
            if c.predecessor_entry.epoch_root == root  # guard:ga_derivation_input
        ]
        if not occurrences:
            return ClosureScopeSeries(root, (), True)
        current = _one(
            [c for c in occurrences if isinstance(c.predecessor_closure_activation, KnownAbsent)],
            "first cycle occurrence",
        )
        steps: list[SeriesStep] = []
        while len(steps) < len(occurrences):
            closer = _closing_activation(records, current)
            if closer is None:
                steps.append(SeriesStep(current.identity, NoCompletedClosure()))
                break
            steps.append(SeriesStep(current.identity, _closure_scope(records, closer)))
            following = [
                c
                for c in occurrences
                if isinstance(c.predecessor_closure_activation, Present)
                and c.predecessor_closure_activation.value == closer  # guard:ga_derivation_input
            ]
            if not following:
                break
            current = _one(following, "successor cycle occurrence")
        if len(steps) != len(occurrences):
            raise _Indeterminacy(IndeterminacyCause.BROKEN_CHAIN, "an occurrence is unreachable")
        scopes = [s.closure.members for s in steps if isinstance(s.closure, ClosureScope)]
        return ClosureScopeSeries(
            root,
            tuple(steps),
            all(later < earlier for earlier, later in zip(scopes, scopes[1:], strict=False)),
        )
    except _Indeterminacy as found:
        return found.outcome
