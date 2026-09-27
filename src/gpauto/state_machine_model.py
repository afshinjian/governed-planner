"""The coordination state machines `M1`…`M4` as data: positions, edges, guards, coupling.

Design basis: AP-04 §3.1–§3.2 (`M1`), §4.1–§4.4 (`M2`, `RP-1`…`RP-7`, `HB-3`…`HB-5`),
§5.1–§5.3 (`M3`, `CP-1`…`CP-5`), §6 (`M4`), §7 (`K-1`…`K-10`), §11 (standing guards), §12
(`TM-1`); the AP-04 bounded-cycle amendment §3.1 (`B15`), §3.2 (`CE-0a`…`CE-6`,
`CE-T1`…`CE-T3`), §3.5.6 (`B8`); AP-04 `S10` amendment (`S10A-1`); AP-11 §16 `GP-AUTO-ST-05`,
§4 (`SV11-1`, `SV11-1a`, `SV11-3`, `SV11-12`).

**A transcription, never an authority** (`SV11-1a`). Every edge below carries the frozen
row it transcribes, and every guard condition carries a verbatim fragment of the frozen
text it comes from, so the transcription is checked against the artifacts rather than
trusted. A disagreement is a defect in this data, resolved by correcting the data.

**The one encoding of each concept is imported** (`SRB11-4`). Positions and edge names are
ST-03's `IV11-*` vocabularies and ST-01's `AuthorizationDisposition`; nothing here repeats
them. What this module adds is only what AP-04 fixes and no earlier stage encoded: which
edge leaves which position for which, under which guard.

**Guards are conditions over named facts.** A fact is a closed set of values; `INDETERMINATE`
is always possible and is in no admitted set, so an unevaluable fact fails every guard
that reads it (`P-04`). Where each fact's value comes from is recorded as its *supplier*:
a later stage's evaluation (`GP-AUTO-ST-06` for `RA-*` and envelope derivation, `-07`
observation, `-08` attribution, `-09` the cycle predicate's facts, `-12` execution, `-14`
decision binding), an ST-04 derivation, or the act presenting the edge. ST-05 evaluates
guards over facts; it computes none of those facts itself.

A guard is either a disjunction of conjunctions of conditions (`Conjunctive`), or — for
`B8` and `B15` alone — the amendment's two-tier predicate (`Stratified`). Both are data;
the evaluator is `state_machine.py`'s.

**Standing guards from AP-04 §11** are transcribed onto the edges §11 names, each citing
its §11 row: `V-01`/`V-09` (`M4 = LIVE`) on `B3`…`B8` and `C2`; `V-02`…`V-04`, `V-10` before
each derivation `B3`, `B4`, `B6a`, `B7`; `V-14` as the precondition of every derivation
(`B3`, `B4`, `B6a`, `B7`, `C1`, `C2`); `V-06` before every derivation (`B3`, `B4`, `B6a`,
`B7`, `C1`). Where an edge's own row already states the same fact, it is not stated twice.

**Two amendment clauses bind existing edges.** `C2` refuses an activation whose admitted
obligation set is not `CYCLE_BOUND` (`OP-8`(i)), a fact read against ST-04's `DV-3` and
inapplicable to an envelope without an `E-14` frozen-set reference. `B13` restores the
recorded position **and that recorded cycle occurrence** (`HB-1` as restated), so its guard
reads that the named halt's occurrence binding is determinate and consistent.

Guard identifier fixed on each condition (`MU11-3`): `ga_transition_guard`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from gpauto.coordination_vocabulary import (
    M1Edge,
    M1Position,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
    M4Edge,
    Machine,
)
from gpauto.vocabulary import AuthorizationDisposition, OwnerDecisionKind, StageOutcomeDisposition

# --- truth values and positions ------------------------------------------------------

TRUE: Final = "TRUE"
FALSE: Final = "FALSE"
INDETERMINATE: Final = "INDETERMINATE"
"""The value of any fact that is unavailable, unreadable or outside its domain (`P-04`)."""

BOOLEAN: Final[tuple[str, ...]] = (TRUE, FALSE)
T: Final[tuple[str, ...]] = (TRUE,)
F: Final[tuple[str, ...]] = (FALSE,)


@dataclass(frozen=True)
class Entry:
    """The position of a subject that has no entry yet: what an entry edge (`A1`, `B1`,
    `C1`) leaves. M4 has none — a never-disposed instance is `LIVE` by default (`M4-5`)."""

    machine: Machine


M1_ENTRY: Final = Entry(Machine.M1)
M2_ENTRY: Final = Entry(Machine.M2)
M3_ENTRY: Final = Entry(Machine.M3)

type Position = M1Position | M2Position | M3Position | AuthorizationDisposition | Entry
type EdgeName = M1Edge | M2Edge | M3Edge | M4Edge


@dataclass(frozen=True)
class RestoredPosition:
    """`B13`'s target: the recorded source position of the halt occurrence the resolving
    decision names — never the most recent, never inferred, never chosen (`HB-4`) — and
    that halt's recorded cycle occurrence, never another (`HB-1` as restated)."""


RESTORED: Final = RestoredPosition()

POSITIONS: Final[tuple[tuple[Machine, tuple[Position, ...]], ...]] = (
    (Machine.M1, (M1_ENTRY, *M1Position)),
    (Machine.M2, (M2_ENTRY, *M2Position)),
    (Machine.M3, (M3_ENTRY, *M3Position)),
    (Machine.M4, tuple(AuthorizationDisposition)),
)
"""Every position of every machine — the rows of the conformance matrix."""

TERMINAL: Final[frozenset[Position]] = frozenset(
    {
        M2Position.S10_EPOCH_SETTLED,
        M2Position.S11_EPOCH_AUTHORITY_ENDED,
        M3Position.ENVELOPE_VOIDED,
        M3Position.ACTIVATION_COMPLETED,
        M3Position.ACTIVATION_CLOSED_UNADOPTED,
        AuthorizationDisposition.CONSUMED,
        AuthorizationDisposition.REVOKED,
    }
)
"""`TM-1`, `AP04-I16`: the seven terminal states."""

M1_HALTS: Final[frozenset[Position]] = frozenset(
    {M1Position.ROOT_ABSENT, M1Position.ROOT_CONTESTED}
)
"""`TM-1`, `M1-3`: halts, not terminals — and like terminals, without an outgoing edge."""

PROGRESSING: Final[tuple[M2Position, ...]] = (
    M2Position.S1_EPOCH_OPENED,
    M2Position.S2_ENTRY_BOUNDARY_FIXED,
    M2Position.S3_IMPLEMENTATION_ACTIVE,
    M2Position.S4_DISCOVERY_ACTIVE,
    M2Position.S5_FINDING_SET_FROZEN,
    M2Position.S6_REMEDIATION_ACTIVE,
    M2Position.S7_CLOSURE_ACTIVE,
)
"""AP-04 §4.1: *progressing* = `{S1…S7}`."""

HALTABLE: Final[tuple[M2Position, ...]] = (*PROGRESSING, M2Position.S8_GATE_REACHED)
"""`B9`'s sources: any of `S1…S8` (§4.2, `SH-1`)."""

NON_TERMINAL: Final[tuple[M2Position, ...]] = (*HALTABLE, M2Position.S9_EPOCH_HALTED)
"""*Non-terminal* = progressing ∪ waiting — `B12`'s sources."""

STEP_STATES: Final[frozenset[M2Position]] = frozenset(
    {
        M2Position.S3_IMPLEMENTATION_ACTIVE,
        M2Position.S4_DISCOVERY_ACTIVE,
        M2Position.S6_REMEDIATION_ACTIVE,
        M2Position.S7_CLOSURE_ACTIVE,
    }
)
"""`K-5`: the step states, each with an M3 subject position."""

PREFIX: Final[frozenset[M2Position]] = frozenset(PROGRESSING[:5])
"""`S1`…`S5` — the discovery-and-freeze prefix no suffix edge reaches (`AP04-I42`, `BC-1`)."""

SUFFIX: Final[frozenset[M2Position]] = frozenset(
    {M2Position.S6_REMEDIATION_ACTIVE, M2Position.S7_CLOSURE_ACTIVE, M2Position.S8_GATE_REACHED}
)


# --- facts -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Fact:
    """A named fact a guard reads: its closed value set, and who supplies its value."""

    name: str
    values: tuple[str, ...]
    supplier: str


COORDINATOR: Final = "COORDINATOR"
STAGE_ENTRY_ATTEMPT: Final = "STAGE_ENTRY_ATTEMPT"

TRIGGER = Fact(
    "TRIGGER",
    (COORDINATOR, STAGE_ENTRY_ATTEMPT, *OwnerDecisionKind),
    "the act presenting the edge: the coordinator, a stage-entry attempt, or an OwnerDecision"
    " of the named kind (its binding to this epoch is GP-AUTO-ST-14's)",
)
"""Who or what triggers the edge (§3.2, §4.2, §5.2, §6 *Trigger* columns)."""

# M1 — supplied by root resolution (ST-06); read here, never computed.
ELIGIBLE_MULTIPLICITY = Fact(
    "ELIGIBLE_MULTIPLICITY",
    ("ZERO", "ONE", "MANY"),
    "GP-AUTO-ST-06: distinct eligible live identities after exclusion (V-16, V-17a)",
)
IDENTITY_RECORDS_CONSISTENT = Fact(
    "IDENTITY_RECORDS_CONSISTENT", BOOLEAN, "GP-AUTO-ST-06: V-17b over one identity's records"
)

# M2
M1_ROOT_RESOLVED = Fact(
    "M1_ROOT_RESOLVED", BOOLEAN, "DV-4 recorded eligibility: the completing A2 entry names it"
)
PREFLIGHT_PERMITTED = Fact("PREFLIGHT_PERMITTED", BOOLEAN, "GP-AUTO-ST-06: RA-09")
NO_BOUNDARY_FOR_ROOT = Fact("NO_BOUNDARY_FOR_ROOT", BOOLEAN, "GP-AUTO-ST-07")
OBSERVATION_FIXED = Fact("OBSERVATION_FIXED", BOOLEAN, "GP-AUTO-ST-07")
OBSERVATION_READ_ONLY = Fact("OBSERVATION_READ_ONLY", BOOLEAN, "GP-AUTO-ST-07")
NOT_A_WORKER_ACTIVATION = Fact("NOT_A_WORKER_ACTIVATION", BOOLEAN, "GP-AUTO-ST-07")
M4_LIVE = Fact("M4_LIVE", BOOLEAN, "DV-6 M4 position, agreeing with DV-4 liveness")
BOUNDARY_FIXED = Fact("BOUNDARY_FIXED", BOOLEAN, "GP-AUTO-ST-07: V-14")
ROLE_AUTHORIZED = Fact("ROLE_AUTHORIZED", BOOLEAN, "GP-AUTO-ST-06: role in RA-06")
ENVELOPE_VALID = Fact("ENVELOPE_VALID", BOOLEAN, "GP-AUTO-ST-06: V-11, V-12")
BOUNDS_WITHIN_CEILING = Fact("BOUNDS_WITHIN_CEILING", BOOLEAN, "GP-AUTO-ST-06: EV-3")
DERIVATION_TOTAL = Fact("DERIVATION_TOTAL", BOOLEAN, "GP-AUTO-ST-06: EV-4")
BINDINGS_MATCH = Fact("BINDINGS_MATCH", BOOLEAN, "GP-AUTO-ST-06: V-02, V-03, V-04, V-10")
UNACCOUNTED_MUTATION = Fact("UNACCOUNTED_MUTATION", BOOLEAN, "GP-AUTO-ST-08: V-06")
UNRESOLVED_EVENT = Fact("UNRESOLVED_EVENT", BOOLEAN, "DV-4 liveness: an unresolved suspension")
STEP_ACTIVATION_COMPLETED = Fact(
    "STEP_ACTIVATION_COMPLETED", BOOLEAN, "DV-6 M3: the step's subject at ACTIVATION_COMPLETED"
)
STEP_ENVELOPE_TERMINAL = Fact(
    "STEP_ENVELOPE_TERMINAL", BOOLEAN, "DV-6 M3: the step's envelope in a terminal position"
)
VERDICT_SET_CONSISTENT = Fact("VERDICT_SET_CONSISTENT", BOOLEAN, "GP-AUTO-ST-09")
MEMBERSHIP_EMPTY = Fact("MEMBERSHIP_EMPTY", BOOLEAN, "GP-AUTO-ST-09: the frozen set's members")
E14_REFERENCES_FROZEN_SET = Fact("E14_REFERENCES_FROZEN_SET", BOOLEAN, "GP-AUTO-ST-06")
REMEDIATOR_BOUNDS = Fact("REMEDIATOR_BOUNDS", BOOLEAN, "GP-AUTO-ST-06: N-02, N-04")
FROZEN_SET_UNCHANGED = Fact("FROZEN_SET_UNCHANGED", BOOLEAN, "GP-AUTO-ST-09: V-07")
NEW_ENVELOPE_IDENTITY = Fact("NEW_ENVELOPE_IDENTITY", BOOLEAN, "GP-AUTO-ST-06: V-13")
READ_ONLY_WITHOUT_WRITE_BOUNDARY = Fact(
    "READ_ONLY_WITHOUT_WRITE_BOUNDARY", BOOLEAN, "GP-AUTO-ST-06: E-13 read-only, E-12 absent"
)
E20_DESIGNATES_INPUTS = Fact("E20_DESIGNATES_INPUTS", BOOLEAN, "GP-AUTO-ST-06")
CLOSURE_SCOPE_WITHIN_MEMBERSHIP = Fact("CLOSURE_SCOPE_WITHIN_MEMBERSHIP", BOOLEAN, "GP-AUTO-ST-09")
STAGE_OUTCOME_VALUE = Fact(
    "STAGE_OUTCOME_VALUE", tuple(StageOutcomeDisposition), "GP-AUTO-ST-14: the F-9 outcome"
)
AUTHORIZATION_WITHDRAWN = Fact("AUTHORIZATION_WITHDRAWN", BOOLEAN, "GP-AUTO-ST-14: V-09")
BINDINGS_CEASED_TO_MATCH = Fact(
    "BINDINGS_CEASED_TO_MATCH", BOOLEAN, "GP-AUTO-ST-06 / GP-AUTO-ST-14: V-03"
)
DECISION_NAMES_OUTSTANDING_OCCURRENCE = Fact(
    "DECISION_NAMES_OUTSTANDING_OCCURRENCE",
    BOOLEAN,
    "DV-7 outstanding occurrences, on the root's DV-4 suspending events (HB-3)",
)
SINGLE_OUTSTANDING_OCCURRENCE = Fact(
    "SINGLE_OUTSTANDING_OCCURRENCE", BOOLEAN, "DV-7, as above (HB-5)"
)
RESTORED_POSITION = Fact(
    "RESTORED_POSITION", tuple(M2Position), "the named RC-31 occurrence's source_state (HB-4)"
)
RESTORED_OCCURRENCE_BOUND = Fact(
    "RESTORED_OCCURRENCE_BOUND",
    BOOLEAN,
    "the named RC-31 occurrence's cycle_occurrence: present exactly at S6/S7, naming an RC-33"
    " occurrence of this epoch (HB-1 as restated, GH-3)",
)

# The amendment's stratified cycle predicate — every fact is GP-AUTO-ST-09's (AP-11 §16).
CE_0A = Fact("CE_0A_CLOSURE_COMPLETED_ADOPTED", BOOLEAN, "GP-AUTO-ST-09")
CE_0B = Fact("CE_0B_AUTHORIZATION_AND_BOUNDARY_VALID", BOOLEAN, "GP-AUTO-ST-09")
CE_0C = Fact("CE_0C_NO_EVENT_NO_UNACCOUNTED_MUTATION", BOOLEAN, "GP-AUTO-ST-09")
CE_0D = Fact("CE_0D_FROZEN_SET_UNCHANGED_NO_NEW_FINDING", BOOLEAN, "GP-AUTO-ST-09")
CE_1 = Fact("CE_1_SCOPE_NONEMPTY_WITHIN_MEMBERSHIP", BOOLEAN, "GP-AUTO-ST-09: DV-2")
CE_2 = Fact("CE_2_SOME_MEMBER_NOT_ATTESTED", BOOLEAN, "GP-AUTO-ST-09")
CE_3 = Fact("CE_3_SOME_MEMBER_ATTESTED", BOOLEAN, "GP-AUTO-ST-09")
CE_4 = Fact("CE_4_SCOPE_EQUALS_APPLICABLE_SET", BOOLEAN, "GP-AUTO-ST-09")
CE_5 = Fact("CE_5_NEXT_CYCLE_BOUND_NONEMPTY", BOOLEAN, "GP-AUTO-ST-09: DV-3")
CE_6 = Fact("CE_6_BUDGET_AVAILABLE_NOT_EXHAUSTED", BOOLEAN, "GP-AUTO-ST-09: AP-08 budget")

# The resumption predicate — one set of facts for B13 and G6 (K-9).
RP_1 = Fact("RP_1_NO_UNACCOUNTED_MUTATION_IN_CONTEXT", BOOLEAN, "GP-AUTO-ST-08")
RP_2 = Fact("RP_2_NO_ENVELOPE_VIOLATION_IN_EPOCH", BOOLEAN, "GP-AUTO-ST-08")
RP_3 = Fact("RP_3_CAUSE_IS_CASE_A_REFUSAL", BOOLEAN, "GP-AUTO-ST-08")
RP_4 = Fact("RP_4_BOUNDARY_FIXED_AVAILABLE_UNMOVED", BOOLEAN, "GP-AUTO-ST-07")
RP_5 = Fact("RP_5_BINDINGS_MATCH_NOT_CONSUMED_REVOKED", BOOLEAN, "GP-AUTO-ST-06")
RP_6 = Fact("RP_6_NO_OTHER_UNRESOLVED_EVENT", BOOLEAN, "GP-AUTO-ST-14")
RP_7 = Fact("RP_7_NOT_A_ROUTE_AROUND_A_SUBSTANTIVE_REFUSAL", BOOLEAN, "GP-AUTO-ST-14")

# M3
NAMES_ROOT_INSTANCE = Fact("NAMES_ROOT_INSTANCE", BOOLEAN, "GP-AUTO-ST-06: E-02")
ROLE_MATCHES_ENVELOPE = Fact("ROLE_MATCHES_ENVELOPE", BOOLEAN, "GP-AUTO-ST-12: V-05")
EQUAL: Final = "EQUAL"
UNEQUAL: Final = "UNEQUAL"
NOT_APPLICABLE: Final = "NOT_APPLICABLE"
ADMITTED_OBLIGATIONS_AGREE = Fact(
    "ADMITTED_OBLIGATIONS_AGREE",
    (EQUAL, UNEQUAL, NOT_APPLICABLE),
    "DV-3 CYCLE_BOUND against the dispatch's admitted obligation set (OP-8); NOT_APPLICABLE"
    " where the recorded envelope carries no E-14 frozen-set reference",
)
ENVELOPE_NEVER_ACTIVATED = Fact(
    "ENVELOPE_NEVER_ACTIVATED", BOOLEAN, "DV-6 M3: the envelope still at ENVELOPE_DERIVED"
)
M2_IN_MATCHING_STEP = Fact("M2_IN_MATCHING_STEP", BOOLEAN, "DV-6 M2")
PRIOR_ACTIVATION_AT_POSITION = Fact(
    "PRIOR_ACTIVATION_AT_POSITION",
    ("NONE", "CLOSED_AND_QUIESCENT", "NOT_GOVERNANCE_CLOSED", "CLOSED_NOT_QUIESCENT"),
    "GP-AUTO-ST-12: governance closure (DV-6 M3) and observed quiescence (PQ-2)",
)
PRE_DISPATCH_GUARD_FAILED = Fact("PRE_DISPATCH_GUARD_FAILED", BOOLEAN, "GP-AUTO-ST-06")
USED_OUTSIDE_BOUND_STAGE = Fact("USED_OUTSIDE_BOUND_STAGE", BOOLEAN, "GP-AUTO-ST-06: V-10")
EPOCH_HALTED = Fact("EPOCH_HALTED", BOOLEAN, "DV-6 M2: the epoch at S9")
CP_1 = Fact("CP_1_VALID_AT_DISPATCH_NOT_PREVIOUSLY_ACTIVATED", BOOLEAN, "GP-AUTO-ST-12")
CP_2 = Fact("CP_2_RUN_TERMINATED", BOOLEAN, "GP-AUTO-ST-12")
CP_3 = Fact("CP_3_STRUCTURALLY_CONFORMANT", BOOLEAN, "GP-AUTO-ST-10")
CP_4 = Fact("CP_4_NO_VIOLATION_OR_MUTATION_ATTRIBUTED", BOOLEAN, "GP-AUTO-ST-08")
CP_5 = Fact("CP_5_OUTCOME_ADOPTED", BOOLEAN, "GP-AUTO-ST-10")


# --- citations, conditions, guards ------------------------------------------------------

AP04: Final = "AP-04"
CYCLE: Final = "AP-04-CYCLE-AMENDMENT"


@dataclass(frozen=True)
class Row:
    """A frozen table row, found by the text its line begins with once `*` and backticks
    are removed (the checking tests do the normalizing)."""

    artifact: str
    prefix: str


@dataclass(frozen=True)
class Condition:
    """One guard condition: the fact it reads, the values that satisfy it, and the
    verbatim frozen fragment it transcribes from `row`."""

    identifier: str
    fact: Fact
    admitted: tuple[str, ...]
    row: Row
    quote: str


@dataclass(frozen=True)
class Conjunctive:
    """Admissible iff every condition of at least one alternative is satisfied."""

    alternatives: tuple[tuple[Condition, ...], ...]


@dataclass(frozen=True)
class Stratified:
    """The amendment's two-tier predicate (§3.2, `CE-T1`…`CE-T3`). Tier 0 first; Tier 1
    only on a determinate Tier-0 pass; `tier1_holds` is the Tier-1 value this edge takes —
    `True` for `B15`, `False` for `B8` — and an indeterminate Tier 1 admits neither."""

    own: tuple[Condition, ...]
    tier0: tuple[Condition, ...]
    tier1: tuple[Condition, ...]
    tier1_holds: bool


type Guard = Conjunctive | Stratified


@dataclass(frozen=True)
class EdgeRule:
    """One frozen edge: its machine, the positions it leaves, its target, its guard, and
    the frozen row whose *From → To* cell it transcribes."""

    edge: EdgeName
    machine: Machine
    sources: tuple[Position, ...]
    target: Position | RestoredPosition
    guard: Guard
    row: Row


# Rows ---------------------------------------------------------------------------------

A1_ROW = Row(AP04, "| A1 |")
A2_ROW = Row(AP04, "| A2 |")
A3_ROW = Row(AP04, "| A3 |")
A4_ROW = Row(AP04, "| A4 |")
B1_ROW = Row(AP04, "| B1 |")
B2_ROW = Row(AP04, "| B2 |")
B3_ROW = Row(AP04, "| B3 |")
B4_ROW = Row(AP04, "| B4 |")
B5_ROW = Row(AP04, "| B5 |")
B6A_ROW = Row(AP04, "| B6a |")
B6B_ROW = Row(AP04, "| B6b |")
B7_ROW = Row(AP04, "| B7 |")
B8_ROW = Row(CYCLE, "| B8 |")
B9_ROW = Row(AP04, "| B9 |")
B10_ROW = Row(AP04, "| B10 |")
B11_ROW = Row(AP04, "| B11 |")
B12_ROW = Row(AP04, "| B12 |")
B13_ROW = Row(AP04, "| B13 |")
B15_ROW = Row(CYCLE, "| B15 |")
C1_ROW = Row(AP04, "| C1 |")
C2_ROW = Row(AP04, "| C2 |")
C3_ROW = Row(AP04, "| C3 |")
C4_ROW = Row(AP04, "| C4 |")
C5_ROW = Row(AP04, "| C5 |")
C6_ROW = Row(AP04, "| C6 |")
G1_ROW = Row(AP04, "| G1 |")
G2_ROW = Row(AP04, "| G2 |")
G3_ROW = Row(AP04, "| G3 |")
G4_ROW = Row(AP04, "| G4 |")
G5_ROW = Row(AP04, "| G5 |")
G6_ROW = Row(AP04, "| G6 |")
HB3_ROW = Row(AP04, "| HB-3 |")
HB4_ROW = Row(AP04, "| HB-4 |")
HB5_ROW = Row(AP04, "| HB-5 |")
HB1_RESTATED_ROW = Row(CYCLE, "> The current occurrence is never inferred")
OP8_ROW = Row(CYCLE, "| OP-8 |")
V01_ROW = Row(AP04, "| V-01 consumed / V-09 revoked |")
V02_ROW = Row(AP04, "| V-02 baseline / V-03 contract / V-04 stage")
V06_ROW = Row(AP04, "| V-06 unaccounted mutation |")
V14_ROW = Row(AP04, "| V-14 entry boundary not fixed / unavailable |")

# Conditions shared by name across edges ------------------------------------------------
#
# A condition is shared only where the frozen text states one condition for several
# edges: the amendment's CE-* for B8 and B15, RP-* for B13 and G6, CP-* for C4.

_C = Condition

CE_0A_C = _C("CE-0a", CE_0A, T, Row(CYCLE, "| CE-0a |"), "and its outcome adopted")
CE_0B_C = _C(  # guard:ga_transition_guard
    "CE-0b",
    CE_0B,
    T,
    Row(CYCLE, "| CE-0b |"),
    "M4 = LIVE; the EntryStateBoundary is fixed, available and unmoved",
)
CE_0C_C = _C(  # guard:ga_transition_guard
    "CE-0c",
    CE_0C,
    T,
    Row(CYCLE, "| CE-0c |"),
    "No unresolved governance event under this root (V-08)",
)
CE_0D_C = _C(  # guard:ga_transition_guard
    "CE-0d",
    CE_0D,
    T,
    Row(CYCLE, "| CE-0d |"),
    "The frozen set is unchanged since the freeze (V-07)",
)
CE_1_C = _C("CE-1", CE_1, T, Row(CYCLE, "| CE-1 |"), "derived closure scope is non-empty")
CE_2_C = _C("CE-2", CE_2, T, Row(CYCLE, "| CE-2 |"), "does not attest closure")
CE_3_C = _C("CE-3", CE_3, T, Row(CYCLE, "| CE-3 |"), "that does attest closure")
CE_4_C = _C(  # guard:ga_transition_guard
    "CE-4",
    CE_4,
    T,
    Row(CYCLE, "| CE-4 |"),
    "The closure scope equals the applicable obligation set",
)
CE_5_C = _C("CE-5", CE_5, T, Row(CYCLE, "| CE-5 |"), "is non-empty")
CE_6_C = _C("CE-6", CE_6, T, Row(CYCLE, "| CE-6 |"), "is available and not exhausted")

TIER_0: Final = (CE_0A_C, CE_0B_C, CE_0C_C, CE_0D_C)
TIER_1: Final = (CE_1_C, CE_2_C, CE_3_C, CE_4_C, CE_5_C, CE_6_C)

RP_1_C = _C(  # guard:ga_transition_guard
    "RP-1",
    RP_1,
    T,
    Row(AP04, "| RP-1 |"),
    "No UnaccountedMutation exists in this classification context",
)
RP_2_C = _C(  # guard:ga_transition_guard
    "RP-2", RP_2, T, Row(AP04, "| RP-2 |"), "No EnvelopeViolation is recorded in this epoch"
)
RP_3_C = _C(  # guard:ga_transition_guard
    "RP-3", RP_3, T, Row(AP04, "| RP-3 |"), "The halt's cause is a Case A Refusal and nothing else"
)
RP_4_C = _C(  # guard:ga_transition_guard
    "RP-4", RP_4, T, Row(AP04, "| RP-4 |"), "The EntryStateBoundary is fixed, available and unmoved"
)
RP_5_C = _C(  # guard:ga_transition_guard
    "RP-5", RP_5, T, Row(AP04, "| RP-5 |"), "The governing authorization's bindings still match"
)
RP_6_C = _C(  # guard:ga_transition_guard
    "RP-6",
    RP_6,
    T,
    Row(AP04, "| RP-6 |"),
    "No other unresolved governance event exists in the epoch",
)
RP_7_C = _C(  # guard:ga_transition_guard
    "RP-7",
    RP_7,
    T,
    Row(AP04, "| RP-7 |"),
    "Resumption is never a route to obtain what a substantive refusal denied",
)

RESUMPTION_PREDICATE: Final = (RP_1_C, RP_2_C, RP_3_C, RP_4_C, RP_5_C, RP_6_C, RP_7_C)
"""`RP-1`…`RP-7`, evaluated once for `B13` and `G6` together (§4.4, `K-9`)."""

CP_1_C = _C(  # guard:ga_transition_guard
    "CP-1", CP_1, T, Row(AP04, "| CP-1 |"), "whose identity had not previously been activated"
)
CP_2_C = _C("CP-2", CP_2, T, Row(AP04, "| CP-2 |"), "The worker run has terminated")
CP_3_C = _C(  # guard:ga_transition_guard
    "CP-3",
    CP_3,
    T,
    Row(AP04, "| CP-3 |"),
    "Its outcome passed the coordinator's structural conformance validation",
)
CP_4_C = _C(  # guard:ga_transition_guard
    "CP-4", CP_4, T, Row(AP04, "| CP-4 |"), "No EnvelopeViolation is attributed to this activation"
)
CP_5_C = _C("CP-5", CP_5, T, Row(AP04, "| CP-5 |"), "The coordinator has adopted the outcome")

OWNER_STAGE_OUTCOME: Final = (OwnerDecisionKind.STAGE_OUTCOME.value,)
OWNER_REVOCATION: Final = (OwnerDecisionKind.REVOCATION.value,)
OWNER_REFUSAL_RESOLUTION: Final = (OwnerDecisionKind.REFUSAL_RESOLUTION.value,)
OWNER_REBINDING: Final = (
    OwnerDecisionKind.SCOPE_CHANGE.value,
    OwnerDecisionKind.AUTHORITY_EXPANSION.value,
)
BY_COORDINATOR: Final = (COORDINATOR,)

# M1 ------------------------------------------------------------------------------------

A4_T = _C("A4-T", TRIGGER, BY_COORDINATOR, A4_ROW, "coordinator, structurally")

M1_EDGES: Final[tuple[EdgeRule, ...]] = (
    EdgeRule(  # guard:ga_transition_guard
        M1Edge.A1,
        Machine.M1,
        (M1_ENTRY,),
        M1Position.RESOLUTION_OPEN,
        Conjunctive(
            (
                (
                    _C(
                        "A1-T",
                        TRIGGER,
                        (STAGE_ENTRY_ATTEMPT,),
                        A1_ROW,
                        "stage-entry attempt naming (Project, GovernedStage)",
                    ),
                ),
            )
        ),
        A1_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M1Edge.A2,
        Machine.M1,
        (M1Position.RESOLUTION_OPEN,),
        M1Position.ROOT_RESOLVED,
        Conjunctive(
            (
                (
                    _C("A2-T", TRIGGER, BY_COORDINATOR, A2_ROW, "coordinator, structurally"),
                    _C(
                        "A2-1",
                        ELIGIBLE_MULTIPLICITY,
                        ("ONE",),
                        A2_ROW,
                        "exactly one eligible live instance remains after exclusion",
                    ),
                    _C(
                        "A2-2",
                        IDENTITY_RECORDS_CONSISTENT,
                        T,
                        A2_ROW,
                        "consistent across all visible records of its identity",
                    ),
                ),
            )
        ),
        A2_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M1Edge.A3,
        Machine.M1,
        (M1Position.RESOLUTION_OPEN,),
        M1Position.ROOT_ABSENT,
        Conjunctive(
            (
                (
                    _C("A3-T", TRIGGER, BY_COORDINATOR, A3_ROW, "coordinator, structurally"),
                    _C("A3-1", ELIGIBLE_MULTIPLICITY, ("ZERO",), A3_ROW, "zero eligible remain"),
                ),
            )
        ),
        A3_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M1Edge.A4,
        Machine.M1,
        (M1Position.RESOLUTION_OPEN,),
        M1Position.ROOT_CONTESTED,
        Conjunctive(
            (
                (
                    A4_T,
                    _C(
                        "A4-1",
                        ELIGIBLE_MULTIPLICITY,
                        ("MANY",),
                        A4_ROW,
                        "more than one distinct eligible remain",
                    ),
                ),
                (
                    A4_T,
                    _C(
                        "A4-2",
                        ELIGIBLE_MULTIPLICITY,
                        ("ONE",),
                        A4_ROW,
                        "one identity's records conflict",
                    ),
                    _C(
                        "A4-3",
                        IDENTITY_RECORDS_CONSISTENT,
                        F,
                        A4_ROW,
                        "one identity's records conflict",
                    ),
                ),
            )
        ),
        A4_ROW,
    ),
)

# M2 ------------------------------------------------------------------------------------

B12_WITHDRAWN = _C(  # guard:ga_transition_guard
    "B12-1", AUTHORIZATION_WITHDRAWN, T, B12_ROW, "the prior authorization is withdrawn (V-09)"
)

M2_EDGES: Final[tuple[EdgeRule, ...]] = (
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B1,
        Machine.M2,
        (M2_ENTRY,),
        M2Position.S1_EPOCH_OPENED,
        Conjunctive(
            (
                (
                    _C("B1-T", TRIGGER, BY_COORDINATOR, B1_ROW, "coordinator, structurally"),
                    _C(
                        "B1-1",
                        M1_ROOT_RESOLVED,
                        T,
                        B1_ROW,
                        "exactly one eligible live root resolved",
                    ),
                ),
            )
        ),
        B1_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B2,
        Machine.M2,
        (M2Position.S1_EPOCH_OPENED,),
        M2Position.S2_ENTRY_BOUNDARY_FIXED,
        Conjunctive(
            (
                (
                    _C(
                        "B2-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        B2_ROW,
                        "coordinator performs the bounded read-only entry-state observation",
                    ),
                    _C("B2-0", PREFLIGHT_PERMITTED, T, B2_ROW, "permitted by RA-09"),
                    _C("B2-1", NO_BOUNDARY_FOR_ROOT, T, B2_ROW, "no boundary exists for this root"),
                    _C(
                        "B2-2",
                        OBSERVATION_FIXED,
                        T,
                        B2_ROW,
                        "the observation completed and was fixed",
                    ),
                    _C(
                        "B2-3", OBSERVATION_READ_ONLY, T, B2_ROW, "it is read-only and non-mutating"
                    ),
                    _C("B2-4", NOT_A_WORKER_ACTIVATION, T, B2_ROW, "it is not a worker activation"),
                ),
            )
        ),
        B2_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B3,
        Machine.M2,
        (M2Position.S2_ENTRY_BOUNDARY_FIXED,),
        M2Position.S3_IMPLEMENTATION_ACTIVE,
        Conjunctive(
            (
                (
                    _C(
                        "B3-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        B3_ROW,
                        "coordinator derives and dispatches the IMPLEMENTER envelope",
                    ),
                    _C("B3-1", M4_LIVE, T, B3_ROW, "M4 = LIVE"),
                    _C("B3-2", BOUNDARY_FIXED, T, B3_ROW, "boundary fixed (V-14)"),
                    _C("B3-3", ROLE_AUTHORIZED, T, B3_ROW, "role ∈ RA-06"),
                    _C("B3-4", ENVELOPE_VALID, T, B3_ROW, "envelope valid (V-11, V-12)"),
                    _C("B3-5", BOUNDS_WITHIN_CEILING, T, B3_ROW, "bounds ≤ ceiling (EV-3)"),
                    _C(
                        "B3-6",
                        DERIVATION_TOTAL,
                        T,
                        B3_ROW,
                        "derivation total with no free parameters (EV-4)",
                    ),
                    _C("B3-7", BINDINGS_MATCH, T, B3_ROW, "bindings still match (V-02…V-04, V-10)"),
                    _C("B3-8", UNACCOUNTED_MUTATION, F, V06_ROW, "before every derivation"),
                ),
            )
        ),
        B3_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B4,
        Machine.M2,
        (M2Position.S3_IMPLEMENTATION_ACTIVE,),
        M2Position.S4_DISCOVERY_ACTIVE,
        Conjunctive(
            (
                (
                    _C(
                        "B4-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        B4_ROW,
                        "coordinator derives and dispatches the DISCOVERY REVIEWER envelope",
                    ),
                    _C(
                        "B4-C",
                        STEP_ACTIVATION_COMPLETED,
                        T,
                        B4_ROW,
                        "IMPLEMENTER activation completed",
                    ),
                    _C("B4-1", M4_LIVE, T, B3_ROW, "M4 = LIVE"),
                    _C("B4-2", BOUNDARY_FIXED, T, B3_ROW, "boundary fixed (V-14)"),
                    _C("B4-3", ROLE_AUTHORIZED, T, B3_ROW, "role ∈ RA-06"),
                    _C("B4-4", ENVELOPE_VALID, T, B3_ROW, "envelope valid (V-11, V-12)"),
                    _C("B4-5", BOUNDS_WITHIN_CEILING, T, B3_ROW, "bounds ≤ ceiling (EV-3)"),
                    _C(
                        "B4-6",
                        DERIVATION_TOTAL,
                        T,
                        B3_ROW,
                        "derivation total with no free parameters (EV-4)",
                    ),
                    _C("B4-7", BINDINGS_MATCH, T, B3_ROW, "bindings still match (V-02…V-04, V-10)"),
                    _C(
                        "B4-8",
                        STEP_ENVELOPE_TERMINAL,
                        T,
                        B4_ROW,
                        "the implementer envelope is terminal in M3",
                    ),
                    _C(
                        "B4-9", UNRESOLVED_EVENT, F, B4_ROW, "no unresolved governance event (V-08)"
                    ),
                    _C("B4-10", UNACCOUNTED_MUTATION, F, B4_ROW, "no unaccounted mutation (V-06)"),
                ),
            )
        ),
        B4_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B5,
        Machine.M2,
        (M2Position.S4_DISCOVERY_ACTIVE,),
        M2Position.S5_FINDING_SET_FROZEN,
        Conjunctive(
            (
                (
                    _C(
                        "B5-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        B5_ROW,
                        "then the coordinator's structural freeze of the discovery outcome",
                    ),
                    _C(
                        "B5-C",
                        STEP_ACTIVATION_COMPLETED,
                        T,
                        B5_ROW,
                        "DISCOVERY REVIEWER activation completed",
                    ),
                    _C("B5-1", M4_LIVE, T, B3_ROW, "M4 = LIVE"),
                    _C("B5-2", BOUNDARY_FIXED, T, B3_ROW, "boundary fixed (V-14)"),
                    _C("B5-3", ROLE_AUTHORIZED, T, B3_ROW, "role ∈ RA-06"),
                    _C("B5-4", ENVELOPE_VALID, T, B3_ROW, "envelope valid (V-11, V-12)"),
                    _C("B5-5", BOUNDS_WITHIN_CEILING, T, B3_ROW, "bounds ≤ ceiling (EV-3)"),
                    _C(
                        "B5-6",
                        DERIVATION_TOTAL,
                        T,
                        B3_ROW,
                        "derivation total with no free parameters (EV-4)",
                    ),
                    _C("B5-7", BINDINGS_MATCH, T, B3_ROW, "bindings still match (V-02…V-04, V-10)"),
                    _C(
                        "B5-8",
                        STEP_ENVELOPE_TERMINAL,
                        T,
                        B4_ROW,
                        "the implementer envelope is terminal in M3",
                    ),
                    _C(
                        "B5-9", UNRESOLVED_EVENT, F, B4_ROW, "no unresolved governance event (V-08)"
                    ),
                    _C("B5-10", UNACCOUNTED_MUTATION, F, B4_ROW, "no unaccounted mutation (V-06)"),
                    _C(
                        "B5-11",
                        VERDICT_SET_CONSISTENT,
                        T,
                        B5_ROW,
                        "verdict and finding set are internally consistent",
                    ),
                ),
            )
        ),
        B5_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B6a,
        Machine.M2,
        (M2Position.S5_FINDING_SET_FROZEN,),
        M2Position.S6_REMEDIATION_ACTIVE,
        Conjunctive(
            (
                (
                    _C(
                        "B6a-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        B6A_ROW,
                        "coordinator derives and dispatches the REMEDIATOR envelope",
                    ),
                    _C(
                        "B6a-1",
                        MEMBERSHIP_EMPTY,
                        F,
                        B6A_ROW,
                        "membership of the frozen set is non-empty",
                    ),
                    _C("B6a-2", E14_REFERENCES_FROZEN_SET, T, B6A_ROW, "E-14 references that set"),
                    _C(
                        "B6a-3",
                        REMEDIATOR_BOUNDS,
                        T,
                        B6A_ROW,
                        "bounds = stage write boundary ∩ frozen obligation (N-02, N-04)",
                    ),
                    _C(
                        "B6a-4",
                        FROZEN_SET_UNCHANGED,
                        T,
                        B6A_ROW,
                        "frozen set unchanged since freeze (V-07)",
                    ),
                    _C("B6a-5", M4_LIVE, T, V01_ROW, "standing guard on B3…B8 and C2"),
                    _C("B6a-6", BOUNDARY_FIXED, T, V14_ROW, "precondition of every derivation"),
                    _C(
                        "B6a-7",
                        BINDINGS_MATCH,
                        T,
                        V02_ROW,
                        "re-evaluated as a guard before each derivation (B3, B4, B6a, B7)",
                    ),
                    _C("B6a-8", UNACCOUNTED_MUTATION, F, V06_ROW, "before every derivation"),
                ),
            )
        ),
        B6A_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B6b,
        Machine.M2,
        (M2Position.S5_FINDING_SET_FROZEN,),
        M2Position.S8_GATE_REACHED,
        Conjunctive(
            (
                (
                    _C("B6b-T", TRIGGER, BY_COORDINATOR, B6B_ROW, "coordinator, structurally"),
                    _C(
                        "B6b-1",
                        MEMBERSHIP_EMPTY,
                        T,
                        B6B_ROW,
                        "membership of the frozen set is empty",
                    ),
                    _C("B6b-2", M4_LIVE, T, V01_ROW, "standing guard on B3…B8 and C2"),
                ),
            )
        ),
        B6B_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B7,
        Machine.M2,
        (M2Position.S6_REMEDIATION_ACTIVE,),
        M2Position.S7_CLOSURE_ACTIVE,
        Conjunctive(
            (
                (
                    _C(
                        "B7-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        B7_ROW,
                        "coordinator derives and dispatches the BOUNDED CLOSURE VERIFIER envelope",
                    ),
                    _C(
                        "B7-C",
                        STEP_ACTIVATION_COMPLETED,
                        T,
                        B7_ROW,
                        "REMEDIATOR activation completed",
                    ),
                    _C("B7-1", M4_LIVE, T, B7_ROW, "M4 = LIVE"),
                    _C("B7-2", BOUNDARY_FIXED, T, B7_ROW, "boundary fixed (V-14)"),
                    _C(
                        "B7-3",
                        ROLE_AUTHORIZED,
                        T,
                        B7_ROW,
                        "role = BOUNDED CLOSURE VERIFIER ∈ RA-06",
                    ),
                    _C("B7-4", ENVELOPE_VALID, T, B7_ROW, "envelope valid (V-11, V-12)"),
                    _C(
                        "B7-5", NEW_ENVELOPE_IDENTITY, T, B7_ROW, "derived as a new identity (V-13)"
                    ),
                    _C("B7-6", BOUNDS_WITHIN_CEILING, T, B7_ROW, "bounds ≤ ceiling (EV-3)"),
                    _C("B7-7", DERIVATION_TOTAL, T, B7_ROW, "derivation total (EV-4)"),
                    _C("B7-8", BINDINGS_MATCH, T, B7_ROW, "bindings still match (V-02…V-04, V-10)"),
                    _C(
                        "B7-9", UNRESOLVED_EVENT, F, B7_ROW, "no unresolved governance event (V-08)"
                    ),
                    _C("B7-10", UNACCOUNTED_MUTATION, F, B7_ROW, "no unaccounted mutation (V-06)"),
                    _C(
                        "B7-11",
                        READ_ONLY_WITHOUT_WRITE_BOUNDARY,
                        T,
                        B7_ROW,
                        "write mode read-only, with E-12 write boundary absent",
                    ),
                    _C(
                        "B7-12",
                        E14_REFERENCES_FROZEN_SET,
                        T,
                        B7_ROW,
                        "E-14 references the frozen set",
                    ),
                    _C(
                        "B7-13",
                        E20_DESIGNATES_INPUTS,
                        T,
                        B7_ROW,
                        "E-20 designates its authoritative inputs",
                    ),
                    _C(
                        "B7-14",
                        FROZEN_SET_UNCHANGED,
                        T,
                        B7_ROW,
                        "frozen set unchanged since freeze (V-07)",
                    ),
                    _C(
                        "B7-15",
                        CLOSURE_SCOPE_WITHIN_MEMBERSHIP,
                        T,
                        B7_ROW,
                        "closure scope ⊆ frozen-set membership",
                    ),
                ),
            )
        ),
        B7_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B8,
        Machine.M2,
        (M2Position.S7_CLOSURE_ACTIVE,),
        M2Position.S8_GATE_REACHED,
        Stratified(
            own=(
                _C(
                    "B8-T",
                    TRIGGER,
                    BY_COORDINATOR,
                    B8_ROW,
                    "BOUNDED CLOSURE VERIFIER activation completed",
                ),
                _C(
                    "B8-1",
                    CLOSURE_SCOPE_WITHIN_MEMBERSHIP,
                    T,
                    B8_ROW,
                    "closure assessed per member over a scope ⊆ membership",
                ),
            ),
            tier0=TIER_0,
            tier1=TIER_1,
            tier1_holds=False,
        ),
        B8_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B9,
        Machine.M2,
        HALTABLE,
        M2Position.S9_EPOCH_HALTED,
        Conjunctive(
            (
                (
                    _C(
                        "B9-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        B9_ROW,
                        "coordinator, structurally, on an unresolved governance event",
                    ),
                    _C(
                        "B9-1",
                        UNRESOLVED_EVENT,
                        T,
                        B9_ROW,
                        "exists and is unresolved under this root",
                    ),
                ),
            )
        ),
        B9_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B10,
        Machine.M2,
        (M2Position.S8_GATE_REACHED,),
        M2Position.S10_EPOCH_SETTLED,
        Conjunctive(
            (
                (
                    _C(
                        "B10-T",
                        TRIGGER,
                        OWNER_STAGE_OUTCOME,
                        B10_ROW,
                        "OwnerDecision establishing a StageOutcome",
                    ),
                ),
            )
        ),
        B10_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B11,
        Machine.M2,
        (M2Position.S9_EPOCH_HALTED,),
        M2Position.S10_EPOCH_SETTLED,
        Conjunctive(
            (
                (
                    _C(
                        "B11-T",
                        TRIGGER,
                        OWNER_STAGE_OUTCOME,
                        B11_ROW,
                        "OwnerDecision establishing a StageOutcome",
                    ),
                    _C(
                        "B11-1",
                        STAGE_OUTCOME_VALUE,
                        ("REFUSED", "ABANDONED", "ACCEPT_PARTIAL"),
                        B11_ROW,
                        "(refused, abandoned, or accept-partial)",
                    ),
                ),
            )
        ),
        B11_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B12,
        Machine.M2,
        NON_TERMINAL,
        M2Position.S11_EPOCH_AUTHORITY_ENDED,
        Conjunctive(
            (
                (
                    _C(
                        "B12-R",
                        TRIGGER,
                        OWNER_REVOCATION,
                        B12_ROW,
                        "OwnerDecision of kind revocation",
                    ),
                    B12_WITHDRAWN,
                ),
                (
                    _C(
                        "B12-S",
                        TRIGGER,
                        OWNER_REBINDING,
                        B12_ROW,
                        "change taking effect as a new authorization",
                    ),
                    _C(
                        "B12-2",
                        BINDINGS_CEASED_TO_MATCH,
                        T,
                        B12_ROW,
                        "ceases to match its bindings (V-03)",
                    ),
                ),
            )
        ),
        B12_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B13,
        Machine.M2,
        (M2Position.S9_EPOCH_HALTED,),
        RESTORED,
        Conjunctive(
            (
                (
                    _C(
                        "B13-T",
                        TRIGGER,
                        OWNER_REFUSAL_RESOLUTION,
                        B13_ROW,
                        "OwnerDecision of kind refusal resolution",
                    ),
                    _C(
                        "B13-1",
                        DECISION_NAMES_OUTSTANDING_OCCURRENCE,
                        T,
                        HB3_ROW,
                        "The resolving OwnerDecision names the halt occurrence it resolves",
                    ),
                    _C(
                        "B13-2",
                        SINGLE_OUTSTANDING_OCCURRENCE,
                        T,
                        HB5_ROW,
                        "Exactly one halt occurrence can be outstanding",
                    ),
                    _C(
                        "B13-3",
                        RESTORED_POSITION,
                        tuple(HALTABLE),
                        HB4_ROW,
                        "B13's target is that occurrence's recorded source position",
                    ),
                    _C(
                        "B13-4",
                        RESTORED_OCCURRENCE_BOUND,
                        T,
                        HB1_RESTATED_ROW,
                        "B13's target is the recorded position and that recorded cycle"
                        " occurrence, never another",
                    ),
                    *RESUMPTION_PREDICATE,
                ),
            )
        ),
        B13_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M2Edge.B15,
        Machine.M2,
        (M2Position.S7_CLOSURE_ACTIVE,),
        M2Position.S6_REMEDIATION_ACTIVE,
        Stratified(
            own=(
                _C(
                    "B15-T",
                    TRIGGER,
                    BY_COORDINATOR,
                    B15_ROW,
                    "on a completed and adopted BOUNDED CLOSURE VERIFIER activation",
                ),
            ),
            tier0=TIER_0,
            tier1=TIER_1,
            tier1_holds=True,
        ),
        B15_ROW,
    ),
)

# M3 ------------------------------------------------------------------------------------

C3_T = _C("C3-T", TRIGGER, BY_COORDINATOR, C3_ROW, "coordinator, structurally")
C5_T = _C("C5-T", TRIGGER, BY_COORDINATOR, C5_ROW, "coordinator, structurally")
C5_TERMINATED = _C("C5-1", CP_2, T, C5_ROW, "the run terminated")
C6_T = _C("C6-T", TRIGGER, BY_COORDINATOR, C6_ROW, "on loss of governing authority")

M3_EDGES: Final[tuple[EdgeRule, ...]] = (
    EdgeRule(  # guard:ga_transition_guard
        M3Edge.C1,
        Machine.M3,
        (M3_ENTRY,),
        M3Position.ENVELOPE_DERIVED,
        Conjunctive(
            (
                (
                    _C("C1-T", TRIGGER, BY_COORDINATOR, C1_ROW, "coordinator derivation"),
                    _C("C1-1", BOUNDS_WITHIN_CEILING, T, C1_ROW, "EV-3 bounds ≤ ceiling"),
                    _C(
                        "C1-2",
                        DERIVATION_TOTAL,
                        T,
                        C1_ROW,
                        "EV-4 total function, no free parameters",
                    ),
                    _C("C1-3", ENVELOPE_VALID, T, C1_ROW, "§3.2 validity"),
                    _C(
                        "C1-4",
                        NAMES_ROOT_INSTANCE,
                        T,
                        C1_ROW,
                        "E-02 names the resolved root instance identity",
                    ),
                    _C("C1-5", BOUNDARY_FIXED, T, V14_ROW, "M3 C1, C2"),
                    _C("C1-6", UNACCOUNTED_MUTATION, F, V06_ROW, "before every derivation"),
                ),
            )
        ),
        C1_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M3Edge.C2,
        Machine.M3,
        (M3Position.ENVELOPE_DERIVED,),
        M3Position.ACTIVATION_RUNNING,
        Conjunctive(
            (
                (
                    _C(
                        "C2-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        C2_ROW,
                        "coordinator starts one bounded worker",
                    ),
                    _C(
                        "C2-1",
                        ROLE_MATCHES_ENVELOPE,
                        T,
                        C2_ROW,
                        "role matches the envelope's role (V-05)",
                    ),
                    _C(
                        "C2-2",
                        ENVELOPE_NEVER_ACTIVATED,
                        T,
                        C2_ROW,
                        "this envelope identity has never been activated (V-13, EV-5)",
                    ),
                    _C("C2-3", ENVELOPE_VALID, T, C2_ROW, "envelope valid (V-11, V-12)"),
                    _C("C2-4", BOUNDARY_FIXED, T, C2_ROW, "boundary fixed (V-14)"),
                    _C("C2-5", M4_LIVE, T, C2_ROW, "M4 = LIVE"),
                    _C("C2-6", M2_IN_MATCHING_STEP, T, C2_ROW, "M2 is in the matching step state"),
                    _C(
                        "C2-7",
                        PRIOR_ACTIVATION_AT_POSITION,
                        ("NONE", "CLOSED_AND_QUIESCENT"),
                        C2_ROW,
                        "both governance-closed and observed physically quiescent",
                    ),
                    _C(
                        "C2-8",
                        ADMITTED_OBLIGATIONS_AGREE,
                        (EQUAL, NOT_APPLICABLE),
                        OP8_ROW,
                        "C2's guard refuses an activation whose admitted obligation set is not"
                        " CYCLE_BOUND",
                    ),
                ),
            )
        ),
        C2_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M3Edge.C3,
        Machine.M3,
        (M3Position.ENVELOPE_DERIVED,),
        M3Position.ENVELOPE_VOIDED,
        Conjunctive(
            (
                (
                    C3_T,
                    _C(
                        "C3-1",
                        PRE_DISPATCH_GUARD_FAILED,
                        T,
                        C3_ROW,
                        "any pre-dispatch guard failure",
                    ),
                ),
                (
                    C3_T,
                    _C(
                        "C3-2",
                        UNACCOUNTED_MUTATION,
                        T,
                        C3_ROW,
                        "V-06 / V-07 / V-08 / V-09 / V-10 obtains",
                    ),
                ),
                (
                    C3_T,
                    _C(
                        "C3-3",
                        FROZEN_SET_UNCHANGED,
                        F,
                        C3_ROW,
                        "V-06 / V-07 / V-08 / V-09 / V-10 obtains",
                    ),
                ),
                (
                    C3_T,
                    _C(
                        "C3-4",
                        UNRESOLVED_EVENT,
                        T,
                        C3_ROW,
                        "V-06 / V-07 / V-08 / V-09 / V-10 obtains",
                    ),
                ),
                (
                    C3_T,
                    _C(
                        "C3-5",
                        AUTHORIZATION_WITHDRAWN,
                        T,
                        C3_ROW,
                        "V-06 / V-07 / V-08 / V-09 / V-10 obtains",
                    ),
                ),
                (
                    C3_T,
                    _C(
                        "C3-6",
                        USED_OUTSIDE_BOUND_STAGE,
                        T,
                        C3_ROW,
                        "V-06 / V-07 / V-08 / V-09 / V-10 obtains",
                    ),
                ),
                (C3_T, _C("C3-7", EPOCH_HALTED, T, C3_ROW, "or the epoch halted")),
            )
        ),
        C3_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M3Edge.C4,
        Machine.M3,
        (M3Position.ACTIVATION_RUNNING,),
        M3Position.ACTIVATION_COMPLETED,
        Conjunctive(
            (
                (
                    _C("C4-T", TRIGGER, BY_COORDINATOR, C4_ROW, "coordinator adoption"),
                    CP_1_C,
                    CP_2_C,
                    CP_3_C,
                    CP_4_C,
                    CP_5_C,
                ),
            )
        ),
        C4_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M3Edge.C5,
        Machine.M3,
        (M3Position.ACTIVATION_RUNNING,),
        M3Position.ACTIVATION_CLOSED_UNADOPTED,
        Conjunctive(
            (
                (C5_T, C5_TERMINATED, _C("C5-3", CP_3, F, C5_ROW, "any of CP-2…CP-5 fails")),
                (C5_T, C5_TERMINATED, _C("C5-4", CP_4, F, C5_ROW, "any of CP-2…CP-5 fails")),
                (C5_T, C5_TERMINATED, _C("C5-5", CP_5, F, C5_ROW, "any of CP-2…CP-5 fails")),
            )
        ),
        C5_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M3Edge.C6,
        Machine.M3,
        (M3Position.ACTIVATION_RUNNING,),
        M3Position.ACTIVATION_CLOSED_UNADOPTED,
        Conjunctive(
            (
                (C6_T, _C("C6-1", M4_LIVE, F, C6_ROW, "M4 left LIVE")),
                (C6_T, _C("C6-2", BINDINGS_MATCH, F, C6_ROW, "a binding ceased to match")),
                (C6_T, _C("C6-3", EPOCH_HALTED, T, C6_ROW, "the epoch halted (B9)")),
            )
        ),
        C6_ROW,
    ),
)

# M4 ------------------------------------------------------------------------------------

G_STAGE_OUTCOME = "OwnerDecision establishing a StageOutcome"
G_REVOCATION = "OwnerDecision of kind revocation"

M4_EDGES: Final[tuple[EdgeRule, ...]] = (
    EdgeRule(  # guard:ga_transition_guard
        M4Edge.G1,
        Machine.M4,
        (AuthorizationDisposition.LIVE,),
        AuthorizationDisposition.SUSPENDED,
        Conjunctive(
            (
                (
                    _C(
                        "G1-T",
                        TRIGGER,
                        BY_COORDINATOR,
                        G1_ROW,
                        "an unresolved governance event arises under this root",
                    ),
                    _C(
                        "G1-1",
                        UNRESOLVED_EVENT,
                        T,
                        G1_ROW,
                        "an unresolved governance event arises under this root",
                    ),
                ),
            )
        ),
        G1_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M4Edge.G2,
        Machine.M4,
        (AuthorizationDisposition.LIVE,),
        AuthorizationDisposition.CONSUMED,
        Conjunctive(((_C("G2-T", TRIGGER, OWNER_STAGE_OUTCOME, G2_ROW, G_STAGE_OUTCOME),),)),
        G2_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M4Edge.G3,
        Machine.M4,
        (AuthorizationDisposition.SUSPENDED,),
        AuthorizationDisposition.CONSUMED,
        Conjunctive(((_C("G3-T", TRIGGER, OWNER_STAGE_OUTCOME, G3_ROW, G_STAGE_OUTCOME),),)),
        G3_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M4Edge.G4,
        Machine.M4,
        (AuthorizationDisposition.LIVE,),
        AuthorizationDisposition.REVOKED,
        Conjunctive(((_C("G4-T", TRIGGER, OWNER_REVOCATION, G4_ROW, G_REVOCATION),),)),
        G4_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M4Edge.G5,
        Machine.M4,
        (AuthorizationDisposition.SUSPENDED,),
        AuthorizationDisposition.REVOKED,
        Conjunctive(((_C("G5-T", TRIGGER, OWNER_REVOCATION, G5_ROW, G_REVOCATION),),)),
        G5_ROW,
    ),
    EdgeRule(  # guard:ga_transition_guard
        M4Edge.G6,
        Machine.M4,
        (AuthorizationDisposition.SUSPENDED,),
        AuthorizationDisposition.LIVE,
        Conjunctive(
            (
                (
                    _C(
                        "G6-T",
                        TRIGGER,
                        OWNER_REFUSAL_RESOLUTION,
                        G6_ROW,
                        "OwnerDecision of kind refusal resolution",
                    ),
                    *RESUMPTION_PREDICATE,
                ),
            )
        ),
        G6_ROW,
    ),
)

EDGES: Final[tuple[EdgeRule, ...]] = (*M1_EDGES, *M2_EDGES, *M3_EDGES, *M4_EDGES)
"""Every frozen edge, `A1`…`A4`, `B1`…`B13` with `B6a`/`B6b`, `B15`, `C1`…`C6`, `G1`…`G6` —
and no `B14`, which `D-AP04-02(b)` records does not exist and the vocabulary cannot name."""


# --- cross-machine coupling ------------------------------------------------------------


@dataclass(frozen=True)
class CoupledEdges:
    """An M2 edge and the M4 edge(s) one act moves together (§4.2, §6, `K-2`…`K-4`, `K-9`).

    `joint` pairs fire together or not at all. A pair that is not joint names the M4 edge
    the act takes *where the instance moves at all*: a scope or authority change under
    `B12` moves no disposition (`M4-4`, §6.1 outcomes 2 and 3)."""

    m2: M2Edge
    m4: tuple[M4Edge, ...]
    joint: bool
    row: Row


COUPLED: Final[tuple[CoupledEdges, ...]] = (
    CoupledEdges(M2Edge.B9, (M4Edge.G1,), True, G1_ROW),
    CoupledEdges(M2Edge.B10, (M4Edge.G2,), True, Row(AP04, "| K-3 |")),
    CoupledEdges(M2Edge.B11, (M4Edge.G3,), True, Row(AP04, "| K-3 |")),
    CoupledEdges(M2Edge.B13, (M4Edge.G6,), True, Row(AP04, "| K-9 |")),
    CoupledEdges(M2Edge.B12, (M4Edge.G4, M4Edge.G5), False, Row(AP04, "| K-4 |")),
)

COUPLING_INVARIANTS: Final[tuple[str, ...]] = (
    "K-1",
    "K-2",
    "K-2a",
    "K-3",
    "K-4",
    "K-5",
    "K-6",
    "K-7",
    "K-8",
    "K-9",
    "K-10",
)
"""AP-04 §7, in its frozen order of identifiers; each is checked by `state_machine.py`."""
