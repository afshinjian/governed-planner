"""The transition evaluator, the coupling checks and the generated conformance matrix.

Design basis: AP-04 §3–§12 (`M1`…`M4`, `K-1`…`K-10`, §7.1 occupancies, `M2-12`, `TM-1`),
§17 (`AP04-I01`…`AP04-I41`); the AP-04 bounded-cycle amendment §3.1–§3.6 (`B15`,
`CE-0a`…`CE-6`, `CE-T1`…`CE-T3`, `AP04-I42`…`AP04-I50`), §3.3.3 (`OP-8`), §3.5.12 (`HB-1` as
restated); AP-07 §8 (`DV-3`, `DV-4`, `DV-6`, `DV-7`), `GH-3`
as allocated by the AP-11 ST-04 amendment (`DO11-2`, `DO11-3`); AP-11 §4 (`SV11-1`…`SV11-11`).

**One authority source.** Everything here reads `state_machine_model`; nothing restates an
edge, a guard or a position. The evaluator, the matrix and the coupling checks are three
readings of the same data, so the matrix cannot disagree with what the evaluator admits.

**Pure.** Every function is a function of its arguments and of the model: no clock, no
store write, no repository, no worker, no provider, no randomness, no state kept between
calls. A position is never held here: `recorded_positions` reads it from the `RC-34` chains
through ST-04's `DV-6` each time it is asked, and nothing it returns is storable.

**What evaluation decides, and what it does not.** `evaluate` answers one question — *is
this edge, from this position, admissible under these facts?* It never chooses among edges:
the edge is the caller's input, and `admissible_edges` returns every admissible edge as an
unordered set without preferring one (`AP04-I06`). No fact is computed here except those an
ST-04 derivation already yields (`derived_guard_facts`); root resolution, envelope
derivation, observation, attribution and the cycle predicate's facts are later stages', and
a fact nobody supplied is `INDETERMINATE`, which fails every guard (`P-04`).

**Fail closed, in the frozen order.** An edge with no rule from the position is refused
before any fact is read — the pair is inexpressible. For `B8`/`B15`, Tier 0 is evaluated
first and a Tier-0 failure never reaches Tier 1; an indeterminate Tier 1 admits neither edge
(`CE-T1`…`CE-T3`). A refusal changes no position (`AP04-I21`).

**`B13` is bound to its halt occurrence** (`HB-1` as restated, `SV11-6`). Its admitted
result carries the named halt's `Restoration` — the halt, its recorded source position and
its recorded cycle occurrence, read by `recorded_restoration` from that `RC-31` record and
never inferred. Its guard facts carry, under `NAMED_HALT`, the halt they were read for.
Without a restoration, with one whose position is not the guard's, or with one for another
halt than the facts' — or facts naming no halt — `B13` is refused; two halts at one
position in different cycle occurrences give different results, and are never
interchangeable. The evaluator checks the halt it is given; it never chooses one.

Guard identifier fixed on each evaluation line (`MU11-3`): `ga_transition_evaluator`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from gpauto import derivations as dv
from gpauto import state_machine_model as model
from gpauto.absence import Determined, NotApplicable, Present
from gpauto.coordination_identity import CycleOccurrenceId, HaltOccurrenceId
from gpauto.coordination_records import (
    AuthorityEnvelopeRecord,
    CycleOccurrence,
    HaltOccurrence,
    ResolvedRootResult,
)
from gpauto.coordination_vocabulary import (
    M1Edge,
    M1Position,
    M2Edge,
    M2Position,
    M3Position,
    M4Edge,
    Machine,
    Quiescence,
)
from gpauto.identity import (
    AuthorityEnvelopeId,
    OwnerAuthorizationId,
    RemediationObligationId,
    RootResolutionId,
)
from gpauto.vocabulary import AuthorizationDisposition

type Facts = dict[str, str]
"""Fact name → value. A missing fact, or a value outside its fact's domain, is
`INDETERMINATE`. Unordered: evaluation never depends on how the facts were assembled."""

NO_EDGE: Final = "NO_EDGE"
"""The pair is inexpressible: the edge leaves none of this position's rules (`SV11-2`)."""
GUARD: Final = "GUARD"
TIER_0: Final = "TIER_0"
TIER_1_INDETERMINATE: Final = "TIER_1_INDETERMINATE"
TIER_1_OTHER_EDGE: Final = "TIER_1_OTHER_EDGE"
COUPLED_EDGE: Final = "COUPLED_EDGE"
RESTORATION: Final = "RESTORATION"
"""`B13`'s guard holds, but no recorded restoration agreeing with it was given (`HB-1`)."""

NAMED_HALT: Final = "NAMED_HALT"
"""The facts' key for the identity of the halt occurrence their halt-sensitive facts were
read for — not a guard fact, and read by `B13` alone, against its restoration (`SV11-6`)."""


@dataclass(frozen=True)
class Unmet:
    """One condition a refusal names: its identifier, its fact and the value it saw."""

    condition: str
    fact: str
    observed: str


@dataclass(frozen=True)
class Restoration:
    """`HB-1` as restated: one halt occurrence as recorded — its exact M2 source position
    and the cycle occurrence the epoch then occupied, `KnownAbsent` off `S6`/`S7`."""

    halt: HaltOccurrenceId
    position: M2Position
    cycle_occurrence: Determined[CycleOccurrenceId]


@dataclass(frozen=True)
class Admitted:
    """The edge is admissible from `source`, and would take the subject to `target`. For
    `B13` alone, `restored` names the halt occurrence, position and cycle occurrence the
    target restores; it is `None` for every other edge."""

    edge: model.EdgeName
    source: model.Position
    target: model.Position
    restored: Restoration | None = None


@dataclass(frozen=True)
class Refused:
    """The edge is not admissible. Nothing moves (`AP04-I21`); `stratum` says where the
    evaluation stopped, and `unmet` names each condition that failed there."""

    edge: model.EdgeName
    source: model.Position
    stratum: str
    unmet: tuple[Unmet, ...]


type Evaluation = Admitted | Refused


# --- the evaluator ------------------------------------------------------------------------


def edge_rule(edge: model.EdgeName) -> model.EdgeRule:
    """The model's one rule for `edge`. Read from the model on every call."""
    (rule,) = [r for r in model.EDGES if r.edge == edge]
    return rule


def fact_value(facts: Facts, fact: model.Fact) -> str:
    """The supplied value, or `INDETERMINATE` if absent or outside the fact's domain."""
    value = facts.get(fact.name, model.INDETERMINATE)
    return value if value in fact.values else model.INDETERMINATE  # guard:ga_transition_evaluator


def _unmet(conditions: tuple[model.Condition, ...], facts: Facts) -> tuple[Unmet, ...]:
    return tuple(
        Unmet(c.identifier, c.fact.name, fact_value(facts, c.fact))
        for c in conditions
        if fact_value(facts, c.fact) not in c.admitted  # guard:ga_transition_evaluator
    )


def _admitted(
    rule: model.EdgeRule, source: model.Position, facts: Facts, restoration: Restoration | None
) -> Evaluation:
    """The admitted result, once the guard holds. A restored target is the named halt's
    recorded position and cycle occurrence, taken from its `Restoration` — which must
    exist, agree with the position the guard read, and be for the very halt the guard's
    facts were read for (`HB-1` as restated, `HB-4`, `SV11-6`)."""
    if not isinstance(rule.target, model.RestoredPosition):
        return Admitted(rule.edge, source, rule.target)
    restored = fact_value(facts, model.RESTORED_POSITION)
    if restoration is None or restoration.position != restored:  # guard:ga_transition_evaluator
        return Refused(rule.edge, source, RESTORATION, ())
    if facts.get(NAMED_HALT) != restoration.halt.value:  # guard:ga_transition_evaluator
        return Refused(rule.edge, source, RESTORATION, ())
    return Admitted(rule.edge, source, restoration.position, restoration)


def evaluate(
    edge: model.EdgeName,
    source: model.Position,
    facts: Facts,
    restoration: Restoration | None = None,
) -> Evaluation:
    """Whether `edge` is admissible from `source` under `facts` — and nothing else.
    `restoration` is read by `B13` alone, and only once its guard holds."""
    rule = edge_rule(edge)
    if source not in rule.sources:  # guard:ga_transition_evaluator
        return Refused(edge, source, NO_EDGE, ())
    guard = rule.guard
    if isinstance(guard, model.Stratified):
        return _stratified(rule, source, guard, facts)
    failures = [_unmet(alternative, facts) for alternative in guard.alternatives]
    if any(not failed for failed in failures):  # guard:ga_transition_evaluator
        return _admitted(rule, source, facts, restoration)
    return Refused(edge, source, GUARD, tuple(u for failed in failures for u in failed))


def _stratified(
    rule: model.EdgeRule, source: model.Position, guard: model.Stratified, facts: Facts
) -> Evaluation:
    """`CE-T1`…`CE-T3`: the edge's own conditions; then Tier 0; then, only on a
    determinate Tier-0 pass, Tier 1 — which admits this edge only when it takes this
    edge's value, and admits neither edge when any of it is indeterminate."""
    own = _unmet(guard.own, facts)
    if own:
        return Refused(rule.edge, source, GUARD, own)
    tier0 = _unmet(guard.tier0, facts)
    if tier0:  # guard:ga_transition_evaluator
        return Refused(rule.edge, source, TIER_0, tier0)
    tier1 = [(c, fact_value(facts, c.fact)) for c in guard.tier1]
    unknown = tuple(
        Unmet(c.identifier, c.fact.name, value)
        for c, value in tier1
        if value == model.INDETERMINATE  # guard:ga_transition_evaluator
    )
    if unknown:  # guard:ga_transition_evaluator
        return Refused(rule.edge, source, TIER_1_INDETERMINATE, unknown)
    holds = all(value in c.admitted for c, value in tier1)  # guard:ga_transition_evaluator
    if holds != guard.tier1_holds:  # guard:ga_transition_evaluator
        return Refused(rule.edge, source, TIER_1_OTHER_EDGE, _unmet(guard.tier1, facts))
    return _admitted(rule, source, facts, None)


def admissible_edges(
    machine: Machine,
    source: model.Position,
    facts: Facts,
    restoration: Restoration | None = None,
) -> frozenset[Admitted]:
    """Every edge of `machine` admissible from `source` — a set, never a choice."""
    return frozenset(
        found
        for rule in model.EDGES
        if rule.machine == machine
        for found in (evaluate(rule.edge, source, facts, restoration),)
        if isinstance(found, Admitted)
    )


# --- one act moving two machines ---------------------------------------------------------


@dataclass(frozen=True)
class Act:
    """An M2 edge and the M4 edge the same act takes, or `None` where it moves none."""

    m2: Admitted
    m4: Admitted | None


def evaluate_act(
    m2_edge: M2Edge,
    m2_source: model.Position,
    m4_source: AuthorizationDisposition,
    facts: Facts,
    restoration: Restoration | None = None,
) -> Act | Refused:
    """An M2 edge together with its coupled M4 edge (§4.2, §6): a joint pair fires together
    or not at all (`K-9` for `B13`/`G6`; `B9`/`G1`, `B10`/`G2`, `B11`/`G3`); `B12` moves M4
    only where a revocation edge is admissible (§6.1). Uncoupled edges move M2 alone."""
    m2 = evaluate(m2_edge, m2_source, facts, restoration)
    if isinstance(m2, Refused):
        return m2
    coupled = [c for c in model.COUPLED if c.m2 == m2_edge]
    if not coupled:
        return Act(m2, None)
    (coupling,) = coupled
    moved = [
        found
        for edge in coupling.m4
        for found in (evaluate(edge, m4_source, facts),)
        if isinstance(found, Admitted)
    ]
    if coupling.joint and not moved:  # guard:ga_transition_evaluator
        return Refused(m2_edge, m2_source, COUPLED_EDGE, ())
    return Act(m2, moved[0] if moved else None)


# --- the generated conformance matrix ------------------------------------------------------


@dataclass(frozen=True)
class MatrixCell:
    """One (position, edge) pair of one machine, disposed: legal with its guard's
    conditions and target, or illegal — inexpressible, with no guard to satisfy."""

    machine: Machine
    source: model.Position
    edge: model.EdgeName
    legal: bool
    target: model.Position | model.RestoredPosition | None
    conditions: tuple[str, ...]
    triggers: tuple[str, ...]
    row: model.Row


def guard_conditions(guard: model.Guard) -> tuple[model.Condition, ...]:
    """Every condition a guard reads, once each, in the model's order."""
    if isinstance(guard, model.Stratified):
        found = (*guard.own, *guard.tier0, *guard.tier1)
    else:
        found = tuple(c for alternative in guard.alternatives for c in alternative)
    unique: dict[str, model.Condition] = {}
    for condition in found:
        unique.setdefault(condition.identifier, condition)
    return tuple(unique.values())


def conformance_matrix() -> tuple[MatrixCell, ...]:
    """The complete `position × edge` product of every machine, generated from the model
    (`SV11-1`, `SV11-2`): every pair is a cell and every cell has a disposition."""
    cells: list[MatrixCell] = []
    for machine, positions in model.POSITIONS:
        rules = [rule for rule in model.EDGES if rule.machine == machine]
        for position in positions:
            for rule in rules:
                legal = position in rule.sources
                conditions = guard_conditions(rule.guard)
                cells.append(
                    MatrixCell(
                        machine,
                        position,
                        rule.edge,
                        legal,
                        rule.target if legal else None,
                        tuple(c.identifier for c in conditions) if legal else (),
                        tuple(
                            value
                            for c in conditions
                            if c.fact is model.TRIGGER
                            for value in c.admitted
                        )
                        if legal
                        else (),
                        rule.row,
                    )
                )
    return tuple(cells)


# --- cross-machine coupling ------------------------------------------------------------------


@dataclass(frozen=True)
class Subject:
    """One M3 subject as it bears on coupling: its envelope, position, the step it was
    derived for, its cycle occurrence at `S6`/`S7`, whether it is the current occurrence's
    subject, and the observed quiescence of its process where it has been closed."""

    envelope: str
    position: M3Position
    step: M2Position
    occurrence: str | None
    current: bool
    quiescence: Quiescence | None


@dataclass(frozen=True)
class Configuration:
    """One epoch's coupled positions: its root resolution (M1), the epoch (M2), the
    governing instance (M4) and its recorded eligibility, and the M3 subjects."""

    m1: M1Position | model.Entry
    m2: M2Position | model.Entry
    m4: AuthorizationDisposition
    eligible: bool | None
    subjects: tuple[Subject, ...]


@dataclass(frozen=True)
class CouplingViolation:
    invariant: str
    detail: str


LIVE_M3: Final = frozenset({M3Position.ENVELOPE_DERIVED, M3Position.ACTIVATION_RUNNING})
NO_LIVE_SUBJECT: Final = frozenset(
    {
        M2Position.S1_EPOCH_OPENED,
        M2Position.S2_ENTRY_BOUNDARY_FIXED,
        M2Position.S5_FINDING_SET_FROZEN,
        M2Position.S8_GATE_REACHED,
        M2Position.S9_EPOCH_HALTED,
    }
)
"""`K-5`'s second clause: at these states no M3 subject is live."""


def coupling_violations(config: Configuration) -> tuple[CouplingViolation, ...]:
    """`K-1` … `K-8` and `K-10` over one configuration; `K-9` is an act's (`evaluate_act`,
    `act_violations`). An empty result is conformance; nothing is repaired."""
    found: list[CouplingViolation] = []
    m2, m4 = config.m2, config.m4
    live = [s for s in config.subjects if s.position in LIVE_M3]
    non_terminal = m2 in model.NON_TERMINAL
    if non_terminal and m4 not in (
        AuthorizationDisposition.LIVE,
        AuthorizationDisposition.SUSPENDED,
    ):
        found.append(CouplingViolation("K-1", f"{m2} with {m4}"))
    halted = m2 == M2Position.S9_EPOCH_HALTED
    if non_terminal and halted != (m4 == AuthorizationDisposition.SUSPENDED):
        found.append(CouplingViolation("K-2", f"{m2} with {m4}"))
    retained = {
        M2Position.S10_EPOCH_SETTLED: {AuthorizationDisposition.CONSUMED},
        M2Position.S11_EPOCH_AUTHORITY_ENDED: {
            AuthorizationDisposition.REVOKED,
            AuthorizationDisposition.LIVE,
            AuthorizationDisposition.SUSPENDED,
        },
    }
    if isinstance(m2, M2Position) and m2 in retained and m4 not in retained[m2]:
        found.append(CouplingViolation("K-2a", f"{m2} retains {m4}"))
    if (m2 == M2Position.S10_EPOCH_SETTLED) != (m4 == AuthorizationDisposition.CONSUMED):
        found.append(CouplingViolation("K-3", f"{m2} with {m4}"))
    if m2 == M2Position.S11_EPOCH_AUTHORITY_ENDED and not (
        m4 == AuthorizationDisposition.REVOKED
        or (
            m4 in (AuthorizationDisposition.LIVE, AuthorizationDisposition.SUSPENDED)
            and config.eligible is False
        )
    ):
        found.append(CouplingViolation("K-4", f"{m4}, eligible={config.eligible}"))
    if len(live) > 1:
        found.append(CouplingViolation("K-5", f"{len(live)} live subjects"))
    if m2 in NO_LIVE_SUBJECT and live:
        found.append(CouplingViolation("K-5", f"a live subject at {m2}"))
    if m2 in model.STEP_STATES and [s for s in live if s.step != m2 or not s.current]:
        found.append(CouplingViolation("K-5", f"a live subject not the current one at {m2}"))
    found.extend(_completed_bound(config.subjects))
    if m4 != AuthorizationDisposition.LIVE and live:
        found.append(CouplingViolation("K-7", f"a live subject under {m4}"))
    if config.m1 in model.M1_HALTS and m2 != model.M2_ENTRY:
        found.append(CouplingViolation("K-8", f"an epoch at {m2} under {config.m1}"))
    found.extend(_running_bound(config.subjects))
    return tuple(found)


def _completed_bound(subjects: tuple[Subject, ...]) -> list[CouplingViolation]:
    """`K-6` as restated by the amendment §3.5.2: at most one completed subject per step per
    epoch outside `{S6, S7}`, and at `S6`/`S7` at most one per cycle occurrence."""
    found: list[CouplingViolation] = []
    completed = [s for s in subjects if s.position == M3Position.ACTIVATION_COMPLETED]
    for step in model.STEP_STATES:
        here = [s for s in completed if s.step == step]
        cyclic = step in (M2Position.S6_REMEDIATION_ACTIVE, M2Position.S7_CLOSURE_ACTIVE)
        keys = [s.occurrence for s in here] if cyclic else [None for _ in here]
        if len(keys) != len(set(keys)):
            found.append(CouplingViolation("K-6", f"two completed subjects at {step}"))
    return found


def _running_bound(subjects: tuple[Subject, ...]) -> list[CouplingViolation]:
    """`K-10`: at most one possibly-running process per step position. A running subject
    runs; a closed-unadopted one runs until observed quiescent — indeterminate is not
    quiescence (`PQ-2`, `P-04`)."""
    found: list[CouplingViolation] = []
    for step in model.STEP_STATES:
        running = [
            s
            for s in subjects
            if s.step == step
            and (
                s.position == M3Position.ACTIVATION_RUNNING
                or (
                    s.position == M3Position.ACTIVATION_CLOSED_UNADOPTED
                    and s.quiescence != Quiescence.QUIESCENT
                )
            )
        ]
        if len(running) > 1:
            found.append(CouplingViolation("K-10", f"{len(running)} possibly running at {step}"))
    return found


def act_violations(m2_edge: M2Edge | None, m4_edge: M4Edge | None) -> tuple[CouplingViolation, ...]:
    """`K-9` and its companions: a joint pair recorded half — an M2 edge without its M4
    edge, or an M4 edge without its M2 edge — is a violation."""
    found: list[CouplingViolation] = []
    for coupling in model.COUPLED:
        if not coupling.joint:
            continue
        has_m2 = m2_edge == coupling.m2
        has_m4 = m4_edge in coupling.m4
        if has_m2 != has_m4:
            invariant = "K-9" if coupling.m2 == M2Edge.B13 else "K-2"
            found.append(CouplingViolation(invariant, f"{m2_edge} with {m4_edge}"))
    return tuple(found)


LIVE_OCCUPANCY: Final = "LIVE"
COMPLETED_NOT_ROUTED: Final = "COMPLETED_NOT_ROUTED"
NOTHING_LIVE: Final = "NOTHING_LIVE"


def occupancy(config: Configuration) -> str | None:
    """§7.1: how a step state is occupied — by a live subject; by a completed, not yet
    routed one; or with nothing live (resumed, or not yet dispatched). `None` off a step.
    Read of the **current** occurrence's subject; earlier cycles' subjects are history
    (`OC-4` as restated)."""
    if config.m2 not in model.STEP_STATES:
        return None
    current = [s for s in config.subjects if s.current and s.step == config.m2]
    if [s for s in current if s.position in LIVE_M3]:
        return LIVE_OCCUPANCY
    if [s for s in current if s.position == M3Position.ACTIVATION_COMPLETED]:
        return COMPLETED_NOT_ROUTED
    return NOTHING_LIVE


# --- positions and facts, from ST-04's derivations ----------------------------------------------


@dataclass(frozen=True)
class Positions:
    """M1 … M4 positions, each read from its `RC-34` chain by `DV-6` — never stored."""

    m1: M1Position | model.Entry
    m2: M2Position | model.Entry
    m3: tuple[tuple[AuthorityEnvelopeId, M3Position | model.Entry], ...]
    m4: AuthorizationDisposition


def _m1(records: dv.AuthoritativeRecords, resolution: RootResolutionId) -> M1Position | model.Entry:
    found = dv.derive_m1_position(records, resolution)
    if isinstance(found, dv.Indeterminate):
        raise _Undetermined(found)
    return model.M1_ENTRY if isinstance(found, dv.Unoccupied) else found.reached.state


def _m2(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> M2Position | model.Entry:
    found = dv.derive_m2_position(records, root)
    if isinstance(found, dv.Indeterminate):
        raise _Undetermined(found)
    return model.M2_ENTRY if isinstance(found, dv.Unoccupied) else found.reached.state


def _m3(
    records: dv.AuthoritativeRecords, envelope: AuthorityEnvelopeId
) -> M3Position | model.Entry:
    found = dv.derive_m3_position(records, envelope)
    if isinstance(found, dv.Indeterminate):
        raise _Undetermined(found)
    return model.M3_ENTRY if isinstance(found, dv.Unoccupied) else found.reached.state


def _m4(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> AuthorizationDisposition:
    """`M4-5`: an instance no M4 entry names is `LIVE` — the default, not a record."""
    found = dv.derive_m4_position(records, root)
    if isinstance(found, dv.Indeterminate):
        raise _Undetermined(found)
    return (
        AuthorizationDisposition.LIVE if isinstance(found, dv.Unoccupied) else found.reached.state
    )


class _Undetermined(Exception):
    """Internal signal: a derivation this read needs was indeterminate."""

    def __init__(self, outcome: dv.Indeterminate) -> None:
        super().__init__(outcome.detail)
        self.outcome = outcome


def recorded_positions(
    records: dv.AuthoritativeRecords,
    resolution: RootResolutionId,
    root: OwnerAuthorizationId,
    envelopes: tuple[AuthorityEnvelopeId, ...],
) -> Positions | dv.Indeterminate:
    """The four machines' positions for one resolution, one epoch and its envelopes,
    each followed by predecessor reference through `DV-6` (`PV11-11`)."""
    try:
        return Positions(
            _m1(records, resolution),
            _m2(records, root),
            tuple((envelope, _m3(records, envelope)) for envelope in envelopes),
            _m4(records, root),
        )
    except _Undetermined as undetermined:
        return undetermined.outcome


def _truth(value: bool) -> str:
    return model.TRUE if value else model.FALSE


def derived_guard_facts(
    records: dv.AuthoritativeRecords,
    resolution: RootResolutionId,
    root: OwnerAuthorizationId,
    envelope: AuthorityEnvelopeId | None = None,
    named_halt: HaltOccurrenceId | None = None,
    admitted_obligations: frozenset[RemediationObligationId] | None = None,
) -> Facts:
    """The guard facts an ST-04 derivation yields, and only those (`DO11-2`, `DO11-3`).

    * `M1_ROOT_RESOLVED` — `DV-4` recorded eligibility: the resolution's completing `A2`
      entry already names `root`. A result is read only once it exists.
    * `M4_LIVE` — `DV-6` M4 position, which must agree with `DV-4` liveness.
    * `UNRESOLVED_EVENT` — `DV-4` liveness: an unresolved suspending event.
    * `EPOCH_HALTED` — `DV-6` M2 position.
    * for `envelope`: `ENVELOPE_NEVER_ACTIVATED`, `STEP_ACTIVATION_COMPLETED`,
      `STEP_ENVELOPE_TERMINAL` from its `DV-6` M3 position, and `M2_IN_MATCHING_STEP`
      from its recorded target step against the epoch's `DV-6` M2 position.
    * for `envelope`: `ADMITTED_OBLIGATIONS_AGREE` (`OP-8`(i)) — the dispatch's
      `admitted_obligations` against `DV-3` `CYCLE_BOUND`'s members, as committed by ST-04
      and never recomputed here; `NOT_APPLICABLE` where the recorded envelope carries no
      `E-14` frozen-set reference. Absent where the set is not given, the epoch has no
      frozen set, or `E-14` names another set than the epoch's.
    * for `named_halt`: `HB-3`, `HB-5` from `DV-7`'s outstanding occurrences on the root's
      suspending events, and `HB-4`'s restored position and `HB-1`'s occurrence binding
      from the named occurrence's `Restoration` — all read for that one halt, whose
      identity is carried under `NAMED_HALT`.

    A fact whose derivation is indeterminate is `INDETERMINATE`; nothing defaults.
    """
    facts: Facts = {}
    eligibility = dv.derive_recorded_eligibility(records, resolution)
    if isinstance(eligibility, dv.CompletedResolution):
        result = eligibility.result
        facts[model.M1_ROOT_RESOLVED.name] = _truth(
            eligibility.edge == M1Edge.A2
            and isinstance(result, ResolvedRootResult)
            and result.resolved_root == root
        )
    elif isinstance(eligibility, dv.OpenResolution):
        facts[model.M1_ROOT_RESOLVED.name] = model.FALSE
    liveness = dv.derive_liveness(records, root)
    try:
        disposition = _m4(records, root)
        m2 = _m2(records, root)
    except _Undetermined:
        return facts
    if isinstance(liveness, dv.Liveness):
        if liveness.live == (disposition == AuthorizationDisposition.LIVE):
            facts[model.M4_LIVE.name] = _truth(liveness.live)
        facts[model.UNRESOLVED_EVENT.name] = _truth(bool(liveness.suspended_by))
    facts[model.EPOCH_HALTED.name] = _truth(m2 == M2Position.S9_EPOCH_HALTED)
    if envelope is not None:
        facts.update(_envelope_facts(records, envelope, m2))
        facts.update(_cycle_bound_facts(records, root, envelope, admitted_obligations))
    if named_halt is not None and isinstance(liveness, dv.Liveness):
        facts.update(_halt_facts(records, root, named_halt, liveness))
    return facts


def _envelope_facts(
    records: dv.AuthoritativeRecords, envelope: AuthorityEnvelopeId, m2: M2Position | model.Entry
) -> Facts:
    try:
        m3 = _m3(records, envelope)
    except _Undetermined:
        return {}
    facts: Facts = {
        model.ENVELOPE_NEVER_ACTIVATED.name: _truth(m3 == M3Position.ENVELOPE_DERIVED),
        model.STEP_ACTIVATION_COMPLETED.name: _truth(m3 == M3Position.ACTIVATION_COMPLETED),
        model.STEP_ENVELOPE_TERMINAL.name: _truth(m3 in model.TERMINAL),
    }
    if AuthorityEnvelopeRecord in records.unreadable | records.unstable:
        return facts
    targets = {
        r.target_state
        for r in records.records
        if isinstance(r, AuthorityEnvelopeRecord) and r.envelope.identity == envelope
    }
    if len(targets) == 1:
        facts[model.M2_IN_MATCHING_STEP.name] = _truth(targets == {m2})
    return facts


def _cycle_bound_facts(
    records: dv.AuthoritativeRecords,
    root: OwnerAuthorizationId,
    envelope: AuthorityEnvelopeId,
    admitted: frozenset[RemediationObligationId] | None,
) -> Facts:
    """`OP-8`(i): at `C2`, the activation's admitted obligation set is `CYCLE_BOUND`."""
    if AuthorityEnvelopeRecord in records.unreadable | records.unstable:
        return {}
    references = {
        r.envelope.bounds.frozen_set_reference
        for r in records.records
        if isinstance(r, AuthorityEnvelopeRecord) and r.envelope.identity == envelope
    }
    if len(references) != 1:
        return {}
    (reference,) = references
    name = model.ADMITTED_OBLIGATIONS_AGREE.name
    if isinstance(reference, NotApplicable):
        return {name: model.NOT_APPLICABLE}
    bound = dv.derive_cycle_bound(records, root)
    if admitted is None or not isinstance(bound, dv.CycleBound):
        return {}
    if bound.frozen_set != reference.value:
        return {}
    return {name: model.EQUAL if admitted == bound.members else model.UNEQUAL}


def recorded_restoration(
    records: dv.AuthoritativeRecords, named: HaltOccurrenceId
) -> Restoration | dv.Indeterminate:
    """The named halt occurrence as its `RC-31` record states it — source position and
    cycle occurrence exactly as recorded, never inferred from any other record (`HB-1`)."""
    if HaltOccurrence in records.unreadable:
        return dv.Indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "RC-31")
    if HaltOccurrence in records.unstable:
        return dv.Indeterminate(dv.IndeterminacyCause.UNSTABLE_READ, "RC-31")
    found = [r for r in records.records if isinstance(r, HaltOccurrence) and r.identity == named]
    if len(found) != 1:
        return dv.Indeterminate(dv.IndeterminacyCause.MISSING_RECORD, "the named RC-31 record")
    (halt,) = found
    return Restoration(halt.identity, halt.source_state, halt.cycle_occurrence)


CYCLIC: Final = frozenset({M2Position.S6_REMEDIATION_ACTIVE, M2Position.S7_CLOSURE_ACTIVE})
"""The positions at which a halt records its cycle occurrence (`HB-1` as restated, `GH-3`)."""


def _occurrence_bound(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId, restoration: Restoration
) -> Facts:
    """`HB-1` as restated: present exactly at `S6`/`S7`, and then naming an `RC-33`
    occurrence of this epoch. An unreadable `RC-33` leaves the fact indeterminate."""
    name = model.RESTORED_OCCURRENCE_BOUND.name
    cyclic = restoration.position in CYCLIC
    occurrence = restoration.cycle_occurrence
    if not isinstance(occurrence, Present):
        return {name: _truth(not cyclic)}
    if CycleOccurrence in records.unreadable | records.unstable:
        return {}
    recorded = [
        r
        for r in records.records
        if isinstance(r, CycleOccurrence) and r.identity == occurrence.value
    ]
    return {
        name: _truth(
            cyclic and len(recorded) == 1 and recorded[0].predecessor_entry.epoch_root == root
        )
    }


def _halt_facts(
    records: dv.AuthoritativeRecords,
    root: OwnerAuthorizationId,
    named: HaltOccurrenceId,
    liveness: dv.Liveness,
) -> Facts:
    outstanding = dv.derive_outstanding_halts(records)
    if isinstance(outstanding, dv.Indeterminate):
        return {}
    if HaltOccurrence in records.unreadable | records.unstable:
        return {}
    halts = [r for r in records.records if isinstance(r, HaltOccurrence)]
    on_root = frozenset(
        h.identity
        for h in halts
        if h.event in liveness.suspended_by and h.identity in outstanding.occurrences
    )
    facts: Facts = {
        NAMED_HALT: named.value,
        model.DECISION_NAMES_OUTSTANDING_OCCURRENCE.name: _truth(named in on_root),
        model.SINGLE_OUTSTANDING_OCCURRENCE.name: _truth(len(on_root) == 1),
    }
    restoration = recorded_restoration(records, named)
    if isinstance(restoration, Restoration):
        facts[model.RESTORED_POSITION.name] = restoration.position.value
        facts.update(_occurrence_bound(records, root, restoration))
    return facts
