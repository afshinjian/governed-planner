"""`GP-AUTO-ST-05`: the model data against the frozen text, and the evaluator over it.

Design basis: AP-11 §4 (`SV11-1`…`SV11-12`), §16 (`GP-AUTO-ST-05`); AP-04 §3–§12, §17; the
AP-04 bounded-cycle amendment §3.1–§3.6; AP-03 `AP03-I12`.

Three kinds of evidence, kept apart.

* **Transcription** (`SV11-12`, `SV11-1a`): each edge's *From → To* is parsed out of its
  frozen row and compared with the model, and each condition's quoted fragment is found in
  the frozen row it cites. The frozen artifacts are digest-verified first.
* **Generated behaviour** (`SV11-1`, `SV11-2`, `SV11-3`): every legal pair is admitted under
  a satisfying fact set; every illegal pair is refused under any facts; every condition,
  alone, decides its guard — checked against a small independent oracle, over a snapshot
  of the model taken before any mutation substitutes it.
* **Named properties**: terminality, `AP03-I12`, `EPOCH_HALTED`, the prefix, the four cycle
  cases, the joint resumption, and the absence of time, order, authorship and count.
"""

from __future__ import annotations

import ast
import itertools
import re
from pathlib import Path

import pytest

from gpauto import state_machine as sm
from gpauto import state_machine_model as model
from gpauto.absence import KnownAbsent, Present
from gpauto.coordination_identity import CycleOccurrenceId, HaltOccurrenceId
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
from gpauto.minting import mint_value
from gpauto.vocabulary import AuthorizationDisposition, OwnerDecisionKind
from traceability import AP04_CYCLE_PATH, AP04_CYCLE_SHA256, AP04_PATH, AP04_SHA256, verified_text

GPAUTO_STAGE = "GP-AUTO-ST-05"

SNAPSHOT: tuple[model.EdgeRule, ...] = model.EDGES
"""The model as imported, before any mutant substitutes the table the evaluator reads."""

INDETERMINATE = model.INDETERMINATE
FROZEN_EDGES = {
    *(f"A{n}" for n in range(1, 5)),
    *(f"B{n}" for n in (1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 15)),
    "B6a",
    "B6b",
    *(f"C{n}" for n in range(1, 7)),
    *(f"G{n}" for n in range(1, 7)),
}


# --- helpers: satisfying facts and an independent oracle ------------------------------------


def _value(facts: sm.Facts, fact: model.Fact) -> str:
    value = facts.get(fact.name, INDETERMINATE)
    return value if value in fact.values else INDETERMINATE


def _holds(conditions: tuple[model.Condition, ...], facts: sm.Facts) -> bool:
    return all(_value(facts, c.fact) in c.admitted for c in conditions)


def oracle(rule: model.EdgeRule, facts: sm.Facts) -> bool:
    """Admissibility read straight off the frozen shape, sharing no code with `sm`."""
    guard = rule.guard
    if isinstance(guard, model.Conjunctive):
        return any(_holds(alternative, facts) for alternative in guard.alternatives)
    if not (_holds(guard.own, facts) and _holds(guard.tier0, facts)):
        return False
    if any(_value(facts, c.fact) == INDETERMINATE for c in guard.tier1):
        return False
    return _holds(guard.tier1, facts) == guard.tier1_holds


def satisfying(conditions: tuple[model.Condition, ...]) -> sm.Facts:
    return {c.fact.name: c.admitted[0] for c in conditions}


HALT = HaltOccurrenceId(value=mint_value())
"""The one halt occurrence `B13`'s generated facts are read for, and restorations name."""


def bases(rule: model.EdgeRule) -> list[tuple[tuple[model.Condition, ...], sm.Facts]]:
    """Each way the guard can hold, with the facts that make it hold that way — for `B13`,
    bound to `HALT`, the halt occurrence those facts were read for (`SV11-6`)."""
    guard = rule.guard
    if isinstance(guard, model.Conjunctive):
        bound = (
            {sm.NAMED_HALT: HALT.value} if isinstance(rule.target, model.RestoredPosition) else {}
        )
        return [
            (alternative, {**satisfying(alternative), **bound})
            for alternative in guard.alternatives
        ]
    fixed = satisfying((*guard.own, *guard.tier0))
    if guard.tier1_holds:
        return [((*guard.own, *guard.tier0, *guard.tier1), {**fixed, **satisfying(guard.tier1)})]
    found = []
    for designated in guard.tier1:
        tier1 = {c.fact.name: model.TRUE for c in guard.tier1}
        tier1[designated.fact.name] = model.FALSE
        found.append(((*guard.own, *guard.tier0, *guard.tier1), {**fixed, **tier1}))
    return found


def rule_of(edge: model.EdgeName) -> model.EdgeRule:
    (rule,) = [r for r in SNAPSHOT if r.edge == edge]
    return rule


def restoration(
    position: M2Position, cycle: CycleOccurrenceId | None = None, halt: HaltOccurrenceId = HALT
) -> sm.Restoration:
    """A halt occurrence as recorded (`HB-1` as restated): its source position and, at
    `S6`/`S7`, its cycle occurrence — `KnownAbsent` elsewhere."""
    if position in sm.CYCLIC and cycle is None:
        cycle = CycleOccurrenceId(value=mint_value())
    recorded = (
        Present[CycleOccurrenceId](value=cycle)
        if cycle is not None
        else KnownAbsent(basis="no cycle occurrence off S6/S7")
    )
    return sm.Restoration(halt, position, recorded)


def restoring(rule: model.EdgeRule, facts: sm.Facts) -> sm.Restoration | None:
    """For `B13`, the recorded restoration agreeing with the guard's restored position —
    whatever position that is, so the guard alone decides whether it is restorable."""
    value = facts.get(model.RESTORED_POSITION.name, INDETERMINATE)
    if not isinstance(rule.target, model.RestoredPosition) or value not in set(M2Position):
        return None
    return restoration(M2Position(value))


# --- transcription against the frozen text -------------------------------------------------


def _normalized(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("`", "").replace("*", "")).strip()


def _artifact_lines(artifact: str) -> list[str]:
    path, digest = {
        model.AP04: (AP04_PATH, AP04_SHA256),
        model.CYCLE: (AP04_CYCLE_PATH, AP04_CYCLE_SHA256),
    }[artifact]
    return [_normalized(line) for line in verified_text(path, digest).splitlines()]


def frozen_row(row: model.Row) -> str:
    prefix = _normalized(row.prefix)
    found = [line for line in _artifact_lines(row.artifact) if line.startswith(prefix)]
    assert len(found) == 1, (row, len(found))
    return found[0]


def _parse_end(token: str, machine: Machine) -> tuple[object, ...]:
    token = token.strip()
    if token == "(entry)" or (machine == Machine.M2 and token.startswith("M1 ")):
        return (
            {Machine.M1: model.M1_ENTRY, Machine.M2: model.M2_ENTRY}.get(machine, model.M3_ENTRY),
        )
    if token == "(any of S1…S8)":
        return model.HALTABLE
    if token == "(any non-terminal)":
        return model.NON_TERMINAL
    if token == "(the state it halted from)":
        return (model.RESTORED,)
    numbered = re.match(r"^S(\d+)\b", token)
    if numbered:
        (position,) = [p for p in M2Position if p.value.startswith(f"S{numbered[1]}_")]
        return (position,)
    vocabulary = {
        Machine.M1: M1Position,
        Machine.M3: M3Position,
        Machine.M4: AuthorizationDisposition,
    }[machine]
    return (vocabulary(token),)


@pytest.mark.traces(
    "ST05-C1",
    "ST05-D1",
    "A1",
    "A2",
    "A3",
    "A4",
    "B1",
    "B2",
    "B3",
    "B4",
    "B5",
    "B6a",
    "B6b",
    "B7",
    "B8",
    "B9",
    "B10",
    "B11",
    "B12",
    "B13",
    "B15",
    "C1",
    "C2",
    "C3",
    "C4",
    "C5",
    "C6",
    "G1",
    "G2",
    "G3",
    "G4",
    "G5",
    "G6",
)
def test_every_edge_transcribes_its_frozen_row() -> None:
    """`SV11-12`: each edge's *From → To* cell, parsed from its digest-verified frozen row
    (the amendment's for `B8` and `B15`), is exactly the model's sources and target."""
    for rule in SNAPSHOT:
        row = frozen_row(rule.row)
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        assert cells[0] == str(rule.edge), rule.edge
        left, right = cells[1].split("→")
        assert set(_parse_end(left, rule.machine)) == set(rule.sources), rule.edge
        assert _parse_end(right, rule.machine) == (rule.target,), rule.edge


@pytest.mark.traces("ST05-C1", "ST05-D1", "ST05-A1")
def test_every_condition_quotes_the_frozen_row_it_cites() -> None:
    """Each guard condition's fragment is found verbatim, once `*` and backticks are removed,
    in the one frozen row it cites — the edge's own row, a §11 standing-guard row, an
    `RP-*`/`CP-*`/`HB-*` row, or the amendment's `CE-*` row."""
    for rule in SNAPSHOT:
        for condition in sm.guard_conditions(rule.guard):
            row = frozen_row(condition.row)
            assert _normalized(condition.quote) in row, (rule.edge, condition.identifier)
            assert set(condition.admitted) <= set(condition.fact.values), condition.identifier
            assert INDETERMINATE not in condition.admitted, condition.identifier


@pytest.mark.supports("AP04-I30")
@pytest.mark.traces("ST05-D1", "ST05-C1", "AP04-I26")
def test_the_edge_set_is_exactly_the_frozen_set_and_b14_does_not_exist() -> None:
    """`A1`…`A4`, `B1`…`B13` with `B6a`/`B6b` and no `B6`, `B15`, `C1`…`C6`, `G1`…`G6` — one
    rule each. `B14` is not an edge, not a name the vocabulary has, and not modelled
    (`D-AP04-02(b)`); no state name reuses a GP-SPK-001 scope semantic (§13)."""
    edges = [str(rule.edge) for rule in SNAPSHOT]
    assert sorted(edges) == sorted(FROZEN_EDGES)
    assert "B14" not in {e.value for e in M2Edge}
    assert "B14" not in edges
    names = {str(p) for _, positions in model.POSITIONS for p in positions}
    for token in ("SCOPE", "DRAFTING", "REVIEW_PENDING", "APPROVED"):
        assert not [n for n in names if token in n], token


# --- generated behaviour -----------------------------------------------------------------------


@pytest.mark.traces(
    "ST05-T1",
    "ST05-D2",
    "A1",
    "A2",
    "A3",
    "A4",
    "B1",
    "B2",
    "B3",
    "B4",
    "B5",
    "B6a",
    "B6b",
    "B7",
    "B8",
    "B9",
    "B10",
    "B11",
    "B12",
    "B13",
    "B15",
    "C1",
    "C2",
    "C3",
    "C4",
    "C5",
    "C6",
    "G1",
    "G2",
    "G3",
    "G4",
    "G5",
    "G6",
)
def test_every_legal_transition_is_admissible_under_its_guard() -> None:
    """Every legal (position, edge) cell of the generated matrix, under each way its guard
    can hold, is admitted to exactly the frozen target — `B13` to each recorded source."""
    for cell in sm.conformance_matrix():
        if not cell.legal:
            continue
        rule = rule_of(cell.edge)
        for _, facts in bases(rule):
            restored = restoring(rule, facts)
            found = sm.evaluate(cell.edge, cell.source, facts, restored)
            assert isinstance(found, sm.Admitted), (cell.edge, cell.source, found)
            if isinstance(rule.target, model.RestoredPosition):
                assert found.target == M2Position(facts[model.RESTORED_POSITION.name])
                assert found.restored == restored
            else:
                assert found.target == rule.target and found.restored is None
    for position in model.HALTABLE:
        rule = rule_of(M2Edge.B13)
        facts = {**bases(rule)[0][1], model.RESTORED_POSITION.name: position.value}
        found = sm.evaluate(M2Edge.B13, M2Position.S9_EPOCH_HALTED, facts, restoration(position))
        assert isinstance(found, sm.Admitted) and found.target == position


def _every_satisfying_fact() -> sm.Facts:
    facts: sm.Facts = {}
    for rule in SNAPSHOT:
        facts.update(bases(rule)[0][1])
    return facts


@pytest.mark.traces("ST05-N1", "ST05-A2", "AP04-I21")
def test_every_illegal_pair_is_refused_under_any_facts() -> None:
    """`SV11-2`: every illegal cell is refused as inexpressible — under no facts, and under
    facts that satisfy the edge's own guard — and a refusal names no target."""
    for cell in sm.conformance_matrix():
        if cell.legal:
            continue
        for facts in ({}, *(f for _, f in bases(rule_of(cell.edge))), _every_satisfying_fact()):
            found = sm.evaluate(cell.edge, cell.source, facts)
            assert isinstance(found, sm.Refused), (cell.edge, cell.source)
            assert found.stratum == sm.NO_EDGE and found.unmet == ()
            assert not hasattr(found, "target")


@pytest.mark.traces(
    "ST05-M1", "ST05-M2", "ST05-D2",
    "RP-1", "RP-2", "RP-3", "RP-4", "RP-5", "RP-6", "RP-7",
    "CP-1", "CP-2", "CP-3", "CP-4", "CP-5",
    "CE-0a", "CE-0b", "CE-0c", "CE-0d", "CE-1", "CE-2", "CE-3", "CE-4", "CE-5", "CE-6",
)  # fmt: skip
def test_every_condition_is_individually_falsifiable() -> None:
    """`SV11-3`: for every way each guard can hold, each of its conditions — every `RP-*`,
    `CE-*` and `CP-*` included — is set, alone, to each value it does not admit and to
    `INDETERMINATE`, and the evaluator agrees with the oracle every time; and at least one
    such value refuses the edge. Conditions come from the pre-mutation snapshot, so a
    condition removed from the evaluated model cannot escape this test."""
    for rule in SNAPSHOT:
        source = rule.sources[0]
        for conditions, base in bases(rule):
            restored = restoring(rule, base)
            assert oracle(rule, base), rule.edge
            assert isinstance(sm.evaluate(rule.edge, source, base, restored), sm.Admitted)
            for condition in conditions:
                assert set(condition.admitted) < set(condition.fact.values), condition.identifier
                others = [v for v in condition.fact.values if v not in condition.admitted]
                refused_once = False
                for value in (*others, INDETERMINATE):
                    facts = {**base, condition.fact.name: value}
                    expected = oracle(rule, facts)
                    found = sm.evaluate(rule.edge, source, facts, restoring(rule, facts))
                    assert isinstance(found, sm.Admitted) == expected, (
                        rule.edge,
                        condition.identifier,
                        value,
                    )
                    refused_once = refused_once or not expected
                if isinstance(rule.guard, model.Stratified) and not rule.guard.tier1_holds:
                    if condition in rule.guard.tier1 and base[condition.fact.name] == model.FALSE:
                        # B8's decisive Tier-1 condition: true makes Tier 1 hold (B15's),
                        # which refuses B8 — the flip that makes it decisive.
                        facts = {**base, condition.fact.name: model.TRUE}
                        assert isinstance(sm.evaluate(rule.edge, source, facts), sm.Refused)
                        refused_once = True
                    elif condition in rule.guard.tier1:
                        continue  # not the decisive one in this base
                assert refused_once, (rule.edge, condition.identifier)


@pytest.mark.traces("ST05-D2", "ST05-N5")
def test_a_value_outside_its_domain_is_indeterminate() -> None:
    """`P-04`: a supplied value outside its fact's closed domain is `INDETERMINATE`, so in
    Tier 1 it admits neither `B8` nor `B15`, and elsewhere it satisfies nothing."""
    base = {**bases(rule_of(M2Edge.B15))[0][1], **satisfying(rule_of(M2Edge.B8).guard.own)}  # type: ignore[union-attr]
    facts = {**base, model.CE_6.name: "EXHAUSTED_PERHAPS"}
    for edge in (M2Edge.B8, M2Edge.B15):
        found = sm.evaluate(edge, M2Position.S7_CLOSURE_ACTIVE, facts)
        assert isinstance(found, sm.Refused) and found.stratum == sm.TIER_1_INDETERMINATE
    assert sm.fact_value({model.M4_LIVE.name: "true"}, model.M4_LIVE) == INDETERMINATE
    facts = {model.TRIGGER.name: "coordinator", model.ELIGIBLE_MULTIPLICITY.name: "ZERO"}
    assert isinstance(sm.evaluate(M1Edge.A3, M1Position.RESOLUTION_OPEN, facts), sm.Refused)


# --- the stratified cycle predicate -----------------------------------------------------------


def _cycle_facts(tier0: dict[str, str], tier1: dict[str, str]) -> sm.Facts:
    own = {
        **satisfying(rule_of(M2Edge.B8).guard.own),  # type: ignore[union-attr]
        **satisfying(rule_of(M2Edge.B15).guard.own),  # type: ignore[union-attr]
    }
    return {
        **own,
        **{c.fact.name: model.TRUE for c in model.TIER_0},
        **tier0,
        **{c.fact.name: model.TRUE for c in model.TIER_1},
        **tier1,
    }


def _at_s7(facts: sm.Facts) -> tuple[sm.Evaluation, sm.Evaluation]:
    s7 = M2Position.S7_CLOSURE_ACTIVE
    return sm.evaluate(M2Edge.B8, s7, facts), sm.evaluate(M2Edge.B15, s7, facts)


@pytest.mark.supports("AP04-I45", "AP04-I47")
@pytest.mark.traces(
    "ST05-T4", "CE-T1", "CE-T2", "CE-T3", "B8", "B15",
    "AP04-I42", "AP04-I43", "AP04-I44", "AP04-I46", "AP04-I06",
)  # fmt: skip
def test_the_stratified_cycle_predicate_in_all_four_cases() -> None:
    """`SV11-4`, `BC-12`: (i) Tier 0 fails or is indeterminate — neither edge, the refusal
    stops at Tier 0 even though Tier 1 is false (never `B8`); (ii) Tier 1 true — `B15`
    only; (iii) Tier 1 determinately false, an exhausted budget included — `B8` only;
    (iv) Tier 1 indeterminate, alone or beside a false condition — neither."""
    all_false = {c.fact.name: model.FALSE for c in model.TIER_1}
    for condition in model.TIER_0:
        for value in (model.FALSE, INDETERMINATE):
            b8, b15 = _at_s7(_cycle_facts({condition.fact.name: value}, all_false))
            for found in (b8, b15):
                assert isinstance(found, sm.Refused) and found.stratum == sm.TIER_0
    b8, b15 = _at_s7(_cycle_facts({}, {}))
    assert isinstance(b15, sm.Admitted) and b15.target == M2Position.S6_REMEDIATION_ACTIVE
    assert isinstance(b8, sm.Refused) and b8.stratum == sm.TIER_1_OTHER_EDGE
    for condition in model.TIER_1:
        b8, b15 = _at_s7(_cycle_facts({}, {condition.fact.name: model.FALSE}))
        assert isinstance(b8, sm.Admitted) and b8.target == M2Position.S8_GATE_REACHED
        assert isinstance(b15, sm.Refused) and b15.stratum == sm.TIER_1_OTHER_EDGE
        b8, b15 = _at_s7(_cycle_facts({}, {condition.fact.name: INDETERMINATE}))
        for found in (b8, b15):
            assert isinstance(found, sm.Refused) and found.stratum == sm.TIER_1_INDETERMINATE
    b8, _ = _at_s7(_cycle_facts({}, all_false))
    assert isinstance(b8, sm.Admitted)
    others = [c for c in model.TIER_1 if c is not model.CE_6_C]
    mixed = {others[0].fact.name: INDETERMINATE, others[1].fact.name: model.FALSE}
    for found in _at_s7(_cycle_facts({}, mixed)):
        assert isinstance(found, sm.Refused) and found.stratum == sm.TIER_1_INDETERMINATE
    # AP04-I47's routing: exhausted budget -> B8; unavailable budget -> neither.
    b8, b15 = _at_s7(_cycle_facts({}, {model.CE_6.name: model.FALSE}))
    assert isinstance(b8, sm.Admitted) and isinstance(b15, sm.Refused)
    unavailable = _cycle_facts({}, {})
    del unavailable[model.CE_6.name]
    assert all(isinstance(found, sm.Refused) for found in _at_s7(unavailable))


@pytest.mark.traces("AP04-I06", "AP04-I44", "AP04-I05", "AP04-I10", "A2", "A3", "A4", "B6a", "B6b")
def test_no_two_edges_of_a_partition_are_ever_both_admissible() -> None:
    """`AP04-I06`: the machine never chooses. Over every combination of the deciding facts,
    at most one of `A2`/`A3`/`A4`, of `B6a`/`B6b` and of `B8`/`B15` is admissible — and
    `ROOT_CONTESTED` is reachable in both ambiguity forms (`AP04-I05`, `M1-6`)."""
    reached: set[model.Position] = set()
    for multiplicity, consistent in itertools.product(
        (*model.ELIGIBLE_MULTIPLICITY.values, INDETERMINATE), (*model.BOOLEAN, INDETERMINATE)
    ):
        facts = {
            model.TRIGGER.name: model.COORDINATOR,
            model.ELIGIBLE_MULTIPLICITY.name: multiplicity,
            model.IDENTITY_RECORDS_CONSISTENT.name: consistent,
        }
        found = sm.admissible_edges(Machine.M1, M1Position.RESOLUTION_OPEN, facts)
        assert len(found) <= 1, facts
        reached |= {a.target for a in found}
        if model.INDETERMINATE in (multiplicity,):
            assert not found
    assert reached == {M1Position.ROOT_RESOLVED, M1Position.ROOT_ABSENT, M1Position.ROOT_CONTESTED}
    branch = {**bases(rule_of(M2Edge.B6a))[0][1], **bases(rule_of(M2Edge.B6b))[0][1]}
    for empty in (*model.BOOLEAN, INDETERMINATE):
        facts = {**branch, model.MEMBERSHIP_EMPTY.name: empty}
        found = sm.admissible_edges(Machine.M2, M2Position.S5_FINDING_SET_FROZEN, facts)
        assert len(found) == (0 if empty == INDETERMINATE else 1)
    for values in itertools.product((*model.BOOLEAN, INDETERMINATE), repeat=len(model.TIER_1)):
        tier1 = {c.fact.name: v for c, v in zip(model.TIER_1, values, strict=True)}
        admitted = [f for f in _at_s7(_cycle_facts({}, tier1)) if isinstance(f, sm.Admitted)]
        assert len(admitted) == (0 if INDETERMINATE in values else 1)


@pytest.mark.supports("AP04-I12")
@pytest.mark.traces("AP04-I10", "AP04-I11", "B6a", "B6b")
def test_branch_selection_is_emptiness_of_membership_and_nothing_else() -> None:
    """`M2-5`: `MEMBERSHIP_EMPTY` is the only fact on which `B6a` and `B6b` require
    different values, and neither edge crosses a gate: `B6a` leaves for a step, triggered
    by the coordinator, and findings existing couples no M4 edge (`AP04-I11`)."""
    b6a = {c.fact.name: set(c.admitted) for c in sm.guard_conditions(rule_of(M2Edge.B6a).guard)}
    b6b = {c.fact.name: set(c.admitted) for c in sm.guard_conditions(rule_of(M2Edge.B6b).guard)}
    differing = {name for name in b6a.keys() & b6b.keys() if b6a[name] != b6b[name]}
    assert differing == {model.MEMBERSHIP_EMPTY.name}
    assert rule_of(M2Edge.B6a).target == M2Position.S6_REMEDIATION_ACTIVE
    assert b6a[model.TRIGGER.name] == {model.COORDINATOR}
    assert M2Edge.B6a not in {c.m2 for c in model.COUPLED}


@pytest.mark.traces("AP04-I37", "B7")
def test_b7_states_the_closure_verifiers_own_guards() -> None:
    """`BG-1`…`BG-4`: `B7` requires read-only with `E-12` absent, `E-14` and `E-20`, and a
    new identity; it inherits no REMEDIATOR write bound."""
    facts = {c.fact for c in sm.guard_conditions(rule_of(M2Edge.B7).guard)}
    for required in (
        model.READ_ONLY_WITHOUT_WRITE_BOUNDARY,
        model.E14_REFERENCES_FROZEN_SET,
        model.E20_DESIGNATES_INPUTS,
        model.NEW_ENVELOPE_IDENTITY,
    ):
        assert required in facts
    assert model.REMEDIATOR_BOUNDS not in facts


# --- structure: ordering, prefix, terminality ---------------------------------------------------


@pytest.mark.supports("AP04-I31")
@pytest.mark.traces("AP04-I01", "AP04-I02", "AP04-I20", "AP04-I18", "ST05-D1")
def test_ordered_establishment_each_position_has_one_admitting_forward_edge() -> None:
    """`M2-1`, `AP04-I01`: `S1` only by `B1`, `S2` only by `B2` (from `S1`), `S3` by `B3`, `S4`
    by `B4`, `S5` by `B5` — apart from `B13` restoring a position the epoch already held.
    `RESOLUTION_OPEN` is entered only by `A1` from no position, so there is no
    re-resolution edge (`AP04-I02`); the boundary is fixed by `B2` alone, which needs no
    boundary to exist (`AP04-I20`); and no edge leaves `S10`/`S11` for anything (`AP04-I18`)."""
    expected = {
        M2Position.S1_EPOCH_OPENED: M2Edge.B1,
        M2Position.S2_ENTRY_BOUNDARY_FIXED: M2Edge.B2,
        M2Position.S3_IMPLEMENTATION_ACTIVE: M2Edge.B3,
        M2Position.S4_DISCOVERY_ACTIVE: M2Edge.B4,
        M2Position.S5_FINDING_SET_FROZEN: M2Edge.B5,
    }
    for state, edge in expected.items():
        admitting = {r.edge for r in SNAPSHOT if r.target == state}
        assert admitting == {edge}, state
    assert {r.edge for r in SNAPSHOT if r.target == M1Position.RESOLUTION_OPEN} == {M1Edge.A1}
    assert rule_of(M1Edge.A1).sources == (model.M1_ENTRY,)
    b2 = {c.fact for c in sm.guard_conditions(rule_of(M2Edge.B2).guard)}
    assert model.NO_BOUNDARY_FOR_ROOT in b2
    assert not [r for r in SNAPSHOT if model.M2_ENTRY in r.sources and r.edge != M2Edge.B1]


@pytest.mark.traces("ST05-N3", "ST05-N4", "AP04-I09", "AP04-I24", "AP04-I42", "B15")
def test_no_self_loop_and_the_prefix_is_never_reentered() -> None:
    """`AP04-I09` as restated (§3.5.1) and `AP04-I24` as restated (§3.5.10): no rule leaves a
    position for itself; no edge from `S6`, `S7` or `S8` reaches `S1`…`S5`; over the prefix
    every step edge advances; the only step edge to an earlier step is `B15`, to `S6`
    only, fired on a completed and adopted closure (`CE-0a`) — never on a failure; and
    `B13` is the OWNER's alone."""
    order = {p: i for i, p in enumerate(M2Position)}
    for rule in SNAPSHOT:
        assert rule.target not in rule.sources, rule.edge
        if set(rule.sources) & model.SUFFIX:
            assert rule.target not in model.PREFIX, rule.edge
    backward = [
        r.edge
        for r in SNAPSHOT
        if r.machine == Machine.M2
        and isinstance(r.target, M2Position)
        and r.target in model.PROGRESSING
        and any(isinstance(s, M2Position) and order[r.target] < order[s] for s in r.sources)
    ]
    assert backward == [M2Edge.B15]
    b15 = rule_of(M2Edge.B15).guard
    assert isinstance(b15, model.Stratified) and model.CE_0A_C in b15.tier0
    b13 = {c.fact.name: c.admitted for c in sm.guard_conditions(rule_of(M2Edge.B13).guard)}
    assert b13[model.TRIGGER.name] == (OwnerDecisionKind.REFUSAL_RESOLUTION.value,)


@pytest.mark.supports("AP04-I35")
@pytest.mark.traces("ST05-N2", "AP04-I16", "AP04-I04", "AP03-I12")
def test_terminal_positions_have_no_lawful_outgoing_edge() -> None:
    """`SV11-7`, `TM-1`, `AP04-I16`: the seven frozen terminals — named in the frozen
    `TM-1` row — and the two M1 halts (`AP04-I04`) leave by no rule, and every edge from
    them is refused under any facts."""
    tm1 = frozen_row(model.Row(model.AP04, "| TM-1 |"))
    for terminal in model.TERMINAL:
        assert not isinstance(terminal, model.Entry)
        name = (
            terminal.value.split("_", 1)[1] if isinstance(terminal, M2Position) else terminal.value
        )
        assert name in tm1, name
    every = _every_satisfying_fact()
    for position in model.TERMINAL | model.M1_HALTS:
        assert not [r for r in SNAPSHOT if position in r.sources], position
        for rule in SNAPSHOT:
            found = sm.evaluate(rule.edge, position, every)
            assert isinstance(found, sm.Refused) and found.stratum == sm.NO_EDGE


# --- AP03-I12: one envelope identity, one activation --------------------------------------------


@pytest.mark.traces("AP03-I12", "AP04-I17", "C2")
def test_one_envelope_identity_permits_exactly_one_activation() -> None:
    """`AP03-I12`(1): `ACTIVATION_RUNNING` is entered by `C2` alone, from
    `ENVELOPE_DERIVED` alone, and only under `V-13`'s never-activated condition; the
    envelope reaches `ENVELOPE_DERIVED` only by `C1`, from no position."""
    into_running = [r for r in SNAPSHOT if r.target == M3Position.ACTIVATION_RUNNING]
    assert [(r.edge, r.sources) for r in into_running] == [
        (M3Edge.C2, (M3Position.ENVELOPE_DERIVED,))
    ]
    into_derived = [r for r in SNAPSHOT if r.target == M3Position.ENVELOPE_DERIVED]
    assert [(r.edge, r.sources) for r in into_derived] == [(M3Edge.C1, (model.M3_ENTRY,))]
    c2 = {c.fact for c in sm.guard_conditions(rule_of(M3Edge.C2).guard)}
    assert model.ENVELOPE_NEVER_ACTIVATED in c2


@pytest.mark.traces("AP03-I12", "AP04-I17", "C2")
def test_a_second_activation_of_one_identity_is_refused() -> None:
    """`AP03-I12`(2): once activated the envelope is past `ENVELOPE_DERIVED`, and from every
    later position `C2` is inexpressible whatever the facts; at `ENVELOPE_DERIVED` an
    identity already activated fails `C2-2`."""
    every = _every_satisfying_fact()
    for position in (
        M3Position.ACTIVATION_RUNNING,
        M3Position.ACTIVATION_COMPLETED,
        M3Position.ACTIVATION_CLOSED_UNADOPTED,
        M3Position.ENVELOPE_VOIDED,
    ):
        found = sm.evaluate(M3Edge.C2, position, every)
        assert isinstance(found, sm.Refused) and found.stratum == sm.NO_EDGE
    facts = {**bases(rule_of(M3Edge.C2))[0][1], model.ENVELOPE_NEVER_ACTIVATED.name: model.FALSE}
    found = sm.evaluate(M3Edge.C2, M3Position.ENVELOPE_DERIVED, facts)
    assert isinstance(found, sm.Refused)
    assert [u.condition for u in found.unmet] == ["C2-2"]


@pytest.mark.traces("AP03-I12", "AP04-I16", "AP04-I24", "C4", "C5", "C6", "C3")
def test_a_consumed_identity_is_terminal_and_nothing_revives_it() -> None:
    """`AP03-I12`(3)–(5), `CN-1`: completed, closed-unadopted and voided are terminal; no
    edge returns to `ENVELOPE_DERIVED` or `ACTIVATION_RUNNING`; and no revive, reset,
    reopen or reuse exists — no edge, no function, no name in either ST-05 module."""
    for position in (
        M3Position.ACTIVATION_COMPLETED,
        M3Position.ACTIVATION_CLOSED_UNADOPTED,
        M3Position.ENVELOPE_VOIDED,
    ):
        assert position in model.TERMINAL
        assert not [r for r in SNAPSHOT if position in r.sources]
    for rule in SNAPSHOT:
        if rule.target in (M3Position.ENVELOPE_DERIVED, M3Position.ACTIVATION_RUNNING):
            assert not set(rule.sources) & model.TERMINAL
    for module in (sm, model):
        source = Path(module.__file__ or "").read_text(encoding="utf-8")
        names = {
            n.name if isinstance(n, ast.FunctionDef | ast.ClassDef) else n.id
            for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.FunctionDef | ast.ClassDef | ast.Name)
        }
        for word in ("revive", "reset", "reopen", "reuse", "retry", "rearm"):
            assert not [n for n in names if word in n.lower()], (module.__name__, word)


# --- gates and halts -----------------------------------------------------------------------------


@pytest.mark.traces("ST05-N6", "AP04-I13", "AP04-I33", "B9", "B11", "B12", "B13")
def test_epoch_halted_has_no_component_triggered_exit() -> None:
    """`M2-12`, `AP04-I13`: `EPOCH_HALTED` is left by exactly `B11`, `B12`, `B13`, each only
    on an `OwnerDecision`; with every other fact satisfied and the coordinator as trigger,
    nothing is admissible from `S9`. From `GATE_REACHED` the one coordinator edge is the
    safety halt `B9` into `S9` (`AP04-I33`); `B10` and `B12` are the OWNER's."""
    halted = M2Position.S9_EPOCH_HALTED
    exits = {r.edge for r in SNAPSHOT if halted in r.sources}
    assert exits == {M2Edge.B11, M2Edge.B12, M2Edge.B13}
    owner_kinds = {k.value for k in OwnerDecisionKind}
    for edge in exits:
        for condition in sm.guard_conditions(rule_of(edge).guard):
            if condition.fact is model.TRIGGER:
                assert set(condition.admitted) <= owner_kinds, edge
    every = _every_satisfying_fact()
    for trigger in (model.COORDINATOR, model.STAGE_ENTRY_ATTEMPT):
        facts = {**every, model.TRIGGER.name: trigger}
        assert sm.admissible_edges(Machine.M2, halted, facts) == frozenset()
        suspended = AuthorizationDisposition.SUSPENDED
        assert sm.admissible_edges(Machine.M4, suspended, facts) == frozenset()
    gate = M2Position.S8_GATE_REACHED
    facts = {**every, model.TRIGGER.name: model.COORDINATOR}
    assert {a.edge for a in sm.admissible_edges(Machine.M2, gate, facts)} == {M2Edge.B9}
    assert rule_of(M2Edge.B9).target == halted


@pytest.mark.traces("AP04-I14", "AP04-I15", "B10", "B11", "G2", "G3", "G4", "G5", "G1")
def test_only_an_owner_decision_settles_and_arrival_couples_nothing() -> None:
    """`AP04-I15`, `AP04-I14`: the only edges into `S10`/`CONSUMED` are triggered by a
    `STAGE_OUTCOME` decision and move together (`K-3`); arriving at the gate (`B6b`, `B8`)
    couples no M4 edge; `B9` couples `G1` to `SUSPENDED`, never to `CONSUMED`; revocation
    is the OWNER's; and `B11` admits only refused, abandoned or accept-partial."""
    settling = [
        r
        for r in SNAPSHOT
        if r.target in (M2Position.S10_EPOCH_SETTLED, AuthorizationDisposition.CONSUMED)
    ]
    for rule in settling:
        triggers = [c for c in sm.guard_conditions(rule.guard) if c.fact is model.TRIGGER]
        assert [c.admitted for c in triggers] == [model.OWNER_STAGE_OUTCOME], rule.edge
    coupled = {c.m2: c for c in model.COUPLED}
    assert coupled[M2Edge.B10].m4 == (M4Edge.G2,) and coupled[M2Edge.B11].m4 == (M4Edge.G3,)
    assert coupled[M2Edge.B9].m4 == (M4Edge.G1,)
    assert M2Edge.B6b not in coupled and M2Edge.B8 not in coupled
    for edge in (M4Edge.G4, M4Edge.G5):
        (trigger,) = sm.guard_conditions(rule_of(edge).guard)
        assert trigger.admitted == model.OWNER_REVOCATION
    b11 = {c.fact.name: c.admitted for c in sm.guard_conditions(rule_of(M2Edge.B11).guard)}
    assert set(b11[model.STAGE_OUTCOME_VALUE.name]) == {"REFUSED", "ABANDONED", "ACCEPT_PARTIAL"}


@pytest.mark.traces(
    "AP04-I29", "AP04-I39", "AP04-I40", "B13", "G6", "K-9", "RP-1", "RP-6", "ST05-D3",
)  # fmt: skip
def test_b13_and_g6_fire_together_or_not_at_all() -> None:
    """`K-9`, `AP04-I29`: under one refusal-resolution decision and one evaluation of
    `RP-1`…`RP-7`, `B13` returns the epoch to the named occurrence's recorded source and
    `G6` returns the instance to `LIVE` — together. Where `G6` cannot move (the instance is
    not `SUSPENDED`), `B13` does not move either; any `RP-*` or `HB-*` condition failing
    refuses both. The shared predicate reads no role (`AP04-I40`)."""
    rule = rule_of(M2Edge.B13)
    facts = {**bases(rule)[0][1], model.RESTORED_POSITION.name: "S4_DISCOVERY_ACTIVE"}
    restored = restoration(M2Position.S4_DISCOVERY_ACTIVE)
    act = sm.evaluate_act(
        M2Edge.B13, M2Position.S9_EPOCH_HALTED, AuthorizationDisposition.SUSPENDED, facts, restored
    )
    assert isinstance(act, sm.Act)
    assert act.m2.target == M2Position.S4_DISCOVERY_ACTIVE and act.m2.restored == restored
    assert act.m4 == sm.Admitted(
        M4Edge.G6, AuthorizationDisposition.SUSPENDED, AuthorizationDisposition.LIVE
    )
    split = sm.evaluate_act(
        M2Edge.B13, M2Position.S9_EPOCH_HALTED, AuthorizationDisposition.LIVE, facts, restored
    )
    assert isinstance(split, sm.Refused) and split.stratum == sm.COUPLED_EDGE
    for condition in (*model.RESUMPTION_PREDICATE, *sm.guard_conditions(rule.guard)):
        if condition.fact is model.RESTORED_POSITION:
            continue
        failing = {**facts, condition.fact.name: INDETERMINATE}
        assert isinstance(
            sm.evaluate_act(
                M2Edge.B13,
                M2Position.S9_EPOCH_HALTED,
                AuthorizationDisposition.SUSPENDED,
                failing,
                restored,
            ),
            sm.Refused,
        ), condition.identifier
    unbound = sm.evaluate_act(
        M2Edge.B13, M2Position.S9_EPOCH_HALTED, AuthorizationDisposition.SUSPENDED, facts
    )
    assert isinstance(unbound, sm.Refused) and unbound.stratum == sm.RESTORATION
    g6 = set(sm.guard_conditions(rule_of(M4Edge.G6).guard))
    assert set(model.RESUMPTION_PREDICATE) <= g6 and set(model.RESUMPTION_PREDICATE) <= set(
        sm.guard_conditions(rule.guard)
    )
    assert not [c for c in model.RESUMPTION_PREDICATE if "ROLE" in c.fact.name]
    assert sm.act_violations(M2Edge.B13, None)[0].invariant == "K-9"
    assert sm.act_violations(M2Edge.B13, M4Edge.G6) == ()
    to_s9 = {**facts, model.RESTORED_POSITION.name: "S9_EPOCH_HALTED"}
    assert isinstance(
        sm.evaluate_act(
            M2Edge.B13,
            M2Position.S9_EPOCH_HALTED,
            AuthorizationDisposition.SUSPENDED,
            to_s9,
            restoration(M2Position.S9_EPOCH_HALTED),
        ),
        sm.Refused,
    )


# --- ST05-IMPL-R01 … R03: V-06 on C1, OP-8 on C2, HB-1 on B13 ---------------------------------


def _edges_reading(fact: model.Fact) -> set[str]:
    return {
        str(rule.edge)
        for rule in SNAPSHOT
        if [c for c in sm.guard_conditions(rule.guard) if c.fact is fact]
    }


@pytest.mark.traces("C1", "ST05-M1", "ST05-D1")
def test_c1_derives_no_envelope_over_an_unaccounted_mutation() -> None:
    """`ST05-IMPL-R01`, AP-04 §11 `V-06`: *before every derivation*. `C1` is the envelope
    derivation, so it is refused while an unaccounted mutation exists or is indeterminate,
    and admitted only when none exists and every other condition holds. The condition cites
    the `V-06` row, and the frozen placements are kept: the derivation edges, `B5` as `B4`,
    and `C3`'s voiding alternative — nothing else."""
    rule = rule_of(M3Edge.C1)
    (v06,) = [c for c in sm.guard_conditions(rule.guard) if c.fact is model.UNACCOUNTED_MUTATION]
    assert (v06.identifier, v06.admitted, v06.row) == ("C1-6", model.F, model.V06_ROW)
    (base,) = [facts for _, facts in bases(rule)]
    assert base[model.UNACCOUNTED_MUTATION.name] == model.FALSE
    admitted = sm.evaluate(M3Edge.C1, model.M3_ENTRY, base)
    assert admitted == sm.Admitted(M3Edge.C1, model.M3_ENTRY, M3Position.ENVELOPE_DERIVED)
    for value in (model.TRUE, INDETERMINATE):
        refused = sm.evaluate(M3Edge.C1, model.M3_ENTRY, {**base, v06.fact.name: value})
        assert isinstance(refused, sm.Refused) and refused.stratum == sm.GUARD
        assert refused.unmet == (sm.Unmet("C1-6", v06.fact.name, value),)
    (cell,) = [c for c in sm.conformance_matrix() if c.edge == M3Edge.C1 and c.legal]
    assert "C1-6" in cell.conditions
    assert _edges_reading(model.UNACCOUNTED_MUTATION) == {"B3", "B4", "B5", "B6a", "B7", "C1", "C3"}


@pytest.mark.supports("AP04-I49")
@pytest.mark.traces("C2", "AP03-I12", "ST05-M1", "ST05-D1")
def test_c2_dispatch_requires_the_admitted_obligation_set_to_be_cycle_bound() -> None:
    """`ST05-IMPL-R02`, amendment `OP-8`(i): `C2` refuses an activation whose admitted
    obligation set is not `CYCLE_BOUND` — unequal, or undetermined — and admits it when
    equal, or where the envelope carries no `E-14` reference and so admits no obligation
    set. Only `C2` reads the fact, and `AP03-I12`'s one-activation guard is unchanged."""
    rule = rule_of(M3Edge.C2)
    fact = model.ADMITTED_OBLIGATIONS_AGREE
    (op8,) = [c for c in sm.guard_conditions(rule.guard) if c.fact is fact]
    assert (op8.identifier, op8.row) == ("C2-8", model.OP8_ROW)
    assert op8.admitted == (model.EQUAL, model.NOT_APPLICABLE)
    (base,) = [facts for _, facts in bases(rule)]
    derived, running = M3Position.ENVELOPE_DERIVED, M3Position.ACTIVATION_RUNNING
    for value in (model.EQUAL, model.NOT_APPLICABLE):
        found = sm.evaluate(M3Edge.C2, derived, {**base, fact.name: value})
        assert found == sm.Admitted(M3Edge.C2, derived, running)
    for value in (model.UNEQUAL, INDETERMINATE):
        refused = sm.evaluate(M3Edge.C2, derived, {**base, fact.name: value})
        assert isinstance(refused, sm.Refused)
        assert refused.unmet == (sm.Unmet("C2-8", fact.name, value),)
    missing = {k: v for k, v in base.items() if k != fact.name}
    assert isinstance(sm.evaluate(M3Edge.C2, derived, missing), sm.Refused)
    assert _edges_reading(fact) == {"C2"}
    never = {**base, model.ENVELOPE_NEVER_ACTIVATED.name: model.FALSE}
    assert isinstance(sm.evaluate(M3Edge.C2, derived, never), sm.Refused)
    again = sm.evaluate(M3Edge.C2, running, base)
    assert isinstance(again, sm.Refused) and again.stratum == sm.NO_EDGE


@pytest.mark.traces("B13", "AP04-I39", "ST05-M1", "ST05-D2")
def test_b13_is_bound_to_the_named_halts_cycle_occurrence() -> None:
    """`ST05-IMPL-R03`, `HB-1` as restated, `SV11-6`: `B13`'s target is the recorded position
    **and that recorded cycle occurrence**. Two halts at `S6` in occurrences X and Y give two
    different admitted results with the same target; a binding that is not determinately
    consistent refuses; and a restoration that is absent, disagrees with the guard's
    position, or is for another halt than the facts name — or facts naming no halt —
    refuses, with nothing inferred."""
    rule = rule_of(M2Edge.B13)
    (bound,) = [
        c for c in sm.guard_conditions(rule.guard) if c.fact is model.RESTORED_OCCURRENCE_BOUND
    ]
    assert (bound.identifier, bound.admitted, bound.row) == (
        "B13-4",
        model.T,
        model.HB1_RESTATED_ROW,
    )
    s6, s9 = M2Position.S6_REMEDIATION_ACTIVE, M2Position.S9_EPOCH_HALTED
    facts = {**bases(rule)[0][1], model.RESTORED_POSITION.name: s6.value}
    x, y = CycleOccurrenceId(value=mint_value()), CycleOccurrenceId(value=mint_value())
    in_x, in_y = restoration(s6, x), restoration(s6, y)
    found_x = sm.evaluate(M2Edge.B13, s9, facts, in_x)
    found_y = sm.evaluate(M2Edge.B13, s9, facts, in_y)
    assert isinstance(found_x, sm.Admitted) and isinstance(found_y, sm.Admitted)
    assert found_x.target == found_y.target == s6
    assert found_x != found_y
    assert found_x.restored == in_x and found_y.restored == in_y
    assert in_x.cycle_occurrence == Present[CycleOccurrenceId](value=x)
    for value in (model.FALSE, INDETERMINATE):
        refused = sm.evaluate(M2Edge.B13, s9, {**facts, bound.fact.name: value}, in_x)
        assert isinstance(refused, sm.Refused) and refused.stratum == sm.GUARD
        assert refused.unmet == (sm.Unmet("B13-4", bound.fact.name, value),)
    for given in (None, restoration(M2Position.S7_CLOSURE_ACTIVE, x)):
        refused = sm.evaluate(M2Edge.B13, s9, facts, given)
        assert refused == sm.Refused(M2Edge.B13, s9, sm.RESTORATION, ())
    unnamed = {k: v for k, v in facts.items() if k != sm.NAMED_HALT}
    assert sm.evaluate(M2Edge.B13, s9, unnamed, in_x) == sm.Refused(
        M2Edge.B13, s9, sm.RESTORATION, ()
    )
    other = restoration(s6, x, HaltOccurrenceId(value=mint_value()))
    assert sm.evaluate(M2Edge.B13, s9, facts, other) == sm.Refused(
        M2Edge.B13, s9, sm.RESTORATION, ()
    )
    off_cycle = restoration(M2Position.S3_IMPLEMENTATION_ACTIVE)
    assert isinstance(off_cycle.cycle_occurrence, KnownAbsent)
    assert _edges_reading(model.RESTORED_OCCURRENCE_BOUND) == {"B13"}


# --- no time, order, authorship or count ----------------------------------------------------------

FORBIDDEN_FACT_WORDS = frozenset(
    {
        "TIME", "TIMESTAMP", "CLOCK", "DATE", "DEADLINE", "TTL", "ELAPSED", "RECENT",
        "RECENCY", "LATEST", "NEWEST", "ORDER", "SEQUENCE", "ARRIVAL", "INSERTION", "ROWID",
        "AUTHOR", "AUTHORSHIP", "WRITER", "COUNT", "RETRY", "ATTEMPT", "PROVIDER",
    }
)  # fmt: skip
"""Whole words of a fact's name — `AUTHORIZATION` is not `AUTHOR`."""

MULTIPLICITY_FACTS = {
    "ELIGIBLE_MULTIPLICITY": "exactly one eligible live instance remains after exclusion",
    "SINGLE_OUTSTANDING_OCCURRENCE": "Exactly one halt occurrence can be outstanding",
}
"""The only facts stating a multiplicity, each because its frozen guard says so in words —
of distinct eligible identities (`A2`…`A4`) and of outstanding halts (`HB-5`) — never a
count of records, attempts or cycles."""


def _all_facts() -> set[model.Fact]:
    return {c.fact for rule in SNAPSHOT for c in sm.guard_conditions(rule.guard)}


@pytest.mark.traces("ST05-N5", "AP04-I07", "AP04-I08", "AP04-I40")
def test_no_guard_consults_time_order_authorship_or_count() -> None:
    """`SV11-10`, static half: no fact a guard reads names a time, a deadline, an order, a
    recency, an author, a provider or a retry count; the two multiplicity facts are the
    frozen text's own words; and no fact is a role (`AP04-I40`)."""
    for fact in _all_facts():
        assert not FORBIDDEN_FACT_WORDS & set(fact.name.split("_")), fact.name
        assert "ROLE" not in fact.name or fact.name in {"ROLE_AUTHORIZED", "ROLE_MATCHES_ENVELOPE"}
    multiplicities = {
        f.name for f in _all_facts() if {"ZERO", "MANY"} & set(f.values) or "SINGLE" in f.name
    }
    assert multiplicities == set(MULTIPLICITY_FACTS)
    quotes = {c.quote for rule in SNAPSHOT for c in sm.guard_conditions(rule.guard)}
    assert set(MULTIPLICITY_FACTS.values()) <= quotes


@pytest.mark.traces("ST05-N5", "AP04-I07", "AP04-I08")
def test_outcomes_are_identical_under_reordered_and_retimed_facts() -> None:
    """`SV11-10`, dynamic half: the same facts in any order, with a timestamp, sequence
    number, author or provider added, give the same result for every legal cell."""
    extras = {
        "TIMESTAMP": "2026-09-27T00:00:00Z",
        "SEQUENCE": "7",
        "AUTHOR": "someone",
        "PROVIDER": "any",
        "ROWID": "1",
    }
    for cell in sm.conformance_matrix():
        if not cell.legal:
            continue
        for _, facts in bases(rule_of(cell.edge)):
            expected = sm.evaluate(cell.edge, cell.source, facts)
            reordered = dict(reversed(list(facts.items())))
            assert sm.evaluate(cell.edge, cell.source, reordered) == expected
            assert sm.evaluate(cell.edge, cell.source, {**extras, **facts}) == expected


@pytest.mark.traces("AP04-I27", "C4", "C5", "CP-1", "CP-2", "CP-3", "CP-4", "CP-5")
def test_completion_is_exactly_cp1_to_cp5_and_nothing_else_admits_completed() -> None:
    """`AP04-I27`: `ACTIVATION_COMPLETED` is entered by `C4` alone, whose guard is its
    trigger and `CP-1`…`CP-5` — no fewer, no other; `C5` closes a terminated run when any of
    `CP-3`…`CP-5` fails, so a failing condition never completes (`CP-2` failing contradicts
    `C5`'s own *the run terminated*)."""
    into = [r for r in SNAPSHOT if r.target == M3Position.ACTIVATION_COMPLETED]
    assert [r.edge for r in into] == [M3Edge.C4]
    c4 = [c.identifier for c in sm.guard_conditions(rule_of(M3Edge.C4).guard)]
    assert c4 == ["C4-T", "CP-1", "CP-2", "CP-3", "CP-4", "CP-5"]
    c5 = rule_of(M3Edge.C5).guard
    assert isinstance(c5, model.Conjunctive)
    decisive = {alternative[-1].fact for alternative in c5.alternatives}
    assert decisive == {model.CP_3, model.CP_4, model.CP_5}
    assert all(model.C5_TERMINATED in alternative for alternative in c5.alternatives)
