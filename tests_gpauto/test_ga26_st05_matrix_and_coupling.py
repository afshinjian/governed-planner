"""`GP-AUTO-ST-05`: the generated conformance matrix, the coupling checks, the occupancies.

Design basis: AP-11 §4 (`SV11-1`, `SV11-2`, `SV11-8`, `SV11-11`), §16 (`GP-AUTO-ST-05`
Deliverables, Acceptance); AP-04 §7 (`K-1`…`K-10`), §7.1 (`OC-1`…`OC-6`), §6.1 (`SU-*`);
the AP-04 bounded-cycle amendment §3.5.2 (`K-6`), §3.5.11 (`OC-4`, `OC-5`).

The matrix is the model's, not a list kept here: its completeness is checked against the
product of every machine's positions and edges, and a change to the model shows up in it.
Each coupling invariant is shown holding over legitimate configurations and, alone,
reported over a configuration that breaks exactly it.
"""

from __future__ import annotations

import itertools

import pytest

from gpauto import state_machine as sm
from gpauto import state_machine_model as model
from gpauto.coordination_vocabulary import (
    M1Position,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
    M4Edge,
    Machine,
    Quiescence,
)
from gpauto.vocabulary import AuthorizationDisposition

GPAUTO_STAGE = "GP-AUTO-ST-05"

LIVE = AuthorizationDisposition.LIVE
SUSPENDED = AuthorizationDisposition.SUSPENDED
CONSUMED = AuthorizationDisposition.CONSUMED
REVOKED = AuthorizationDisposition.REVOKED

MATRIX_SHAPE = {Machine.M1: (5, 4), Machine.M2: (12, 15), Machine.M3: (6, 6), Machine.M4: (4, 6)}
"""Positions × edges per machine: M1 `RESOLUTION_OPEN`…`ROOT_CONTESTED` plus the unentered
position; M2 `S1`…`S11` plus it; M3 its five plus it; M4 its four dispositions."""


# --- the matrix ---------------------------------------------------------------------------


@pytest.mark.traces("ST05-D4", "ST05-A2", "ST05-N1")
def test_the_matrix_disposes_every_position_edge_pair_exactly_once() -> None:
    """`SV11-2`: one cell per (position, edge) of each machine, no pair missing and none
    twice — 260 cells, 46 legal — and every cell disposed: legal with its guard's
    conditions and a target, or illegal with neither."""
    cells = sm.conformance_matrix()
    for machine, (positions, edges) in MATRIX_SHAPE.items():
        here = [c for c in cells if c.machine == machine]
        assert len(here) == positions * edges, machine
        expected = {
            (p, r.edge)
            for p in dict(model.POSITIONS)[machine]
            for r in model.EDGES
            if r.machine == machine
        }
        assert {(c.source, c.edge) for c in here} == expected, machine
    assert len(cells) == 260
    assert len({(c.machine, c.source, c.edge) for c in cells}) == len(cells)
    legal = [c for c in cells if c.legal]
    assert len(legal) == sum(len(r.sources) for r in model.EDGES) == 46
    for cell in cells:
        if cell.legal:
            assert cell.target is not None and cell.conditions and cell.triggers, cell
        else:
            assert cell.target is None and cell.conditions == () and cell.triggers == (), cell


@pytest.mark.traces("ST05-D4", "ST05-A2", "ST05-T1", "ST05-N1")
def test_the_matrix_and_the_evaluator_are_one_reading_of_one_model() -> None:
    """The matrix is generated, not kept: a legal cell is exactly a pair the evaluator
    ever admits, an illegal one exactly a pair it refuses as inexpressible, and each legal
    cell lists every condition of its edge's guard."""
    for cell in sm.conformance_matrix():
        found = sm.evaluate(cell.edge, cell.source, {})
        assert isinstance(found, sm.Refused)
        assert (found.stratum == sm.NO_EDGE) == (not cell.legal), cell
        if cell.legal:
            rule = sm.edge_rule(cell.edge)
            assert cell.conditions == tuple(c.identifier for c in sm.guard_conditions(rule.guard))


@pytest.mark.traces("ST05-D4", "ST05-C1")
def test_the_matrix_follows_the_model_and_keeps_no_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    """A model without `B9`'s `S8` source yields a matrix where that pair is illegal: the
    matrix is regenerated from the model on every call and holds no second list."""
    rules = tuple(
        model.EdgeRule(
            r.edge,
            r.machine,
            tuple(s for s in r.sources if s != M2Position.S8_GATE_REACHED)
            if r.edge == M2Edge.B9
            else r.sources,
            r.target,
            r.guard,
            r.row,
        )
        for r in model.EDGES
    )
    before = {(c.source, c.edge): c.legal for c in sm.conformance_matrix()}
    monkeypatch.setattr(model, "EDGES", rules)
    after = {(c.source, c.edge): c.legal for c in sm.conformance_matrix()}
    changed = {key for key in before if before[key] != after[key]}
    assert changed == {(M2Position.S8_GATE_REACHED, M2Edge.B9)}


# --- coupling -----------------------------------------------------------------------------------


def subject(
    position: M3Position,
    step: M2Position,
    *,
    envelope: str = "e1",
    occurrence: str | None = None,
    current: bool = True,
    quiescence: Quiescence | None = None,
) -> sm.Subject:
    return sm.Subject(envelope, position, step, occurrence, current, quiescence)


def config(
    m2: M2Position | model.Entry,
    m4: AuthorizationDisposition,
    *subjects: sm.Subject,
    m1: M1Position | model.Entry = M1Position.ROOT_RESOLVED,
    eligible: bool | None = True,
) -> sm.Configuration:
    return sm.Configuration(m1, m2, m4, eligible, subjects)


S3 = M2Position.S3_IMPLEMENTATION_ACTIVE
S6 = M2Position.S6_REMEDIATION_ACTIVE
S7 = M2Position.S7_CLOSURE_ACTIVE

LEGITIMATE: tuple[sm.Configuration, ...] = (
    config(model.M2_ENTRY, LIVE, m1=M1Position.RESOLUTION_OPEN),
    config(model.M2_ENTRY, LIVE, m1=M1Position.ROOT_ABSENT),
    config(model.M2_ENTRY, LIVE, m1=M1Position.ROOT_CONTESTED),
    config(M2Position.S1_EPOCH_OPENED, LIVE),
    config(S3, LIVE, subject(M3Position.ACTIVATION_RUNNING, S3)),
    config(S3, LIVE, subject(M3Position.ACTIVATION_COMPLETED, S3)),
    config(M2Position.S8_GATE_REACHED, LIVE, subject(M3Position.ACTIVATION_COMPLETED, S7)),
    config(M2Position.S9_EPOCH_HALTED, SUSPENDED, subject(M3Position.ENVELOPE_VOIDED, S3)),
    config(M2Position.S10_EPOCH_SETTLED, CONSUMED),
    config(M2Position.S11_EPOCH_AUTHORITY_ENDED, REVOKED, eligible=False),
    config(M2Position.S11_EPOCH_AUTHORITY_ENDED, LIVE, eligible=False),
    config(M2Position.S11_EPOCH_AUTHORITY_ENDED, SUSPENDED, eligible=False),
    config(
        S6,
        LIVE,
        subject(M3Position.ACTIVATION_COMPLETED, S6, envelope="r1", occurrence="c1", current=False),
        subject(M3Position.ACTIVATION_COMPLETED, S7, envelope="v1", occurrence="c1", current=False),
        subject(M3Position.ACTIVATION_RUNNING, S6, envelope="r2", occurrence="c2"),
    ),
)
"""Legitimate coupled positions, the three `B12` outcomes of §6.1 and a second cycle
occurrence included — `(EPOCH_AUTHORITY_ENDED, SUSPENDED)` among them (`K-2a`, `SU-6`)."""


@pytest.mark.traces("ST05-T2", "ST05-D3", "K-1", "K-2", "K-2a", "K-3", "K-4", "AP04-I34")
def test_every_legitimate_configuration_satisfies_every_coupling_invariant() -> None:
    for legitimate in LEGITIMATE:
        assert sm.coupling_violations(legitimate) == (), legitimate


BROKEN: tuple[tuple[str, sm.Configuration], ...] = (
    ("K-1", config(S3, CONSUMED)),
    ("K-2", config(M2Position.S9_EPOCH_HALTED, LIVE)),
    ("K-2", config(M2Position.S2_ENTRY_BOUNDARY_FIXED, SUSPENDED)),
    ("K-2a", config(M2Position.S10_EPOCH_SETTLED, REVOKED)),
    ("K-3", config(M2Position.S5_FINDING_SET_FROZEN, CONSUMED)),
    ("K-4", config(M2Position.S11_EPOCH_AUTHORITY_ENDED, LIVE, eligible=True)),
    ("K-4", config(M2Position.S11_EPOCH_AUTHORITY_ENDED, SUSPENDED, eligible=None)),
    (
        "K-5",
        config(
            S3,
            LIVE,
            subject(M3Position.ACTIVATION_RUNNING, S3),
            subject(M3Position.ENVELOPE_DERIVED, S3, envelope="e2"),
        ),
    ),
    (
        "K-5",
        config(M2Position.S5_FINDING_SET_FROZEN, LIVE, subject(M3Position.ENVELOPE_DERIVED, S3)),
    ),
    (
        "K-6",
        config(
            M2Position.S5_FINDING_SET_FROZEN,
            LIVE,
            subject(M3Position.ACTIVATION_COMPLETED, M2Position.S4_DISCOVERY_ACTIVE),
            subject(M3Position.ACTIVATION_COMPLETED, M2Position.S4_DISCOVERY_ACTIVE, envelope="e2"),
        ),
    ),
    (
        "K-6",
        config(
            M2Position.S8_GATE_REACHED,
            LIVE,
            subject(M3Position.ACTIVATION_COMPLETED, S7, occurrence="c1"),
            subject(M3Position.ACTIVATION_COMPLETED, S7, envelope="e2", occurrence="c1"),
        ),
    ),
    ("K-8", config(M2Position.S1_EPOCH_OPENED, LIVE, m1=M1Position.ROOT_CONTESTED)),
    (
        "K-10",
        config(
            S6,
            LIVE,
            subject(
                M3Position.ACTIVATION_CLOSED_UNADOPTED,
                S6,
                envelope="r1",
                current=False,
                quiescence=Quiescence.INDETERMINATE,
            ),
            subject(M3Position.ACTIVATION_RUNNING, S6, envelope="r2"),
        ),
    ),
)
"""One configuration per invariant, breaking it and — apart from the invariants each break
necessarily also touches, listed below — nothing else."""

ALSO_BROKEN = {"K-1": {"K-3"}, "K-3": {"K-1"}, "K-2a": {"K-3"}}
"""A consumed instance outside `S10` breaks `K-1` and `K-3` together; `S10` without
`CONSUMED` breaks `K-2a` and `K-3` together."""


@pytest.mark.traces(
    "ST05-T2", "ST05-D3", "K-1", "K-2", "K-2a", "K-3", "K-4", "K-5", "K-6", "K-8", "K-10"
)
@pytest.mark.parametrize(("invariant", "broken"), BROKEN, ids=[i for i, _ in BROKEN])
def test_each_coupling_invariant_is_reported_when_broken(
    invariant: str, broken: sm.Configuration
) -> None:
    reported = {v.invariant for v in sm.coupling_violations(broken)}
    assert invariant in reported
    assert reported <= {invariant} | ALSO_BROKEN.get(invariant, set()), reported


@pytest.mark.supports("AP04-I32")
@pytest.mark.traces("K-7", "ST05-D3", "C3", "C6")
def test_k7_no_live_subject_survives_the_instance_leaving_live() -> None:
    """`K-7`: when M4 leaves `LIVE` every derived envelope is voided (`C3`) and every running
    activation closed unadopted (`C6`) — a live subject under a non-`LIVE` instance is a
    violation, and the `C3`/`C6` alternatives the model gives both fire on it."""
    for disposition in (SUSPENDED, REVOKED):
        for position in (M3Position.ENVELOPE_DERIVED, M3Position.ACTIVATION_RUNNING):
            broken = config(M2Position.S9_EPOCH_HALTED, disposition, subject(position, S3))
            assert "K-7" in {v.invariant for v in sm.coupling_violations(broken)}
    facts = {model.TRIGGER.name: model.COORDINATOR, model.M4_LIVE.name: model.FALSE}
    found = sm.evaluate(M3Edge.C6, M3Position.ACTIVATION_RUNNING, facts)
    assert isinstance(found, sm.Admitted)
    assert found.target == M3Position.ACTIVATION_CLOSED_UNADOPTED
    facts = {model.TRIGGER.name: model.COORDINATOR, model.UNRESOLVED_EVENT.name: model.TRUE}
    assert isinstance(sm.evaluate(M3Edge.C3, M3Position.ENVELOPE_DERIVED, facts), sm.Admitted)


@pytest.mark.traces("K-9", "K-2", "ST05-D3", "AP04-I29")
def test_joint_pairs_are_reported_when_one_half_moves() -> None:
    """`K-9`, and `K-2` across halting and settling: `B13` without `G6`, `G6` without `B13`,
    `B9` without `G1`, `B10`/`B11` without `G2`/`G3` are each reported; `B12` may move M4 or
    not (§6.1), and an uncoupled edge moves M2 alone."""
    assert sm.act_violations(M2Edge.B13, M4Edge.G6) == ()
    assert {v.invariant for v in sm.act_violations(M2Edge.B13, None)} == {"K-9"}
    assert {v.invariant for v in sm.act_violations(None, M4Edge.G6)} == {"K-9"}
    assert {v.invariant for v in sm.act_violations(M2Edge.B9, None)} == {"K-2"}
    assert sm.act_violations(M2Edge.B9, M4Edge.G1) == ()
    assert sm.act_violations(M2Edge.B10, None) and sm.act_violations(M2Edge.B11, None)
    assert sm.act_violations(M2Edge.B12, None) == () == sm.act_violations(M2Edge.B12, M4Edge.G5)
    assert sm.act_violations(M2Edge.B3, None) == ()


@pytest.mark.traces("K-6", "ST05-D3", "AP04-I09")
def test_k6_a_step_is_left_forward_only_on_its_subjects_completion() -> None:
    """`K-6`: every forward edge out of a step state requires the step's subject completed —
    `B4`, `B5`, `B7` through `STEP_ACTIVATION_COMPLETED`, `B8` and `B15` through `CE-0a`.
    `ACTIVATION_CLOSED_UNADOPTED` never advances M2: only `B9` and `B12` leave a step
    without it, and both leave the routing."""
    for step in model.STEP_STATES:
        for rule in model.EDGES:
            if step not in rule.sources or rule.edge in (M2Edge.B9, M2Edge.B12):
                continue
            facts = {c.fact for c in sm.guard_conditions(rule.guard)}
            assert model.STEP_ACTIVATION_COMPLETED in facts or model.CE_0A in facts, rule.edge


@pytest.mark.traces("K-10", "AP04-I41", "C2", "C6")
def test_k10_governance_closure_is_not_quiescence() -> None:
    """`K-10`, `PQ-1`, `PQ-2`: `C6` has no termination condition, so it closes a possibly
    running process; `C2` dispatches only with no prior activation or one closed **and**
    quiescent, never on an indeterminate observation; and two possibly-running processes
    at one step position are a violation, one of them closed unadopted or not."""
    c6 = {c.fact for c in sm.guard_conditions(sm.edge_rule(M3Edge.C6).guard)}
    assert model.CP_2 not in c6
    base = {c.fact.name: c.admitted[0] for c in sm.guard_conditions(sm.edge_rule(M3Edge.C2).guard)}
    for prior, admitted in (
        ("NONE", True),
        ("CLOSED_AND_QUIESCENT", True),
        ("CLOSED_NOT_QUIESCENT", False),
        ("NOT_GOVERNANCE_CLOSED", False),
        (model.INDETERMINATE, False),
    ):
        facts = {**base, model.PRIOR_ACTIVATION_AT_POSITION.name: prior}
        found = sm.evaluate(M3Edge.C2, M3Position.ENVELOPE_DERIVED, facts)
        assert isinstance(found, sm.Admitted) == admitted, prior
    quiet = config(
        S6,
        LIVE,
        subject(M3Position.ACTIVATION_CLOSED_UNADOPTED, S6, envelope="r1", current=False,
                quiescence=Quiescence.QUIESCENT),
        subject(M3Position.ACTIVATION_RUNNING, S6, envelope="r2"),
    )  # fmt: skip
    assert sm.coupling_violations(quiet) == ()


@pytest.mark.traces("K-8", "AP04-I04")
def test_k8_a_halted_resolution_has_no_epoch() -> None:
    for halted in model.M1_HALTS:
        assert sm.coupling_violations(config(model.M2_ENTRY, LIVE, m1=halted)) == ()  # type: ignore[arg-type]
        broken = config(M2Position.S1_EPOCH_OPENED, LIVE, m1=halted)  # type: ignore[arg-type]
        assert "K-8" in {v.invariant for v in sm.coupling_violations(broken)}


# --- occupancies --------------------------------------------------------------------------------


@pytest.mark.supports("AP04-I25")
@pytest.mark.traces("ST05-T3", "AP04-I38", "K-5")
def test_the_three_legitimate_occupancies_are_expressible_and_distinct() -> None:
    """`SV11-11`, §7.1: a step state live; completed and not yet routed; resumed with
    nothing live — each a correct position with no coupling violation, and the three told
    apart by the current occurrence's subject alone (`OC-4`). Prior cycles' terminal
    subjects at the same step are history, not the current subject."""
    history = subject(
        M3Position.ACTIVATION_COMPLETED, S6, envelope="r0", occurrence="c0", current=False
    )
    cases = {
        sm.LIVE_OCCUPANCY: config(
            S6, LIVE, history, subject(M3Position.ACTIVATION_RUNNING, S6, occurrence="c1")
        ),
        sm.COMPLETED_NOT_ROUTED: config(
            S6, LIVE, history, subject(M3Position.ACTIVATION_COMPLETED, S6, occurrence="c1")
        ),
        sm.NOTHING_LIVE: config(
            S6,
            LIVE,
            history,
            subject(
                M3Position.ACTIVATION_CLOSED_UNADOPTED,
                S6,
                occurrence="c1",
                quiescence=Quiescence.QUIESCENT,
            ),
        ),
    }
    for expected, occupied in cases.items():
        assert sm.occupancy(occupied) == expected
        assert sm.coupling_violations(occupied) == (), expected
    voided = config(S3, LIVE, subject(M3Position.ENVELOPE_VOIDED, S3))
    assert sm.occupancy(voided) == sm.NOTHING_LIVE
    assert sm.occupancy(config(M2Position.S5_FINDING_SET_FROZEN, LIVE)) is None


@pytest.mark.traces("ST05-T2", "K-5", "K-7")
def test_no_combination_of_step_and_subject_positions_escapes_the_checks() -> None:
    """Exhaustively over one step state, one M4 disposition and one subject's position:
    wherever the subject is live and the configuration is not a live occupancy of its own
    step under a `LIVE` instance, a `K-5` or `K-7` violation is reported."""
    for m2, m4, position in itertools.product(
        (*model.NON_TERMINAL,), (LIVE, SUSPENDED), tuple(M3Position)
    ):
        found = {v.invariant for v in sm.coupling_violations(config(m2, m4, subject(position, S3)))}
        live = position in sm.LIVE_M3
        lawful = m2 == S3 and m4 == LIVE
        if live and not lawful:
            assert found & {"K-5", "K-7"}, (m2, m4, position)
