"""`GP-AUTO-ST-05`: position from records across restart, nothing persisted, and mutation.

Design basis: AP-11 §5 (`PV11-11`), §8 (`MU11-2a`, `MU11-3`, `MU11-7`), §11 (`FI11-1a`
Class A), §16 (`GP-AUTO-ST-05` Restart/persistence evidence and Mutation cells); AP-04
§4.4.1 (`HB-3`…`HB-5`), §5.2 (`C2`, `V-13`); AP-07 §8 (`DV-4`, `DV-6`, `DV-7`); AP-03
`AP03-I12`.

**Restart evidence is Class A** (`FI11-1a`): the records are persisted through the store's
own create path, the store is closed, and the positions are read back — reopened in this
process and, separately, in a fresh interpreter under two hash seeds. Each machine's
position is walked from its `RC-34` chain by `DV-6`; nothing else crosses the restart,
because nothing else exists: ST-05 adds no table, column, schema version or record.
ST-04's own restart evidence is not reused as ST-05's — the evidence here is ST-05's
positions, derived guard facts and evaluations.
"""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

import mutation
import traceability
from gate_scope import REPOSITORY_ROOT
from gpauto import derivations as dv
from gpauto import state_machine as sm
from gpauto import state_machine_model as model
from gpauto import store_schema
from gpauto.absence import Carried
from gpauto.coordination_identity import CycleOccurrenceId, HaltOccurrenceId
from gpauto.coordination_records import (
    AuthorityEnvelopeRecord,
    CycleOccurrence,
    HaltOccurrence,
    RefusalResult,
    ResolvedRootResult,
)
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
from gpauto.envelope import AuthorityEnvelope
from gpauto.identity import (
    AuthorityEnvelopeId,
    FrozenFindingSetId,
    OwnerAuthorizationId,
    RemediationObligationId,
    RootResolutionId,
)
from gpauto.store import open_store
from gpauto.vocabulary import AuthorizationDisposition, OwnerDecisionKind, Role
from st03_world import ABSENT, bounds
from st04_world import Epoch, Subjects, persisted_extended_world, present, rendered, token
from test_ga17_st03_store import PINNED_SCHEMA_DIGEST
from test_ga22_st04_restart_and_absence import raw_contents, stored_derivation_surfaces

GPAUTO_STAGE = "GP-AUTO-ST-05"

ST05_MODULES = (Path("src/gpauto/state_machine_model.py"), Path("src/gpauto/state_machine.py"))


@pytest.fixture
def directory() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="gpauto-st05-") as location:
        yield Path(location)


def evidence(records: dv.AuthoritativeRecords, subjects: Subjects) -> dict[str, object]:
    """ST-05's reading of the persisted world: the four positions, the guard facts ST-04's
    derivations yield, and every edge evaluated from the position of its machine."""
    root = OwnerAuthorizationId(value=subjects.root)
    resolution = RootResolutionId(value=subjects.resolution)
    envelope = AuthorityEnvelopeId(value=subjects.envelope)
    positions = sm.recorded_positions(records, resolution, root, (envelope,))
    assert isinstance(positions, sm.Positions), positions
    facts = sm.derived_guard_facts(records, resolution, root, envelope)
    source = {
        Machine.M1: positions.m1,
        Machine.M2: positions.m2,
        Machine.M3: positions.m3[0][1],
        Machine.M4: positions.m4,
    }
    evaluations = {str(r.edge): sm.evaluate(r.edge, source[r.machine], facts) for r in model.EDGES}
    return {"positions": positions, "facts": facts, "evaluations": evaluations}


def main(argv: list[str]) -> int:
    """In a fresh process: open the store at `argv[0]`, read, and print the rendering."""
    store = open_store(Path(argv[0]))
    try:
        print(rendered(evidence(dv.read_authoritative_records(store), Subjects(*argv[1:]))))
    finally:
        store.close()
    return 0


# --- restart --------------------------------------------------------------------------------


@pytest.mark.traces("ST05-R1", "AP04-I19")
def test_positions_are_reconstructed_identically_after_the_store_is_reopened(
    directory: Path,
) -> None:
    """Persist; read the four positions from their `RC-34` chains; close; reopen; read
    again — identical positions, facts and evaluations. The values are the settled world's:
    a resolved root, a settled epoch, a completed envelope, a consumed instance — and from
    each, every edge is refused, as terminality requires, after restart as before it."""
    with persisted_extended_world(directory) as (store, _, subjects):
        path = store.path
        before = evidence(dv.read_authoritative_records(store), subjects)
    positions = before["positions"]
    assert isinstance(positions, sm.Positions)
    assert positions.m1 == M1Position.ROOT_RESOLVED
    assert positions.m2 == M2Position.S10_EPOCH_SETTLED
    assert positions.m3[0][1] == M3Position.ACTIVATION_COMPLETED
    assert positions.m4 == AuthorizationDisposition.CONSUMED
    facts = before["facts"]
    assert isinstance(facts, dict)
    assert facts[model.M1_ROOT_RESOLVED.name] == model.TRUE
    assert facts[model.M4_LIVE.name] == model.FALSE
    assert facts[model.ENVELOPE_NEVER_ACTIVATED.name] == model.FALSE
    evaluations = before["evaluations"]
    assert isinstance(evaluations, dict)
    for edge, found in evaluations.items():
        if edge.startswith(("B", "C", "G")):
            assert isinstance(found, sm.Refused) and found.stratum == sm.NO_EDGE, edge
    reopened = open_store(path)
    try:
        after = evidence(dv.read_authoritative_records(reopened), subjects)
    finally:
        reopened.close()
    assert after == before
    assert rendered(after) == rendered(before)


@pytest.mark.traces("ST05-R1")
def test_positions_are_reconstructed_identically_in_a_fresh_process(directory: Path) -> None:
    """A new interpreter, under two hash seeds, opens the persisted store and computes the
    same positions, facts and evaluations: only records crossed the process boundary."""
    with persisted_extended_world(directory) as (store, _, subjects):
        path = store.path
        here = rendered(evidence(dv.read_authoritative_records(store), subjects))
    code = (
        "import sys; sys.path.insert(0, 'tests_gpauto'); "
        "from test_ga27_st05_restart_and_mutation import main; "
        "raise SystemExit(main(sys.argv[1:]))"
    )
    for seed in ("0", "4242"):
        completed = subprocess.run(
            [sys.executable, "-c", code, str(path), *subjects.argv()],
            capture_output=True,
            text=True,
            cwd=REPOSITORY_ROOT,
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == here


@pytest.mark.traces("ST05-R1", "ST05-G1", "AP04-I19", "AP04-I23")
def test_reading_positions_and_evaluating_write_nothing(directory: Path) -> None:
    """Every schema object and row of the file is identical before and after positions are
    read and every edge evaluated, twice; no stored surface for a position or a transition
    exists; and the schema is v3, byte-identical to the accepted DDL digest."""
    with persisted_extended_world(directory) as (store, _, subjects):
        before = raw_contents(store.path)
        evidence(dv.read_authoritative_records(store), subjects)
        evidence(dv.read_authoritative_records(store), subjects)
        assert raw_contents(store.path) == before
        assert stored_derivation_surfaces(store.path) == []
    statements = store_schema.schema_statements(store_schema.build_catalogue())
    digest = hashlib.sha256("\n;\n".join(statements).encode("utf-8")).hexdigest()
    assert digest == PINNED_SCHEMA_DIGEST
    assert store_schema.SCHEMA_VERSION == "gpauto.coordination-store/4"
    assert store_schema.STORAGE_VERSION == 4


@pytest.mark.traces("ST05-R1", "ST05-G1", "ST05-D2")
def test_no_mutable_current_state_exists_in_the_st05_modules() -> None:
    """No module-level list, dict or set; no `global`; every class a frozen dataclass or
    a signal; no name for a current state, cursor or position cache; no store import and
    no write call. A position is computed when asked, and held nowhere."""
    for relative in ST05_MODULES:
        tree = ast.parse((REPOSITORY_ROOT / relative).read_text(encoding="utf-8"))
        for statement in tree.body:
            if isinstance(statement, ast.Assign | ast.AnnAssign) and statement.value is not None:
                assert not isinstance(
                    statement.value, ast.List | ast.Dict | ast.Set | ast.ListComp | ast.DictComp
                ), (relative, statement.lineno)
        for node in ast.walk(tree):
            assert not isinstance(node, ast.Global | ast.Nonlocal), relative
            if isinstance(node, ast.ClassDef):
                decorators = [ast.unparse(d) for d in node.decorator_list]
                assert decorators == ["dataclass(frozen=True)"] or node.name == "_Undetermined", (
                    relative,
                    node.name,
                )
            if isinstance(node, ast.Name | ast.Attribute):
                name = (node.id if isinstance(node, ast.Name) else node.attr).lower()
                for word in ("current_state", "cursor", "cache", "snapshot", "create", "insert"):
                    assert word not in name, (relative, name)
            if isinstance(node, ast.ImportFrom):
                assert node.module not in ("gpauto.store", "gpauto.store_schema", "sqlite3")


# --- records-backed guard facts: AP03-I12, HB-3 ... HB-5 ----------------------------------------


@pytest.mark.traces("AP03-I12", "ST05-B1", "C2")
def test_a_persisted_activated_envelope_cannot_be_activated_again(directory: Path) -> None:
    """`AP03-I12` over persisted records: the world's activated envelope is at
    `ACTIVATION_COMPLETED` by its `RC-34` chain, `DV-6` reports it never-activated `FALSE`,
    and `C2` from its reconstructed position is inexpressible — also once `C2`'s other
    conditions are all supplied true."""
    with persisted_extended_world(directory) as (store, _, subjects):
        found = evidence(dv.read_authoritative_records(store), subjects)
    positions = found["positions"]
    assert isinstance(positions, sm.Positions)
    ((_, m3),) = positions.m3
    facts = {
        **{c.fact.name: c.admitted[0] for c in sm.guard_conditions(sm.edge_rule(M3Edge.C2).guard)},
        model.ENVELOPE_NEVER_ACTIVATED.name: model.FALSE,
    }
    refused = sm.evaluate(M3Edge.C2, m3, facts)
    assert isinstance(refused, sm.Refused) and refused.stratum == sm.NO_EDGE


def _halted_epoch(tag: str) -> tuple[Epoch, HaltOccurrence, RootResolutionId]:
    epoch = Epoch(tag)
    epoch.m2(M2Position.S3_IMPLEMENTATION_ACTIVE)
    refusal = epoch.refusal()
    halt = epoch.halt(refusal.refusal.identity, M2Position.S3_IMPLEMENTATION_ACTIVE)
    epoch.m2(M2Position.S9_EPOCH_HALTED, M2Edge.B9)
    epoch.suspend(epoch.root, refusal.refusal.identity)
    epoch.m4(epoch.root, AuthorizationDisposition.SUSPENDED, M4Edge.G1, None)
    resolution = epoch.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=epoch.root)))
    return epoch, halt, resolution.identity


def _resumption_facts(derived: sm.Facts) -> sm.Facts:
    supplied = {c.fact.name: model.TRUE for c in model.RESUMPTION_PREDICATE}
    trigger = {model.TRIGGER.name: OwnerDecisionKind.REFUSAL_RESOLUTION.value}
    return {**supplied, **trigger, **derived}


@pytest.mark.traces("AP04-I39", "B13", "G6", "ST05-B1", "AP04-I29")
def test_b13_reads_its_named_occurrence_and_target_from_the_records() -> None:
    """`HB-3`…`HB-5` from records through `DV-4` and `DV-7`: the decision names the one
    outstanding occurrence on this root, whose recorded source is `S3` — so `B13` restores
    exactly `S3`, with `G6` — while another root's outstanding halt changes nothing. A
    second outstanding occurrence on this root refuses; and once the named occurrence has
    its `RC-32` resolution it is no longer outstanding, so the same decision cannot resume
    the epoch a second time."""
    epoch, halt, resolution = _halted_epoch("st05-h")
    other, _, _ = _halted_epoch("st05-o")
    records = epoch.snapshot(other)
    named = halt.identity
    derived = sm.derived_guard_facts(records, resolution, epoch.root, named_halt=named)
    assert derived[model.DECISION_NAMES_OUTSTANDING_OCCURRENCE.name] == model.TRUE
    assert derived[model.SINGLE_OUTSTANDING_OCCURRENCE.name] == model.TRUE
    assert derived[model.RESTORED_POSITION.name] == M2Position.S3_IMPLEMENTATION_ACTIVE.value
    assert derived[model.RESTORED_OCCURRENCE_BOUND.name] == model.TRUE
    restored = sm.recorded_restoration(records, named)
    assert restored == sm.Restoration(named, M2Position.S3_IMPLEMENTATION_ACTIVE, ABSENT)
    assert derived[model.EPOCH_HALTED.name] == model.TRUE
    assert derived[model.M4_LIVE.name] == model.FALSE
    assert derived[model.UNRESOLVED_EVENT.name] == model.TRUE
    assert derived[model.M1_ROOT_RESOLVED.name] == model.TRUE
    act = sm.evaluate_act(
        M2Edge.B13,
        M2Position.S9_EPOCH_HALTED,
        AuthorizationDisposition.SUSPENDED,
        _resumption_facts(derived),
        restored,
    )
    assert isinstance(act, sm.Act) and act.m2.target == M2Position.S3_IMPLEMENTATION_ACTIVE
    assert act.m2.restored == restored
    assert act.m4 is not None and act.m4.target == AuthorizationDisposition.LIVE

    second = epoch.refusal()
    epoch.halt(second.refusal.identity, M2Position.S9_EPOCH_HALTED)
    epoch.suspend(epoch.root, second.refusal.identity)
    twice = sm.derived_guard_facts(epoch.snapshot(), resolution, epoch.root, named_halt=named)
    assert twice[model.SINGLE_OUTSTANDING_OCCURRENCE.name] == model.FALSE

    resolved_epoch, resolved_halt, resolved_resolution = _halted_epoch("st05-r")
    resolved_epoch.resolve(resolved_halt)
    after = sm.derived_guard_facts(
        resolved_epoch.snapshot(),
        resolved_resolution,
        resolved_epoch.root,
        named_halt=resolved_halt.identity,
    )
    assert after[model.DECISION_NAMES_OUTSTANDING_OCCURRENCE.name] == model.FALSE
    refused = sm.evaluate(
        M2Edge.B13,
        M2Position.S9_EPOCH_HALTED,
        _resumption_facts(after),
        sm.Restoration(resolved_halt.identity, M2Position.S3_IMPLEMENTATION_ACTIVE, ABSENT),
    )
    assert isinstance(refused, sm.Refused)


@pytest.mark.supports("AP04-I03")
@pytest.mark.traces("ST05-B1", "B1")
def test_a_root_resolution_result_is_read_only_once_it_is_recorded() -> None:
    """The ST-06 boundary: `B1`'s `M1_ROOT_RESOLVED` is read from the completing `A2` entry
    through `DV-4` recorded eligibility. An open resolution yields `FALSE` — nothing is
    evaluated to produce the result — and an `A3` completion never reads as resolved."""
    epoch = Epoch("st05-m1")
    open_resolution = epoch.resolution(None)
    facts = sm.derived_guard_facts(epoch.snapshot(), open_resolution.identity, epoch.root)
    assert facts[model.M1_ROOT_RESOLVED.name] == model.FALSE
    refusal = epoch.refusal()
    absent = epoch.resolution((M1Edge.A3, RefusalResult(refusal=refusal.refusal.identity)))
    facts = sm.derived_guard_facts(epoch.snapshot(), absent.identity, epoch.root)
    assert facts[model.M1_ROOT_RESOLVED.name] == model.FALSE
    b1 = sm.evaluate(M2Edge.B1, model.M2_ENTRY, {**facts, model.TRIGGER.name: model.COORDINATOR})
    assert isinstance(b1, sm.Refused)


@pytest.mark.traces("ST05-B1", "ST05-D2")
def test_an_indeterminate_derivation_is_an_indeterminate_fact_never_a_default() -> None:
    """Records that fail to be read as one consistent set give no position and no facts: a
    missing fact is `INDETERMINATE`, and every guard reading it refuses (`P-04`)."""
    epoch, halt, resolution = _halted_epoch("st05-u")
    records = dv.AuthoritativeRecords((), unstable=frozenset(dv.DERIVATION_INPUTS))
    assert isinstance(sm.recorded_positions(records, resolution, epoch.root, ()), dv.Indeterminate)
    facts = sm.derived_guard_facts(records, resolution, epoch.root, named_halt=halt.identity)
    assert model.M4_LIVE.name not in facts and model.RESTORED_POSITION.name not in facts
    assert model.RESTORED_OCCURRENCE_BOUND.name not in facts
    assert isinstance(sm.recorded_restoration(records, halt.identity), dv.Indeterminate)
    assert isinstance(
        sm.evaluate(M2Edge.B13, M2Position.S9_EPOCH_HALTED, _resumption_facts(facts)), sm.Refused
    )


# --- ST05-IMPL-R02: C2 against ST-04's CYCLE_BOUND --------------------------------------------


def _derived_envelope(
    epoch: Epoch,
    role: Role,
    reference: FrozenFindingSetId | None,
    cycle: CycleOccurrence | None,
) -> AuthorityEnvelopeId:
    """An envelope derived by `C1` from the epoch's current entry and not yet dispatched,
    its `E-14` carrying `reference` — or inapplicable, as for a role without one."""
    assert epoch.head is not None
    granted = bounds(epoch.frame).model_copy(
        update={
            "role_applicability": role,
            "frozen_set_reference": Carried[FrozenFindingSetId](value=reference)
            if reference is not None
            else bounds(epoch.frame).frozen_set_reference,
        }
    )
    record = AuthorityEnvelopeRecord(
        envelope=AuthorityEnvelope(
            identity=AuthorityEnvelopeId(value=token()),
            resolved_root=epoch.root,
            stage=epoch.frame.stage,
            entry_boundary=epoch.boundary.boundary.identity,
            role=role,
            bounds=granted,
            declared_closed=True,
        ),
        cycle_occurrence=present(cycle.identity) if cycle else ABSENT,
        predecessor_entry=epoch.head.identity,
        target_state=epoch.head.state,
    )
    epoch.records.append(record)
    epoch.m3(record.envelope.identity, M3Position.ENVELOPE_DERIVED, M3Edge.C1, None)
    return record.envelope.identity


def _dispatch(
    epoch: Epoch,
    envelope: AuthorityEnvelopeId,
    admitted: frozenset[RemediationObligationId] | None,
    *others: Epoch,
) -> tuple[sm.Facts, sm.Evaluation]:
    """`C2` from the envelope's recorded position, over its other conditions supplied true
    and the facts ST-04's derivations yield — `CYCLE_BOUND` among them."""
    resolution = epoch.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=epoch.root)))
    records = epoch.snapshot(*others)
    positions = sm.recorded_positions(records, resolution.identity, epoch.root, (envelope,))
    assert isinstance(positions, sm.Positions)
    ((_, m3),) = positions.m3
    derived = sm.derived_guard_facts(
        records, resolution.identity, epoch.root, envelope, admitted_obligations=admitted
    )
    supplied = {
        c.fact.name: c.admitted[0] for c in sm.guard_conditions(sm.edge_rule(M3Edge.C2).guard)
    }
    supplied.pop(model.ADMITTED_OBLIGATIONS_AGREE.name, None)
    return derived, sm.evaluate(M3Edge.C2, m3, {**supplied, **derived})


@pytest.mark.supports("AP04-I49")
@pytest.mark.traces("C2", "AP03-I12", "ST05-B1", "ST05-M1")
def test_c2_admits_a_dispatch_only_against_the_committed_cycle_bound() -> None:
    """`ST05-IMPL-R02`, `OP-8`(i), over records: a REMEDIATOR envelope referencing the
    frozen set through `E-14` is dispatched only where its admitted obligation set equals
    ST-04's `DV-3` `CYCLE_BOUND` — read, never recomputed. A subset, a superset, an absent
    set, a reference to another set, or no frozen set at all refuses. After a closure
    attests one member the next cycle's bound shrinks, and only the new bound dispatches. An
    envelope with no `E-14` admits no obligation set and is not held to one."""
    epoch = Epoch("st05-cb")
    discovery = epoch.activation(Role.DISCOVERY_REVIEWER)
    epoch.m2(M2Position.S3_IMPLEMENTATION_ACTIVE)
    frozen, obligations = epoch.freeze(discovery, 2)
    o1, o2 = (o.identity for o in obligations)
    first = epoch.cycle(None)
    envelope = _derived_envelope(epoch, Role.REMEDIATOR, frozen.identity, first)
    committed = dv.derive_cycle_bound(epoch.snapshot(), epoch.root)
    assert isinstance(committed, dv.CycleBound) and committed.members == frozenset({o1, o2})
    name = model.ADMITTED_OBLIGATIONS_AGREE.name
    derived, found = _dispatch(epoch, envelope, frozenset({o1, o2}))
    assert derived[name] == model.EQUAL
    assert found == sm.Admitted(
        M3Edge.C2, M3Position.ENVELOPE_DERIVED, M3Position.ACTIVATION_RUNNING
    )
    stranger = RemediationObligationId(
        parent_frozen_set=FrozenFindingSetId(value=token()), member_finding=frozen.members[0]
    )
    for admitted in (frozenset({o1}), frozenset({o1, o2, stranger}), frozenset()):
        derived, found = _dispatch(epoch, envelope, admitted)
        assert derived[name] == model.UNEQUAL
        assert isinstance(found, sm.Refused) and found.unmet == (
            sm.Unmet("C2-8", name, model.UNEQUAL),
        )
    derived, found = _dispatch(epoch, envelope, None)
    assert name not in derived and isinstance(found, sm.Refused)
    elsewhere = _derived_envelope(epoch, Role.REMEDIATOR, FrozenFindingSetId(value=token()), first)
    derived, found = _dispatch(epoch, elsewhere, frozenset({o1, o2}))
    assert name not in derived and isinstance(found, sm.Refused)

    epoch.m2(M2Position.S7_CLOSURE_ACTIVE, cycle=first.identity)
    closure = epoch.activation(Role.BOUNDED_CLOSURE_VERIFIER, cycle=first)
    epoch.assess(closure, o1.member_finding, closed=True, cycle=first)
    epoch.assess(closure, o2.member_finding, closed=False, cycle=first)
    second = epoch.cycle(closure.identity)
    envelope = _derived_envelope(epoch, Role.REMEDIATOR, frozen.identity, second)
    derived, found = _dispatch(epoch, envelope, frozenset({o1, o2}))
    assert derived[name] == model.UNEQUAL and isinstance(found, sm.Refused)
    derived, found = _dispatch(epoch, envelope, frozenset({o2}))
    assert derived[name] == model.EQUAL and isinstance(found, sm.Admitted)

    bare = Epoch("st05-cb-bare")
    bare.m2(M2Position.S3_IMPLEMENTATION_ACTIVE)
    implementer = _derived_envelope(bare, Role.IMPLEMENTER, None, None)
    derived, found = _dispatch(bare, implementer, None)
    assert derived[name] == model.NOT_APPLICABLE and isinstance(found, sm.Admitted)
    orphan = _derived_envelope(bare, Role.REMEDIATOR, frozen.identity, None)
    assert dv.derive_cycle_bound(bare.snapshot(), bare.root) == dv.NoFrozenSet(bare.root)
    derived, found = _dispatch(bare, orphan, frozenset({o1, o2}))
    assert name not in derived and isinstance(found, sm.Refused)


# --- ST05-IMPL-R03: B13 bound to its halt's cycle occurrence -----------------------------------


def _halt(epoch: Epoch, source: M2Position, cycle: CycleOccurrenceId | None) -> HaltOccurrence:
    """An `RC-31` halt at `source`, recording `cycle` as its occurrence exactly as given,
    then `B9` and the suspension it establishes."""
    refusal = epoch.refusal()
    halt = HaltOccurrence(
        identity=HaltOccurrenceId(value=token()),
        event=refusal.refusal.identity,
        source_state=source,
        cycle_occurrence=present(cycle) if cycle else ABSENT,
    )
    epoch.records.append(halt)
    epoch.m2(M2Position.S9_EPOCH_HALTED, M2Edge.B9, cycle)
    epoch.suspend(epoch.root, refusal.refusal.identity)
    return halt


def _resume(
    records: dv.AuthoritativeRecords,
    resolution: RootResolutionId,
    root: OwnerAuthorizationId,
    halt: HaltOccurrenceId,
) -> tuple[sm.Facts, sm.Act | sm.Refused]:
    """`B13` with `G6` for the halt the resolving decision names: its guard facts and its
    restoration both read for that one halt from the records."""
    derived = sm.derived_guard_facts(records, resolution, root, named_halt=halt)
    restored = sm.recorded_restoration(records, halt)
    return derived, sm.evaluate_act(
        M2Edge.B13,
        M2Position.S9_EPOCH_HALTED,
        AuthorizationDisposition.SUSPENDED,
        _resumption_facts(derived),
        restored if isinstance(restored, sm.Restoration) else None,
    )


def _two_cycle_halts() -> tuple[
    dv.AuthoritativeRecords,
    dv.AuthoritativeRecords,
    RootResolutionId,
    OwnerAuthorizationId,
    HaltOccurrence,
    HaltOccurrence,
]:
    """One epoch halting twice at `S6`: in cycle occurrence X (halt A), which is resolved
    and resumed, and then — after a closure and `B15` — in occurrence Y (halt B), which is
    left the sole outstanding halt. Each halts before any envelope is derived in its cycle.
    Returns the records before A's resolution and after B's halt."""
    epoch = Epoch("st05-occ")
    discovery = epoch.activation(Role.DISCOVERY_REVIEWER)
    epoch.m2(M2Position.S3_IMPLEMENTATION_ACTIVE)
    frozen, _ = epoch.freeze(discovery, 2)
    x = epoch.cycle(None)
    halt_a = _halt(epoch, M2Position.S6_REMEDIATION_ACTIVE, x.identity)
    suspended = epoch.m4(epoch.root, AuthorizationDisposition.SUSPENDED, M4Edge.G1, None)
    resolution = epoch.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=epoch.root)))
    before = epoch.snapshot()
    epoch.resolve(halt_a)
    epoch.m2(M2Position.S6_REMEDIATION_ACTIVE, M2Edge.B13, x.identity)
    live = epoch.m4(epoch.root, AuthorizationDisposition.LIVE, M4Edge.G6, suspended)
    epoch.m2(M2Position.S7_CLOSURE_ACTIVE, cycle=x.identity)
    closure = epoch.activation(Role.BOUNDED_CLOSURE_VERIFIER, cycle=x)
    epoch.assess(closure, frozen.members[0], closed=True, cycle=x)
    y = epoch.cycle(closure.identity)
    halt_b = _halt(epoch, M2Position.S6_REMEDIATION_ACTIVE, y.identity)
    epoch.m4(epoch.root, AuthorizationDisposition.SUSPENDED, M4Edge.G1, live)
    return before, epoch.snapshot(), resolution.identity, epoch.root, halt_a, halt_b


@pytest.mark.traces("B13", "G6", "K-9", "AP04-I39", "AP04-I29", "ST05-B1", "ST05-M1")
def test_b13_restores_the_named_halts_position_and_cycle_occurrence() -> None:
    """`ST05-IMPL-R03`, `HB-1` as restated, `SV11-6`: two halts at `S6`, in cycle
    occurrences X and then Y, each halting before any envelope was derived there. Resuming
    each gives `S6` both times, bound to X and to Y respectively — distinguishable results,
    each the named halt's own recorded occurrence, never the most recent one. Once X's halt
    is resolved it can no longer be named, so the earlier cycle is never restored again."""
    before, after, resolution, root, halt_x, halt_y = _two_cycle_halts()
    s6 = M2Position.S6_REMEDIATION_ACTIVE
    assert not [
        r
        for r in before.records
        if isinstance(r, AuthorityEnvelopeRecord)
        and r.cycle_occurrence in (halt_x.cycle_occurrence, halt_y.cycle_occurrence)
    ]
    derived_x, act_x = _resume(before, resolution, root, halt_x.identity)
    assert derived_x[model.RESTORED_OCCURRENCE_BOUND.name] == model.TRUE
    assert derived_x[sm.NAMED_HALT] == halt_x.identity.value
    assert isinstance(act_x, sm.Act) and act_x.m4 is not None
    assert act_x.m2.restored == sm.Restoration(halt_x.identity, s6, halt_x.cycle_occurrence)
    derived_y, act_y = _resume(after, resolution, root, halt_y.identity)
    assert derived_y[model.SINGLE_OUTSTANDING_OCCURRENCE.name] == model.TRUE
    assert isinstance(act_y, sm.Act)
    assert act_y.m2.restored == sm.Restoration(halt_y.identity, s6, halt_y.cycle_occurrence)
    assert act_x.m2.target == act_y.m2.target == s6
    assert act_x.m2 != act_y.m2 and halt_x.cycle_occurrence != halt_y.cycle_occurrence
    assert sm.recorded_restoration(after, halt_x.identity) == act_x.m2.restored
    stale, refused = _resume(after, resolution, root, halt_x.identity)
    assert stale[model.DECISION_NAMES_OUTSTANDING_OCCURRENCE.name] == model.FALSE
    assert isinstance(refused, sm.Refused)


def _joint(
    facts_records: dv.AuthoritativeRecords,
    restoration_records: dv.AuthoritativeRecords,
    resolution: RootResolutionId,
    root: OwnerAuthorizationId,
    facts_for: HaltOccurrence,
    restoration_of: HaltOccurrence,
) -> sm.Act | sm.Refused:
    """The joint `B13`/`G6` act over guard facts read for one halt and a restoration read
    for another (or the same) — each from the records, exactly as its reader gives it."""
    derived = sm.derived_guard_facts(facts_records, resolution, root, named_halt=facts_for.identity)
    restored = sm.recorded_restoration(restoration_records, restoration_of.identity)
    assert isinstance(restored, sm.Restoration)
    return sm.evaluate_act(
        M2Edge.B13,
        M2Position.S9_EPOCH_HALTED,
        AuthorizationDisposition.SUSPENDED,
        _resumption_facts(derived),
        restored,
    )


@pytest.mark.traces("B13", "G6", "K-9", "AP04-I39", "AP04-I29", "ST05-B1", "ST05-M1")
def test_b13_admits_only_the_restoration_of_the_halt_its_facts_were_read_for() -> None:
    """`ST05-IMPL-R03`, `SV11-6`: one coherent halt context for the joint act. Halts A and B
    are both at `S6`, in different cycle occurrences; A is resolved and B is the sole
    outstanding halt. A's facts with A's restoration (before A's resolution) and B's facts
    with B's restoration are admitted, each restoring its own halt. B's facts with A's
    restoration — the same position — and A's facts with B's restoration are refused, and
    so neither `B13` nor `G6` moves; for B's facts only B's restoration is admissible.
    Facts that name no halt are refused: an anonymous fact set proves no occurrence."""
    before, after, resolution, root, a, b = _two_cycle_halts()
    assert a.source_state == b.source_state == M2Position.S6_REMEDIATION_ACTIVE
    assert a.cycle_occurrence != b.cycle_occurrence
    a_with_a = _joint(before, before, resolution, root, a, a)
    assert isinstance(a_with_a, sm.Act) and a_with_a.m4 is not None
    assert a_with_a.m2.restored is not None and a_with_a.m2.restored.halt == a.identity
    b_with_b = _joint(after, after, resolution, root, b, b)
    assert isinstance(b_with_b, sm.Act) and b_with_b.m4 is not None
    assert b_with_b.m2.restored is not None and b_with_b.m2.restored.halt == b.identity
    assert b_with_b.m2.restored.cycle_occurrence == b.cycle_occurrence
    restoration_refused = sm.Refused(M2Edge.B13, M2Position.S9_EPOCH_HALTED, sm.RESTORATION, ())
    assert _joint(after, after, resolution, root, b, a) == restoration_refused
    assert _joint(before, after, resolution, root, a, b) == restoration_refused
    assert isinstance(_joint(after, after, resolution, root, a, b), sm.Refused)
    assert isinstance(_joint(after, after, resolution, root, a, a), sm.Refused)
    admissible = [
        h.identity
        for h in (a, b)
        if isinstance(_joint(after, after, resolution, root, b, h), sm.Act)
    ]
    assert admissible == [b.identity]
    derived = sm.derived_guard_facts(after, resolution, root, named_halt=b.identity)
    anonymous = {k: v for k, v in _resumption_facts(derived).items() if k != sm.NAMED_HALT}
    restored = sm.recorded_restoration(after, b.identity)
    assert isinstance(restored, sm.Restoration)
    unbound = sm.evaluate_act(
        M2Edge.B13,
        M2Position.S9_EPOCH_HALTED,
        AuthorizationDisposition.SUSPENDED,
        anonymous,
        restored,
    )
    assert unbound == restoration_refused


@pytest.mark.traces("B13", "AP04-I39", "ST05-B1", "ST05-D2", "ST05-M1")
def test_b13_refuses_a_cycle_occurrence_binding_that_is_missing_or_inconsistent() -> None:
    """`HB-1` as restated, fail closed (`P-04`): a halt at `S6` recording no occurrence, a
    halt off `S6`/`S7` recording one, one naming an occurrence never recorded or another
    epoch's, and an unreadable `RC-33` each leave `B13` refused — the occurrence is never
    invented or borrowed. A restoration that is absent or disagrees with the guard's
    position refuses at `RESTORATION`."""
    other = Epoch("st05-occ-other")
    foreign = other.cycle(None).identity
    unrecorded = CycleOccurrenceId(value=token())
    s3, s6 = M2Position.S3_IMPLEMENTATION_ACTIVE, M2Position.S6_REMEDIATION_ACTIVE
    cases = (
        (s6, "absent", model.FALSE),
        (s3, "own", model.FALSE),
        (s6, "unrecorded", model.FALSE),
        (s6, "foreign", model.FALSE),
        (s6, "own", model.TRUE),
    )
    name = model.RESTORED_OCCURRENCE_BOUND.name
    for index, (source, recorded, expected) in enumerate(cases):
        epoch = Epoch(f"st05-occ-{index}")
        own = epoch.cycle(None).identity
        cycle = {"absent": None, "own": own, "unrecorded": unrecorded, "foreign": foreign}[recorded]
        halt = _halt(epoch, source, cycle)
        epoch.m4(epoch.root, AuthorizationDisposition.SUSPENDED, M4Edge.G1, None)
        resolution = epoch.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=epoch.root)))
        records = epoch.snapshot(other)
        derived, act = _resume(records, resolution.identity, epoch.root, halt.identity)
        assert derived[name] == expected, recorded
        if expected == model.TRUE:
            assert isinstance(act, sm.Act) and act.m2.restored is not None
            assert act.m2.restored.cycle_occurrence == present(own)
        else:
            assert isinstance(act, sm.Refused), recorded
            assert sm.Unmet("B13-4", name, model.FALSE) in act.unmet, recorded
        unreadable = dv.AuthoritativeRecords(
            records.records, unreadable=frozenset({CycleOccurrence})
        )
        derived, act = _resume(unreadable, resolution.identity, epoch.root, halt.identity)
        if cycle is not None:
            assert name not in derived and isinstance(act, sm.Refused), recorded
        facts = _resumption_facts(
            sm.derived_guard_facts(
                records, resolution.identity, epoch.root, named_halt=halt.identity
            )
        )
        for given in (None, sm.Restoration(halt.identity, M2Position.S7_CLOSURE_ACTIVE, ABSENT)):
            found = sm.evaluate(M2Edge.B13, M2Position.S9_EPOCH_HALTED, facts, given)
            assert isinstance(found, sm.Refused), recorded
            if expected == model.TRUE:
                assert found == sm.Refused(
                    M2Edge.B13, M2Position.S9_EPOCH_HALTED, sm.RESTORATION, ()
                )


# --- mutation ------------------------------------------------------------------------------------


@pytest.mark.traces("ST05-M1", "ST05-M2")
@pytest.mark.parametrize("mutant", mutation.ST05_MUTANTS, ids=lambda m: m.identifier)
def test_every_st05_mutant_is_killed_and_its_control_survives(mutant: mutation.Mutant) -> None:
    """`MU11-7`: each mutant is killed by its named test, by an assertion, and the same
    substitution without the mutation is not (`MU11-2a`: no score, per mutant only)."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.identifier
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST05-M1", "ST05-M2")
def test_the_st05_mutation_inventory_omits_no_guard_rp_or_ce_condition() -> None:
    """Completeness: every (edge, part, condition) of the model has exactly one mutant —
    `RP-1`…`RP-7` on both `B13` and `G6`, `CE-0a`…`CE-6` on both `B8` and `B15`, every
    `CP-*` on `C4` — and every tagged evaluator line carries exactly one mutant. The
    scope is not widened: ST-05's tags are its two guards and appear only in its modules."""
    expected = {
        (str(rule.edge), part, condition.identifier)
        for rule in model.EDGES
        for part, conditions in mutation._model_parts(rule)
        for condition in conditions
    }
    found = [(m.edge, m.part, m.condition) for m in mutation.ST05_MODEL_MUTANTS]
    assert len(found) == len(set(found)) and set(found) == expected
    for edges, ids in (
        (("B13", "G6"), [f"RP-{n}" for n in range(1, 8)]),
        (("B8", "B15"), ["CE-0a", "CE-0b", "CE-0c", "CE-0d", *(f"CE-{n}" for n in range(1, 7))]),
        (("C4",), [f"CP-{n}" for n in range(1, 6)]),
    ):
        for edge in edges:
            for identifier in ids:
                assert [f for f in found if f[0] == edge and f[2] == identifier], (edge, identifier)
    inverted = {(m.edge, m.condition): m.killer for m in mutation.ST05_INVERSION_MUTANTS}
    assert set(inverted) == {("C1", "C1-6"), ("C2", "C2-8"), ("B13", "B13-4")}
    for mutant in mutation.ST05_MODEL_MUTANTS:
        if mutant.condition in mutation.ST05_DEDICATED_KILLERS:
            assert mutant.killer == mutation.ST05_DEDICATED_KILLERS[mutant.condition]
            assert inverted[(mutant.edge, mutant.condition)] == mutant.killer
    source = (REPOSITORY_ROOT / ST05_MODULES[1]).read_text(encoding="utf-8")
    tagged = [line for line in source.splitlines() if "# guard:ga_transition_evaluator" in line]
    assert len(tagged) == len(mutation.ST05_EVALUATOR_MUTANTS) == 12
    for line in tagged:
        assert sum(m.original in line for m in mutation.ST05_EVALUATOR_MUTANTS) == 1, line
    tags = mutation.guard_tags()
    assert {g for g in tags if g.startswith("ga_transition")} == {
        "ga_transition_guard",
        "ga_transition_evaluator",
    }
    for guard in ("ga_transition_guard", "ga_transition_evaluator"):
        assert all(
            t.startswith(("state_machine_model.py:", "state_machine.py:")) for t in tags[guard]
        )
        assert set(mutation.GUARDS[guard].guarantees) <= set(traceability.inventory())
    for other, locations in tags.items():
        if not other.startswith("ga_transition"):
            assert not [t for t in locations if t.startswith("state_machine")], other
