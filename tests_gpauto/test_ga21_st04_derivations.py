"""`GP-AUTO-ST-04`: each derivation it implements, from authoritative records alone.

Design basis: AP-11 ST-04 derivation-ownership amendment §2 (Tests, Negative tests),
`DO11-1`…`DO11-3`; AP-07 §8 (`DV-1`…`DV-8`, `DV-12`, `DV-14`); AP-04 §3, §4.1, §5.3.1,
§6; AP-04 amendment §3.3 (`CYCLE_BOUND`); AP-05 §6.2, §8.2, §8.4; `ST01C-2` F-5, F-6,
`SC01-6`; O6 clarification `O6C-2`.

Every case is built as an in-memory record set by `st04_world.Epoch`, because every
derivation is a pure function of records; `test_ga22` repeats the evidence over records
persisted in, and read back from, the store. Each test asserts the derived value and — for
the negative half of each rule — that the wrong input, present in the same record set,
changed nothing. Those are the tests `mutation.py` names as killers.
"""

from __future__ import annotations

import ast
import inspect
from typing import cast

import pytest
from pydantic import BaseModel, ValidationError

from gpauto import derivations as dv
from gpauto.authorization import (
    AuthorityAmbiguity,
    DistinctMultiplicityForm,
    SuspendedDisposition,
)
from gpauto.coordination_identity import ConformanceDeterminationId, CycleOccurrenceId
from gpauto.coordination_records import (
    ActivationEffectRecord,
    AdoptionDetermination,
    AmbiguityResult,
    ConformanceDetermination,
    CycleOccurrence,
    EffectEnvelopeConformance,
    EnvelopeConformanceDetermination,
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
    RefusalResult,
    ResolvedRootResult,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import (
    M1Edge,
    M2Edge,
    M2Position,
    M3Position,
    M4Edge,
    Machine,
)
from gpauto.governance import DisputeResolutionDecision, OwnerDecision
from gpauto.identity import (
    ActivationEffectId,
    AuthorityAmbiguityId,
    FindingId,
    FrozenFindingSetId,
    OwnerAuthorizationId,
    RemediationObligationId,
    RootResolutionId,
    WorkerActivationId,
)
from gpauto.review import RemediationObligation
from gpauto.store import CoordinationStore, UnreadableRecord
from gpauto.vocabulary import AuthorizationDisposition, OwnerDecisionKind, Role
from st03_world import ABSENT
from st04_world import Epoch, present, token

GPAUTO_STAGE = "GP-AUTO-ST-04"

S = M2Position


def permutations(records: dv.AuthoritativeRecords) -> list[dv.AuthoritativeRecords]:
    """The same records in several read orders — a derivation must not see the difference."""
    forward = records.records
    half = len(forward) // 2
    return [
        records,
        dv.AuthoritativeRecords(tuple(reversed(forward)), records.unreadable),
        dv.AuthoritativeRecords(forward[half:] + forward[:half], records.unreadable),
        dv.AuthoritativeRecords(forward[1::2] + forward[::2], records.unreadable),
    ]


# --- scenarios ------------------------------------------------------------------------


class Remediated:
    """One epoch through a halted-and-resumed remediation and a completed closure."""

    def __init__(self, tag: str = "r") -> None:
        e = self.epoch = Epoch(tag)
        self.implementer = e.activation(
            Role.IMPLEMENTER, effects=(("M src/a.py", True), ("M docs/outside.md", False))
        )
        e.m2(S.S3_IMPLEMENTATION_ACTIVE)
        self.discovery = e.activation(Role.DISCOVERY_REVIEWER, effects=(("A notes.md", True),))
        e.m2(S.S4_DISCOVERY_ACTIVE)
        self.frozen, self.obligations = e.freeze(self.discovery, 3)
        self.cycle = e.cycle(None)
        self.failed = e.activation(
            Role.REMEDIATOR,
            outcome="unadopted",
            effects=(("M src/failed.py", True),),
            cycle=self.cycle,
        )
        e.m2(S.S9_EPOCH_HALTED, cycle=self.cycle.identity)
        e.m2(S.S6_REMEDIATION_ACTIVE, M2Edge.B13, self.cycle.identity)
        self.remediator = e.activation(
            Role.REMEDIATOR, effects=(("M src/b.py", True),), cycle=self.cycle
        )
        e.m2(S.S7_CLOSURE_ACTIVE, cycle=self.cycle.identity)
        self.closure = e.activation(Role.BOUNDED_CLOSURE_VERIFIER, cycle=self.cycle)
        f1, f2, f3 = self.frozen.members
        e.assess(self.closure, f1, closed=True, cycle=self.cycle)
        e.assess(self.closure, f2, closed=False, cycle=self.cycle)
        e.assess(self.closure, f3, closed=True, cycle=self.cycle)
        self.o1, self.o2, self.o3 = (o.identity for o in self.obligations)

    def snapshot(self, *others: Epoch) -> dv.AuthoritativeRecords:
        return self.epoch.snapshot(*others)


def other_epoch() -> tuple[Epoch, Remediated]:
    """A second epoch, with its own completed activations, set and attestations."""
    other = Remediated("o")
    return other.epoch, other


# --- DV-6: position by predecessor reference ------------------------------------------


@pytest.mark.traces("DV-6", "ST04-T2", "ST04-D1")
def test_each_subject_position_is_its_own_chain_walked_by_reference() -> None:
    """`DV-6`: M1 … M4 each reached by predecessor reference over the subject's own
    entries only, whatever order the records are read in (`PA-04`, `SRF11-1`)."""
    a = Remediated("a")
    b_epoch, b = other_epoch()
    a.epoch.m4(a.epoch.root, AuthorizationDisposition.SUSPENDED, M4Edge.G1, None)
    b_first = b_epoch.m4(b_epoch.root, AuthorizationDisposition.SUSPENDED, M4Edge.G1, None)
    b_epoch.m4(b_epoch.root, AuthorizationDisposition.LIVE, M4Edge.G6, b_first)
    for records in permutations(a.snapshot(b_epoch)):
        m2 = dv.derive_m2_position(records, a.epoch.root)
        assert isinstance(m2, dv.Occupancy)
        assert m2.reached == a.epoch.head
        assert [entry.state for entry in m2.chain] == [
            S.S1_EPOCH_OPENED,
            S.S2_ENTRY_BOUNDARY_FIXED,
            S.S3_IMPLEMENTATION_ACTIVE,
            S.S4_DISCOVERY_ACTIVE,
            S.S5_FINDING_SET_FROZEN,
            S.S6_REMEDIATION_ACTIVE,
            S.S9_EPOCH_HALTED,
            S.S6_REMEDIATION_ACTIVE,
            S.S7_CLOSURE_ACTIVE,
        ]
        m3 = dv.derive_m3_position(records, a.closure.envelope)
        assert isinstance(m3, dv.Occupancy)
        assert m3.reached.state == M3Position.ACTIVATION_COMPLETED
        assert {entry.identity.envelope for entry in m3.chain} == {a.closure.envelope}
        failed = dv.derive_m3_position(records, a.failed.envelope)
        assert isinstance(failed, dv.Occupancy)
        assert failed.reached.state == M3Position.ACTIVATION_CLOSED_UNADOPTED
        m4a = dv.derive_m4_position(records, a.epoch.root)
        m4b = dv.derive_m4_position(records, b_epoch.root)
        assert isinstance(m4a, dv.Occupancy) and isinstance(m4b, dv.Occupancy)
        assert m4a.reached.state == AuthorizationDisposition.SUSPENDED
        assert m4b.reached.state == AuthorizationDisposition.LIVE
        assert len(m4b.chain) == 2


@pytest.mark.traces("DV-6", "ST04-T2")
def test_a_subject_with_no_entry_is_unoccupied_not_indeterminate() -> None:
    """`DV-6`: no entry is an affirmative absence (`CO-14`), distinct from a broken chain."""
    records = Remediated().snapshot()
    unknown = OwnerAuthorizationId(value="never-resolved")
    assert dv.derive_m2_position(records, unknown) == dv.Unoccupied(Machine.M2)
    assert dv.derive_m4_position(records, unknown) == dv.Unoccupied(Machine.M4)
    assert dv.derive_m1_position(records, RootResolutionId(value="none")) == dv.Unoccupied(
        Machine.M1
    )


@pytest.mark.traces("DV-6", "ST04-T2", "ST04-N2")
def test_a_forked_rootless_or_dangling_chain_is_indeterminate_never_tie_broken() -> None:
    """A record set the append-only rule does not produce is not read by storage order,
    recency or any tie-break: it is `BROKEN_CHAIN` (`PA-04`, `RC-4`)."""
    e = Epoch("chain")
    first = e.records[0]
    assert isinstance(first, M2PositionEntry)
    fork = first.model_copy(
        update={
            "identity": first.identity.model_copy(update={"discriminator": token()}),
            "predecessor": present(first.identity),
            "state": S.S9_EPOCH_HALTED,
        }
    )
    second_first = first.model_copy(
        update={"identity": first.identity.model_copy(update={"discriminator": token()})}
    )
    dangling = first.model_copy(
        update={
            "identity": first.identity.model_copy(update={"discriminator": token()}),
            "predecessor": present(first.identity.model_copy(update={"discriminator": token()})),
        }
    )
    for extra in (fork, second_first, dangling):
        records = dv.AuthoritativeRecords((*e.records, extra))
        outcome = dv.derive_m2_position(records, e.root)
        assert isinstance(outcome, dv.Indeterminate), extra
        assert outcome.cause == dv.IndeterminacyCause.BROKEN_CHAIN


@pytest.mark.traces("DV-6", "DV-12", "ST04-T1")
def test_an_unreadable_input_class_makes_the_derivation_indeterminate() -> None:
    """`RC-4`, `VM-6`: an unreadable record might be the deciding one, so a derivation
    over its class is indeterminate rather than computed over the readable rest."""
    a = Remediated()
    records = dv.AuthoritativeRecords(a.snapshot().records, frozenset({M2PositionEntry}))
    outcome = dv.derive_m2_position(records, a.epoch.root)
    assert outcome == dv.Indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "M2PositionEntry")
    assert isinstance(dv.derive_obligation_force(records, a.o1), dv.Indeterminate)
    assert isinstance(dv.derive_m3_position(records, a.closure.envelope), dv.Occupancy)


# --- DV-1: the prior authorized state ----------------------------------------------------


@pytest.mark.traces("DV-1", "ST04-D1", "ST04-T1")
def test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects() -> None:
    """`DV-1`, AP-04 §5.3.1: the fixed boundary plus the in-envelope effects of the
    activations completed strictly before the assessed one, in stratified order. The
    unadopted attempt, the out-of-envelope effect, the assessed activation's own effects,
    every later activation and the other epoch contribute nothing (`CN-2`, `CN-3`, `ST-1`,
    `ST-5`, `RS7-10`)."""
    a = Remediated()
    other, _ = other_epoch()
    for records in permutations(a.snapshot(other)):
        state = dv.derive_prior_authorized_state(records, a.closure.identity)
        assert isinstance(state, dv.PriorAuthorizedState)
        assert state.boundary == a.epoch.boundary.boundary
        assert state.context.authorization == a.epoch.root
        assert state.context.entry_boundary == a.epoch.boundary.boundary.identity
        assert [term.activation for term in state.terms] == [
            a.implementer.identity,
            a.discovery.identity,
            a.remediator.identity,
        ]
        observed = [sorted(e.observed_state for e in term.effects) for term in state.terms]
        assert observed == [[("M src/a.py",)], [("A notes.md",)], [("M src/b.py",)]]

        earlier = dv.derive_prior_authorized_state(records, a.discovery.identity)
        assert isinstance(earlier, dv.PriorAuthorizedState)
        assert [term.activation for term in earlier.terms] == [a.implementer.identity]

        first = dv.derive_prior_authorized_state(records, a.implementer.identity)
        assert isinstance(first, dv.PriorAuthorizedState)
        assert first.terms == ()


@pytest.mark.traces("DV-1", "DV-12")
def test_the_prior_authorized_state_is_indeterminate_without_its_inputs() -> None:
    """No boundary, an unknown activation, or a completion without its adoption record is
    indeterminate — never a state computed from what happens to be present (`RC-4`)."""
    a = Remediated()
    without_boundary = dv.AuthoritativeRecords(
        tuple(r for r in a.snapshot().records if r is not a.epoch.boundary)
    )
    outcome = dv.derive_prior_authorized_state(without_boundary, a.closure.identity)
    assert isinstance(outcome, dv.Indeterminate)
    assert outcome.cause == dv.IndeterminacyCause.MISSING_RECORD

    unknown = dv.derive_prior_authorized_state(a.snapshot(), WorkerActivationId(value="unknown"))
    assert isinstance(unknown, dv.Indeterminate)

    adoption_dropped = dv.AuthoritativeRecords(
        tuple(
            r
            for r in a.snapshot().records
            if not (
                isinstance(r, ConformanceDetermination)
                and r.identity.activation == a.implementer.identity
                and isinstance(r.determination, AdoptionDetermination)
            )
        )
    )
    inconsistent = dv.derive_prior_authorized_state(adoption_dropped, a.closure.identity)
    assert isinstance(inconsistent, dv.Indeterminate)
    assert inconsistent.cause == dv.IndeterminacyCause.INCONSISTENT_RECORDS


@pytest.mark.traces("DV-1", "ST04-D1")
def test_the_prior_authorized_state_is_computed_for_the_named_activation() -> None:
    """`DV-1` is the assessed activation's: of two activations, each one's state is its
    own — the later one's holds the earlier one's effects, the earlier one's holds none."""
    e = Epoch("named")
    first = e.activation(Role.IMPLEMENTER, effects=(("M src/a.py", True),))
    e.m2(S.S3_IMPLEMENTATION_ACTIVE)
    second = e.activation(Role.DISCOVERY_REVIEWER)
    for records in permutations(e.snapshot()):
        later = dv.derive_prior_authorized_state(records, second.identity)
        assert isinstance(later, dv.PriorAuthorizedState)
        assert [term.activation for term in later.terms] == [first.identity]
        earlier = dv.derive_prior_authorized_state(records, first.identity)
        assert isinstance(earlier, dv.PriorAuthorizedState) and earlier.terms == ()


# --- DV-1: every envelope determination of an effect (ST04-IMPL-R01) --------------------


def effect_of(a: Remediated, observed: str) -> ActivationEffectId:
    (found,) = [
        r.identity
        for r in a.epoch.records
        if isinstance(r, ActivationEffectRecord)
        and r.identity.parent_activation == a.implementer.identity
        and r.observed_state == (observed,)
    ]
    return found


def envelope_record(
    a: Remediated, judgements: tuple[tuple[str, bool], ...]
) -> ConformanceDetermination:
    """One more `RC-39` envelope-conformance record for the implementer, naming its
    effects by observed state — in exactly the order given, repeats included."""
    return ConformanceDetermination(
        identity=ConformanceDeterminationId(
            activation=a.implementer.identity, discriminator=token()
        ),
        determination=EnvelopeConformanceDetermination(
            effects=tuple(
                EffectEnvelopeConformance(effect=effect_of(a, observed), within_envelope=within)
                for observed, within in judgements
            ),
            violations=ABSENT,
        ),
    )


def implementer_envelope_records(a: Remediated) -> list[ConformanceDetermination]:
    return [
        r
        for r in a.epoch.records
        if isinstance(r, ConformanceDetermination)
        and r.identity.activation == a.implementer.identity
        and isinstance(r.determination, EnvelopeConformanceDetermination)
    ]


def with_envelope_records(
    a: Remediated, replacement: list[ConformanceDetermination]
) -> dv.AuthoritativeRecords:
    """The scenario's records, with the implementer's envelope-conformance records
    replaced by `replacement`, in that order and in the original record's place."""
    (original,) = implementer_envelope_records(a)
    place = a.epoch.records.index(original)
    records = [r for r in a.epoch.records if r is not original]
    return dv.AuthoritativeRecords(tuple(records[:place] + replacement + records[place:]))


AGREED = (("M src/a.py", True), ("M docs/outside.md", False))


@pytest.mark.traces("DV-1", "DV-12", "ST04-D1", "ST04-T1")
@pytest.mark.parametrize(
    "records",
    [
        pytest.param((AGREED,), id="one-determination"),
        pytest.param((AGREED, AGREED), id="duplicate-agreeing-records"),
        pytest.param((tuple(reversed(AGREED)), AGREED), id="duplicate-agreeing-reordered"),
        pytest.param(
            ((("M src/a.py", True), ("M src/a.py", True), ("M docs/outside.md", False)),),
            id="duplicate-agreeing-within-one-record",
        ),
        pytest.param(
            ((("M src/a.py", True),), (("M docs/outside.md", False),)),
            id="effects-split-across-records",
        ),
    ],
)
def test_agreeing_envelope_determinations_give_the_one_recorded_judgement(
    records: tuple[tuple[tuple[str, bool], ...], ...],
) -> None:
    """`RS7-10`: one determination, or several that agree, is one judgement per effect —
    the same prior state as the single-record case, in every read order."""
    a = Remediated()
    reference = dv.derive_prior_authorized_state(a.snapshot(), a.closure.identity)
    assert isinstance(reference, dv.PriorAuthorizedState)
    view = with_envelope_records(a, [envelope_record(a, judged) for judged in records])
    for ordered in permutations(view) * 2:
        assert dv.derive_prior_authorized_state(ordered, a.closure.identity) == reference
    first = reference.terms[0]
    assert first.activation == a.implementer.identity
    assert {e.identity for e in first.effects} == {effect_of(a, "M src/a.py")}


CONFLICTING: dict[str, tuple[tuple[tuple[str, bool], ...], ...]] = {
    "conflict-across-records": (
        (("M src/a.py", True), ("M docs/outside.md", False)),
        (("M src/a.py", True), ("M docs/outside.md", True)),
    ),
    "conflict-across-records-reversed": (
        (("M src/a.py", True), ("M docs/outside.md", True)),
        (("M src/a.py", True), ("M docs/outside.md", False)),
    ),
    "conflict-within-one-record": (
        (("M src/a.py", True), ("M docs/outside.md", False), ("M docs/outside.md", True)),
    ),
    "conflict-within-one-record-reversed": (
        (("M src/a.py", True), ("M docs/outside.md", True), ("M docs/outside.md", False)),
    ),
}
"""The same disagreement in every arrangement: across two records in either order, and
within one record in either order. The within-one-record pair is the reported defect —
per-effect judgements were keyed by last write, so the two orders gave two different
determinate states. Only `M docs/outside.md` conflicts; `M src/a.py` agrees throughout."""

CONFLICT = dv.Indeterminate(
    dv.IndeterminacyCause.INCONSISTENT_RECORDS,
    "conflicting envelope-conformance determinations for one effect",
)


@pytest.mark.traces("DV-1", "DV-12", "ST04-D1", "ST04-T1")
def test_conflicting_envelope_determinations_for_one_effect_make_dv1_indeterminate() -> None:
    """`ST04-IMPL-R01`, `RS7-10`, `DV-12`, `RC-4`: when determinations disagree about one
    effect, `DV-1` is indeterminate — never the first, the last, or a dictionary winner —
    and it is the **same** indeterminate result for every arrangement of the disagreement,
    in every read order, on every call. One agreeing effect beside the conflicting one
    does not rescue the term. A derivation that does not read the conflicted term — the
    implementer's own prior state — is unaffected."""
    outcomes: dict[str, set[object]] = {}
    for name, arrangement in CONFLICTING.items():
        a = Remediated()
        view = with_envelope_records(a, [envelope_record(a, judged) for judged in arrangement])
        results = outcomes.setdefault(name, set())
        for ordered in permutations(view) * 3:
            results.add(dv.derive_prior_authorized_state(ordered, a.closure.identity))
            results.add(dv.derive_prior_authorized_state(ordered, a.discovery.identity))
            own = dv.derive_prior_authorized_state(ordered, a.implementer.identity)
            assert isinstance(own, dv.PriorAuthorizedState) and own.terms == ()
    assert outcomes == {name: {CONFLICT} for name in CONFLICTING}, outcomes


# --- the read: decoding and consistency (ST04-IMPL-R03) ---------------------------------


class ScriptedStore:
    """An in-memory stand-in for the store, read as `read_authoritative_records` reads it:
    one `enumerate` per class per pass. `second_pass_extra` appears only from the second
    pass on, as a unit committed between the passes would; `undecodable` is returned as an
    `UnreadableRecord` in every pass. Every call is recorded."""

    def __init__(
        self,
        records: tuple[BaseModel, ...],
        *,
        second_pass_extra: tuple[BaseModel, ...] = (),
        undecodable: type[BaseModel] | None = None,
    ) -> None:
        self.records = records
        self.second_pass_extra = second_pass_extra
        self.undecodable = undecodable
        self.calls: list[type[BaseModel]] = []

    def enumerate(self, kind: type[BaseModel]) -> tuple[BaseModel | UnreadableRecord, ...]:
        self.calls.append(kind)
        second_pass = len(self.calls) > len(dv.DERIVATION_INPUTS)
        visible = self.records + (self.second_pass_extra if second_pass else ())
        found: tuple[BaseModel | UnreadableRecord, ...] = tuple(
            r for r in visible if type(r) is kind
        )
        if kind is self.undecodable:
            found += (UnreadableRecord(kind.__name__, (("identity", "x"),), "unknown format"),)
        return found


def read(store: ScriptedStore) -> dv.AuthoritativeRecords:
    return dv.read_authoritative_records(cast(CoordinationStore, store))


def owned_derivations(records: dv.AuthoritativeRecords, a: Remediated) -> list[object]:
    return [
        dv.derive_prior_authorized_state(records, a.closure.identity),
        dv.derive_closure_scope(records, a.closure.identity),
        dv.derive_cycle_bound(records, a.epoch.root),
        dv.derive_liveness(records, a.epoch.root),
        dv.derive_obligation_force(records, a.o1),
        dv.derive_m2_position(records, a.epoch.root),
        dv.derive_m3_position(records, a.closure.envelope),
        dv.derive_m4_position(records, a.epoch.root),
        dv.derive_outstanding_halts(records),
        dv.derive_closure_scope_series(records, a.epoch.root),
    ]


@pytest.mark.traces("ST04-T1", "DV-12", "ST04-N2")
def test_a_read_whose_two_passes_differ_is_unstable_and_never_used() -> None:
    """`ST04-IMPL-R03`: both passes decode every record, but the second sees one more `M2`
    entry. The read fails closed — no record is kept, and every derivation is
    indeterminate — and says why: an **unstable read**, not an unreadable record. There
    is no retry: exactly two passes, one `enumerate` per class each. A stable read of the
    same records is unchanged: it yields the records and the derivations computed from
    them directly."""
    a = Remediated()
    late = a.epoch.m2(S.S8_GATE_REACHED)
    before = tuple(r for r in a.epoch.records if r is not late)

    torn = ScriptedStore(before, second_pass_extra=(late,))
    records = read(torn)
    assert torn.calls == list(dv.DERIVATION_INPUTS) * 2
    assert records.records == ()
    assert records.unreadable == frozenset()
    assert records.unstable == frozenset(dv.DERIVATION_INPUTS)
    for outcome in owned_derivations(records, a):
        assert isinstance(outcome, dv.Indeterminate), outcome
        assert outcome.cause == dv.IndeterminacyCause.UNSTABLE_READ
        assert "the two read passes differ" in outcome.detail

    stable = ScriptedStore(before)
    kept = read(stable)
    assert stable.calls == list(dv.DERIVATION_INPUTS) * 2
    assert kept.unreadable == kept.unstable == frozenset()
    direct = dv.AuthoritativeRecords(before)
    assert sorted(map(repr, kept.records)) == sorted(map(repr, direct.records))
    assert owned_derivations(kept, a) == owned_derivations(direct, a)
    assert not any(isinstance(o, dv.Indeterminate) for o in owned_derivations(kept, a))


@pytest.mark.traces("ST04-T1", "DV-12")
def test_an_undecodable_stored_record_marks_its_class_unreadable() -> None:
    """`VM-6`, `RC-4`: a stored `RC-13` record that does not decode is surfaced as its
    class being unreadable — never dropped — so force, which that record might decide, is
    indeterminate as `UNREADABLE_INPUT`; the other classes stay readable, and the read is
    stable, not torn."""
    e, (o1, _) = frozen_epoch()
    store = ScriptedStore(tuple(e.records), undecodable=OwnerDecision)
    records = read(store)
    assert records.unreadable == frozenset({OwnerDecision})
    assert records.unstable == frozenset()
    outcome = dv.derive_obligation_force(records, o1)
    assert outcome == dv.Indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "OwnerDecision")
    assert isinstance(dv.derive_m2_position(records, e.root), dv.Occupancy)


# --- DV-2: closure scope ---------------------------------------------------------------------


@pytest.mark.traces("DV-2", "ST04-T4", "ST04-D1")
def test_closure_scope_is_the_findings_that_closure_activations_assessments_name() -> None:
    """`DV-2`, `SC-1`: computed from the `ClosureAssessment`s naming this closure
    activation, and no other's; empty where it assessed nothing."""
    series = Cycled()
    records = series.epoch.snapshot()
    for view in permutations(records):
        first = dv.derive_closure_scope(view, series.closures[0].identity)
        assert first == dv.ClosureScope(series.closures[0].identity, frozenset(series.members))
        second = dv.derive_closure_scope(view, series.closures[1].identity)
        assert isinstance(second, dv.ClosureScope)
        assert second.members == frozenset(series.members[1:])
    nothing = dv.derive_closure_scope(records, series.remediators[0].identity)
    assert nothing == dv.ClosureScope(series.remediators[0].identity, frozenset())


# --- DV-5: obligation force ----------------------------------------------------------------


def frozen_epoch() -> tuple[Epoch, tuple[RemediationObligationId, RemediationObligationId]]:
    """An epoch at `S5` with a two-member frozen set: both obligations in force."""
    e = Epoch("force")
    discovery = e.activation(Role.DISCOVERY_REVIEWER)
    e.m2(S.S3_IMPLEMENTATION_ACTIVE)
    _, (o1, o2) = e.freeze(discovery, 2)
    return e, (o1.identity, o2.identity)


def force(
    records: dv.AuthoritativeRecords, obligation: RemediationObligationId
) -> dv.ObligationForce:
    outcome = dv.derive_obligation_force(records, obligation)
    assert isinstance(outcome, dv.ObligationForce), outcome
    return outcome


@pytest.mark.traces("DV-5", "ST04-T5", "ST04-D1")
def test_an_established_obligation_with_no_extinguishing_decision_is_in_force() -> None:
    """AP-05 §6.2: established at the freeze, named by no waiver or deferral, epoch
    non-terminal — in force."""
    e, (o1, o2) = frozen_epoch()
    for records in permutations(e.snapshot()):
        for obligation in (o1, o2):
            assert force(records, obligation) == dv.ObligationForce(
                obligation, True, frozenset(), False
            )


@pytest.mark.traces("DV-5", "ST04-T5")
def test_a_waiver_or_deferral_naming_the_obligation_extinguishes_it() -> None:
    """AP-05 §6.2 item 2, `ST01C-2` F-5: the decision names the obligation, and its
    existence extinguishes force. The other obligation is untouched."""
    for kind in (OwnerDecisionKind.WAIVER, OwnerDecisionKind.DEFERRAL):
        e, (o1, o2) = frozen_epoch()
        decision = e.waive(o1, kind)
        for records in permutations(e.snapshot()):
            assert force(records, o1) == dv.ObligationForce(
                o1, False, frozenset({decision.identity}), False
            )
            assert force(records, o2).in_force


@pytest.mark.traces("DV-5", "ST04-T5")
def test_a_waiver_naming_another_obligation_does_not_extinguish_this_one() -> None:
    """*"never from a stage-level decision or one that does not name it"* (ST-04 Tests)."""
    e, (o1, o2) = frozen_epoch()
    e.waive(o2)
    e.waive(o2, OwnerDecisionKind.DEFERRAL)
    assert force(e.snapshot(), o1) == dv.ObligationForce(o1, True, frozenset(), False)
    assert not force(e.snapshot(), o2).in_force


@pytest.mark.traces("DV-5", "ST04-T5")
def test_an_o6_obligation_change_does_not_extinguish_force() -> None:
    """`O6C-2`: an `OBLIGATION_CHANGE` decision names the obligation and carries
    replacement content, and changes neither force nor the applicable set."""
    e, (o1, _) = frozen_epoch()
    e.change(o1)
    e.change(o1)
    assert force(e.snapshot(), o1) == dv.ObligationForce(o1, True, frozenset(), False)


@pytest.mark.traces("DV-5", "ST04-T5")
def test_stage_level_dispute_and_correcting_decisions_do_not_change_force() -> None:
    """A `STAGE_OUTCOME` decision and a dispute naming the member are not waivers; and a
    decision whose `corrects` names a waiver revives nothing — `corrects` carries no
    precedence or latest-wins (`SC01-6`). Every extinguishing decision is carried."""
    e, (o1, o2) = frozen_epoch()
    e.settle()
    finding = o2.member_finding
    e.dispute(finding)
    assert force(e.snapshot(), o2).in_force

    waiver = e.waive(o1)
    e.decide(
        DisputeResolutionDecision(
            kind=OwnerDecisionKind.FINDING_DISPUTE,
            member=o1.member_finding,
            produced_authorization=ABSENT,
            corrects=present(waiver.identity),
        )
    )
    deferral = e.waive(o1, OwnerDecisionKind.DEFERRAL)
    assert force(e.snapshot(), o1) == dv.ObligationForce(
        o1, False, frozenset({waiver.identity, deferral.identity}), False
    )


@pytest.mark.traces("DV-5", "ST04-T5")
def test_force_ends_exactly_when_the_epoch_is_terminal() -> None:
    """AP-05 §6.2 item 3 over AP-04 §4.1: waiting `S8`/`S9` keep force; `S10` and `S11`
    end it — read from the epoch's position reached by reference, not its first entry."""
    for waiting in (S.S8_GATE_REACHED, S.S9_EPOCH_HALTED):
        e, (o1, _) = frozen_epoch()
        e.m2(waiting)
        assert force(e.snapshot(), o1) == dv.ObligationForce(o1, True, frozenset(), False)
    for terminal in (S.S10_EPOCH_SETTLED, S.S11_EPOCH_AUTHORITY_ENDED):
        e, (o1, _) = frozen_epoch()
        e.m2(S.S8_GATE_REACHED)
        e.m2(terminal)
        for records in permutations(e.snapshot()):
            assert force(records, o1) == dv.ObligationForce(o1, False, frozenset(), True)


@pytest.mark.traces("DV-5", "ST04-T5")
def test_an_obligation_not_established_for_a_member_is_not_in_force() -> None:
    """AP-05 §6.2 item 1: an obligation record for a finding outside the set's members,
    or naming no recorded set, is not an established obligation."""
    e, (o1, _) = frozen_epoch()
    stray = RemediationObligationId(
        parent_frozen_set=o1.parent_frozen_set, member_finding=FindingId(value="not-a-member")
    )
    e.records.append(RemediationObligation(identity=stray))
    assert dv.derive_obligation_force(e.snapshot(), stray) == dv.NotEstablished(stray)
    orphan = RemediationObligationId(
        parent_frozen_set=FrozenFindingSetId(value="no-such-set"), member_finding=o1.member_finding
    )
    assert dv.derive_obligation_force(e.snapshot(), orphan) == dv.NotEstablished(orphan)


@pytest.mark.traces("DV-5", "ST04-T5")
def test_an_obligation_is_established_only_by_its_own_record_and_its_own_set() -> None:
    """AP-05 §6.2 item 1: an obligation is established by **its own** `RemediationObligation`
    record under **its own** recorded frozen set. A member whose record is absent is not
    established because another member's record exists; an obligation record naming no
    recorded set is not established because another set holds its finding."""
    e, (o1, o2) = frozen_epoch()
    without_o2 = dv.AuthoritativeRecords(
        tuple(
            r for r in e.records if not (isinstance(r, RemediationObligation) and r.identity == o2)
        )
    )
    assert dv.derive_obligation_force(without_o2, o2) == dv.NotEstablished(o2)
    assert force(without_o2, o1).in_force

    orphan = RemediationObligationId(
        parent_frozen_set=FrozenFindingSetId(value="no-such-set"), member_finding=o1.member_finding
    )
    e.records.append(RemediationObligation(identity=orphan))
    assert dv.derive_obligation_force(e.snapshot(), orphan) == dv.NotEstablished(orphan)


@pytest.mark.traces("DV-5", "DV-12")
def test_force_is_indeterminate_when_its_decisions_or_epoch_cannot_be_read() -> None:
    """An unreadable `RC-13` might hold the extinguishing decision; a set whose epoch has
    no position is inconsistent. Neither is read as in force (`RC-4`)."""
    e, (o1, _) = frozen_epoch()
    unreadable = dv.AuthoritativeRecords(e.snapshot().records, frozenset({OwnerDecision}))
    outcome = dv.derive_obligation_force(unreadable, o1)
    assert isinstance(outcome, dv.Indeterminate)
    assert outcome.cause == dv.IndeterminacyCause.UNREADABLE_INPUT
    no_epoch = dv.AuthoritativeRecords(
        tuple(r for r in e.snapshot().records if not isinstance(r, M2PositionEntry))
    )
    missing = dv.derive_obligation_force(no_epoch, o1)
    assert isinstance(missing, dv.Indeterminate)
    assert missing.cause == dv.IndeterminacyCause.MISSING_RECORD


# --- DV-3: CYCLE_BOUND -----------------------------------------------------------------------


def bound(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> dv.CycleBound:
    outcome = dv.derive_cycle_bound(records, root)
    assert isinstance(outcome, dv.CycleBound), outcome
    return outcome


@pytest.mark.traces("DV-3", "ST04-T4", "ST04-D1")
def test_cycle_bound_is_the_applicable_set_minus_members_attested_closed() -> None:
    """AP-04 amendment §3.3: the in-force obligations minus every member carrying a
    `CLOSED` assessment from a completed, adopted closure activation of this epoch. A
    `NOT_CLOSED` verdict subtracts nothing (`OP-4`)."""
    a = Remediated()
    other, _ = other_epoch()
    f1, _, f3 = a.frozen.members
    for records in permutations(a.snapshot(other)):
        assert bound(records, a.epoch.root) == dv.CycleBound(
            a.epoch.root,
            a.frozen.identity,
            frozenset({a.o1, a.o2, a.o3}),
            frozenset({f1, f3}),
            frozenset({a.o2}),
        )


@pytest.mark.traces("DV-3", "ST04-T4")
def test_cycle_bound_before_any_closure_is_the_whole_applicable_set() -> None:
    """Without a completed closure activation nothing is attested: an assessment from a
    running or unadopted closure activation is not a recorded closure result of a
    completed, adopted one."""
    e, obligations = frozen_epoch()
    e.cycle(None)
    e.m2(S.S7_CLOSURE_ACTIVE)
    unadopted = e.activation(Role.BOUNDED_CLOSURE_VERIFIER, outcome="unadopted")
    running = e.activation(Role.BOUNDED_CLOSURE_VERIFIER, outcome="running")
    for obligation in obligations:
        e.assess(unadopted, obligation.member_finding, closed=True)
        e.assess(running, obligation.member_finding, closed=True)
    result = bound(e.snapshot(), e.root)
    assert result.attested == frozenset()
    assert result.members == result.applicable and len(result.members) == 2


@pytest.mark.traces("DV-3", "ST04-T4", "ST04-T5")
def test_a_waived_or_deferred_obligation_leaves_the_applicable_set_and_the_bound() -> None:
    """`OP-1`, `OP-3`: only an O5 waiver or deferral removes an obligation from the
    applicable set, and it does so without touching the frozen set."""
    for kind in (OwnerDecisionKind.WAIVER, OwnerDecisionKind.DEFERRAL):
        a = Remediated()
        a.epoch.waive(a.o2, kind)
        result = bound(a.snapshot(), a.epoch.root)
        assert result.applicable == frozenset({a.o1, a.o3})
        assert result.members == frozenset()
        assert len(a.frozen.members) == 3


@pytest.mark.traces("DV-3", "ST04-T4", "ST04-T5")
def test_an_o6_change_leaves_the_obligation_in_the_applicable_set_and_the_bound() -> None:
    """`O6C-2`: O6 content is not a same-epoch basis change and extinguishes nothing, so
    `DV-3` is unaffected."""
    a = Remediated()
    a.epoch.change(a.o2)
    a.epoch.change(a.o1)
    result = bound(a.snapshot(), a.epoch.root)
    assert result.applicable == frozenset({a.o1, a.o2, a.o3})
    assert result.members == frozenset({a.o2})


@pytest.mark.traces("DV-3", "ST04-T4")
def test_only_this_epochs_completed_closure_activations_attest() -> None:
    """A `CLOSED` assessment naming a member counts only from a completed, adopted
    BOUNDED CLOSURE VERIFIER activation **of this epoch** — not from another epoch's
    closure activation, not from a remediator named as though it were one, and not from
    an unadopted closure activation."""
    a = Remediated()
    other, b = other_epoch()
    _, f2, _ = a.frozen.members
    other.assess(b.closure, f2, closed=True)
    a.epoch.assess(a.remediator, f2, closed=True)
    stray = a.epoch.activation(Role.BOUNDED_CLOSURE_VERIFIER, outcome="unadopted")
    a.epoch.assess(stray, f2, closed=True)
    result = bound(a.snapshot(other), a.epoch.root)
    assert result.members == frozenset({a.o2})
    assert f2 not in result.attested


@pytest.mark.traces("DV-3", "ST04-T4")
def test_an_attested_member_never_re_enters_the_bound() -> None:
    """`OP-10`: a later `NOT_CLOSED` verdict on a member attested closed earlier does not
    return it — the earlier record is immutable and still exists."""
    series = Cycled()
    series.epoch.assess(series.closures[2], series.members[0], closed=False)
    result = bound(series.epoch.snapshot(), series.epoch.root)
    assert series.members[0] in result.attested
    assert all(o.member_finding != series.members[0] for o in result.members)


@pytest.mark.traces("DV-3", "ST04-T4")
def test_no_set_empty_set_and_terminal_epoch_are_three_distinct_bounds() -> None:
    """`FP-1`: no set is `NoFrozenSet`; an empty set is a real, empty `CycleBound`; a
    terminal epoch leaves nothing in force, so nothing applicable."""
    bare = Epoch("bare")
    assert dv.derive_cycle_bound(bare.snapshot(), bare.root) == dv.NoFrozenSet(bare.root)

    empty = Epoch("empty")
    discovery = empty.activation(Role.DISCOVERY_REVIEWER)
    frozen, _ = empty.freeze(discovery, 0)
    assert bound(empty.snapshot(), empty.root) == dv.CycleBound(
        empty.root, frozen.identity, frozenset(), frozenset(), frozenset()
    )

    ended = Remediated()
    ended.epoch.m2(S.S8_GATE_REACHED)
    ended.epoch.m2(S.S10_EPOCH_SETTLED)
    result = bound(ended.snapshot(), ended.epoch.root)
    assert result.applicable == frozenset() and result.members == frozenset()


@pytest.mark.traces("DV-3", "ST04-T4")
def test_cycle_bound_ranges_over_this_epochs_set_only() -> None:
    """Another epoch's frozen set and obligations are not this epoch's applicable set."""
    a = Remediated()
    other, b = other_epoch()
    result = bound(a.snapshot(other), a.epoch.root)
    assert result.frozen_set == a.frozen.identity
    assert result.applicable.isdisjoint({b.o1, b.o2, b.o3})


# --- DV-8: the closure-scope series ---------------------------------------------------


class Cycled:
    """Three cycles over one set: scopes {f1,f2,f3} ⊋ {f2,f3} ⊋ {f2}; or, with `grow`,
    {f1,f2} → {f2,f3} → {f2}, whose second step keeps the count and swaps a member."""

    def __init__(self, tag: str = "c", *, grow: bool = False) -> None:
        e = self.epoch = Epoch(tag)
        discovery = e.activation(Role.DISCOVERY_REVIEWER)
        e.m2(S.S3_IMPLEMENTATION_ACTIVE)
        frozen, _ = e.freeze(discovery, 3)
        self.members = frozen.members
        f1, f2, f3 = frozen.members
        verdicts: tuple[tuple[tuple[FindingId, bool], ...], ...] = (
            ((f1, True), (f2, False), (f3, False)) if not grow else ((f1, True), (f2, False)),
            ((f2, False), (f3, True)),
            ((f2, False),),
        )
        self.closures: list[WorkerActivationRecord] = []
        self.remediators: list[WorkerActivationRecord] = []
        self.cycles: list[CycleOccurrence] = []
        predecessor: WorkerActivationId | None = None
        for assessments in verdicts:
            cycle = e.cycle(predecessor)
            self.cycles.append(cycle)
            self.remediators.append(e.activation(Role.REMEDIATOR, cycle=cycle))
            e.m2(S.S7_CLOSURE_ACTIVE, cycle=cycle.identity)
            closure = e.activation(Role.BOUNDED_CLOSURE_VERIFIER, cycle=cycle)
            for finding, closed in assessments:
                e.assess(closure, finding, closed=closed, cycle=cycle)
            self.closures.append(closure)
            predecessor = closure.identity


@pytest.mark.traces("DV-8", "ST04-T4", "ST04-D1")
def test_the_series_follows_occurrence_references_and_strictly_decreases() -> None:
    """`DV-8`, `CO-3`, `CO-18`: `DV-2` per occurrence, walked from the first `RC-33` by
    predecessor references, and each later scope a proper subset of the one before."""
    series = Cycled()
    other = Cycled("oc")
    f1, f2, f3 = series.members
    for records in permutations(series.epoch.snapshot(other.epoch)):
        outcome = dv.derive_closure_scope_series(records, series.epoch.root)
        assert isinstance(outcome, dv.ClosureScopeSeries)
        assert [step.cycle_occurrence for step in outcome.steps] == [
            c.identity for c in series.cycles
        ]
        assert [
            step.closure.members
            for step in outcome.steps
            if isinstance(step.closure, dv.ClosureScope)
        ] == [frozenset({f1, f2, f3}), frozenset({f2, f3}), frozenset({f2})]
        assert outcome.strictly_decreasing


@pytest.mark.traces("DV-8", "ST04-T4")
def test_an_equal_count_scope_that_swaps_a_member_is_growth_not_shrinkage() -> None:
    """`SC-10`: the test is over identities, never counts — {f1,f2,f3} → {f1,f2,f3} is not
    a proper subset, and neither is a same-size scope with a different member."""
    grown = Cycled("g", grow=True)
    outcome = dv.derive_closure_scope_series(grown.epoch.snapshot(), grown.epoch.root)
    assert isinstance(outcome, dv.ClosureScopeSeries)
    assert not outcome.strictly_decreasing


@pytest.mark.traces("DV-8", "ST04-T4")
def test_an_occurrence_without_a_completed_closure_ends_the_series_affirmatively() -> None:
    """`CO-14`: the last occurrence's closure is not yet completed — it is in the series
    with `NoCompletedClosure`, never with an empty or guessed scope."""
    a = Remediated()
    open_cycle = a.epoch.cycle(a.closure.identity)
    a.epoch.m2(S.S7_CLOSURE_ACTIVE, cycle=open_cycle.identity)
    unadopted = a.epoch.activation(
        Role.BOUNDED_CLOSURE_VERIFIER, outcome="unadopted", cycle=open_cycle
    )
    a.epoch.assess(unadopted, a.frozen.members[1], closed=True, cycle=open_cycle)
    outcome = dv.derive_closure_scope_series(a.snapshot(), a.epoch.root)
    assert isinstance(outcome, dv.ClosureScopeSeries)
    assert outcome.steps[-1] == dv.SeriesStep(open_cycle.identity, dv.NoCompletedClosure())
    assert len(outcome.steps) == 2
    none = dv.derive_closure_scope_series(Epoch("n").snapshot(), Epoch("n").root)
    assert isinstance(none, dv.ClosureScopeSeries) and none.steps == ()


@pytest.mark.traces("DV-8", "ST04-T4")
def test_two_first_occurrences_in_one_epoch_are_indeterminate() -> None:
    """`CO-3`: exactly one occurrence has no predecessor; two is a broken series."""
    series = Cycled()
    series.epoch.cycle(None)
    outcome = dv.derive_closure_scope_series(series.epoch.snapshot(), series.epoch.root)
    assert isinstance(outcome, dv.Indeterminate)


# --- DV-7: outstanding halt occurrences -----------------------------------------------


@pytest.mark.traces("DV-7", "ST04-T3", "ST04-D1")
def test_outstanding_halts_are_those_no_resolution_names_and_coexist() -> None:
    """`DV-7`, `GH-6`, `GH-7`, `GE-4`: two unresolved occurrences are both outstanding —
    never collapsed into a count — and a resolved one persists and is simply not
    outstanding."""
    e = Epoch("halts")
    first, second, third = (e.refusal() for _ in range(3))
    h1 = e.halt(first.refusal.identity, S.S3_IMPLEMENTATION_ACTIVE)
    h2 = e.halt(second.refusal.identity, S.S3_IMPLEMENTATION_ACTIVE)
    h3 = e.halt(third.refusal.identity, S.S2_ENTRY_BOUNDARY_FIXED)
    e.resolve(h3)
    for records in permutations(e.snapshot()):
        assert dv.derive_outstanding_halts(records) == dv.OutstandingHalts(
            frozenset({h1.identity, h2.identity})
        )
    assert h3 in e.records


# --- DV-4, ST-04's portion: liveness ---------------------------------------------------


def liveness(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> dv.Liveness:
    outcome = dv.derive_liveness(records, root)
    assert isinstance(outcome, dv.Liveness), outcome
    return outcome


@pytest.mark.traces("ST04-D2", "DO11-2")
def test_an_instance_with_no_establishing_record_is_live() -> None:
    """`WP-9`: `LIVE` is the absence of every establishing record, never a value."""
    e = Epoch("live")
    assert liveness(e.snapshot(), e.root) == dv.Liveness(
        e.root, True, frozenset(), frozenset(), frozenset()
    )


@pytest.mark.traces("ST04-D2", "DO11-2")
def test_an_unresolved_suspending_event_makes_the_instance_not_live() -> None:
    """`WP-9`, `GH-11`: the suspension is the establishing reference to an event whose halt
    occurrence no `RC-32` names."""
    e = Epoch("halted")
    refusal = e.refusal()
    e.halt(refusal.refusal.identity, S.S3_IMPLEMENTATION_ACTIVE)
    e.suspend(e.root, refusal.refusal.identity)
    for records in permutations(e.snapshot()):
        assert liveness(records, e.root) == dv.Liveness(
            e.root, False, frozenset(), frozenset(), frozenset({refusal.refusal.identity})
        )


@pytest.mark.traces("ST04-D2", "DO11-2")
def test_a_resolution_naming_the_suspending_events_halt_restores_liveness() -> None:
    """`WP-9`: `G6` is a resolution record naming a halt occurrence, never a status flip.
    The suspension record persists; it is simply resolved."""
    e = Epoch("resumed")
    refusal = e.refusal()
    halt = e.halt(refusal.refusal.identity, S.S3_IMPLEMENTATION_ACTIVE)
    e.suspend(e.root, refusal.refusal.identity)
    e.resolve(halt)
    assert liveness(e.snapshot(), e.root).live


@pytest.mark.traces("ST04-D2", "DO11-2")
def test_a_suspension_with_no_halt_or_only_another_events_resolution_stays_unresolved() -> None:
    """No `RC-31` on the event means nothing can have resolved it; and a resolution of a
    different event's halt resolves only that event (`GH-5`)."""
    e = Epoch("unresolved")
    suspending = e.refusal()
    unrelated = e.refusal()
    e.suspend(e.root, suspending.refusal.identity)
    e.resolve(e.halt(unrelated.refusal.identity, S.S3_IMPLEMENTATION_ACTIVE))
    result = liveness(e.snapshot(), e.root)
    assert not result.live
    assert result.suspended_by == frozenset({suspending.refusal.identity})


@pytest.mark.traces("ST04-D2", "DO11-2")
def test_consumption_and_revocation_each_end_liveness_for_their_instance_only() -> None:
    """`WP-9`: a consumption or revocation record for this instance ends liveness; one for
    another instance does not — the establishing record names its instance (R-4)."""
    e = Epoch("ended")
    other = e.frame.other_root
    outcome = e.consume(e.root)
    revocation = e.revoke(other)
    records = e.snapshot()
    assert liveness(records, e.root) == dv.Liveness(
        e.root, False, frozenset({outcome}), frozenset(), frozenset()
    )
    assert liveness(records, other) == dv.Liveness(
        other, False, frozenset(), frozenset({revocation}), frozenset()
    )
    bystander = Epoch("bystander")
    combined = e.snapshot(bystander)
    assert liveness(combined, bystander.root).live


@pytest.mark.traces("ST04-D2", "DO11-2")
def test_authority_ambiguity_is_not_a_suspension_cause() -> None:
    """`SC01-4`, `M4-5`, AP-04 `T-2`: an `AuthorityAmbiguity` naming the instance as a
    competitor does not suspend it, and a suspension established by one is
    unrepresentable."""
    e = Epoch("contested")
    ambiguity = AuthorityAmbiguity(
        identity=AuthorityAmbiguityId(value=token()),
        stage=e.frame.stage,
        form=DistinctMultiplicityForm(competing_identities=(e.root, e.frame.other_root)),
    )
    records = dv.AuthoritativeRecords((*e.snapshot().records, ambiguity))
    assert liveness(records, e.root).live
    with pytest.raises(ValidationError):
        SuspendedDisposition(
            established_by_event=AuthorityAmbiguityId(value=token())  # type: ignore[arg-type]
        )
    assert AuthorityAmbiguity not in dv.DERIVATION_INPUTS


@pytest.mark.traces("ST04-D2", "DO11-3", "DO11-2")
def test_liveness_reads_no_m1_entry_so_st06_can_consume_it_without_a_cycle() -> None:
    """`DO11-3`, `RO7A-9`: liveness is the *live* conjunct ST-06 consumes; it reads no
    completing M1 entry and no ST-06 output. Adding or removing a resolution changes
    nothing, and no M1 or resolution name appears in its code."""
    e = Epoch("acyclic")
    refusal = e.refusal()
    e.halt(refusal.refusal.identity, S.S3_IMPLEMENTATION_ACTIVE)
    e.suspend(e.root, refusal.refusal.identity)
    before = liveness(e.snapshot(), e.root)
    e.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=e.root)))
    assert liveness(e.snapshot(), e.root) == before
    names = {
        node.id
        for function in (dv.derive_liveness, dv._still_suspending)
        for node in ast.walk(ast.parse(inspect.getsource(function)))
        if isinstance(node, ast.Name)
    }
    assert not {
        n for n in names if n.startswith("M1") or "Resolution" in n and "Governance" not in n
    }


# --- DV-4, ST-04's portion: eligibility as recorded ------------------------------------


@pytest.mark.traces("ST04-D3", "DO11-2")
def test_recorded_eligibility_reads_the_completing_entry_and_nothing_else() -> None:
    """`SRF11-1`, `RO7A-6`(b): an open resolution is `OpenResolution`; a completed one
    returns its completing entry's result **verbatim** — for `A2` the instance, for `A3`
    the refusal, for `A4` the ambiguity — each resolution read from its own chain."""
    e = Epoch("recorded")
    opened = e.resolution(None)
    resolved = e.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=e.root)))
    refusal = e.refusal()
    absent = e.resolution((M1Edge.A3, RefusalResult(refusal=refusal.refusal.identity)))
    ambiguity = AuthorityAmbiguityId(value=token())
    contested = e.resolution((M1Edge.A4, AmbiguityResult(ambiguity=ambiguity)))
    for records in permutations(e.snapshot()):
        assert dv.derive_recorded_eligibility(records, opened.identity) == dv.OpenResolution(
            opened.identity
        )
        for record, edge, result in (
            (resolved, M1Edge.A2, ResolvedRootResult(resolved_root=e.root)),
            (absent, M1Edge.A3, RefusalResult(refusal=refusal.refusal.identity)),
            (contested, M1Edge.A4, AmbiguityResult(ambiguity=ambiguity)),
        ):
            outcome = dv.derive_recorded_eligibility(records, record.identity)
            assert isinstance(outcome, dv.CompletedResolution)
            assert (outcome.resolution, outcome.edge, outcome.result) == (
                record.identity,
                edge,
                result,
            )
            assert outcome.completing_entry.resolution == record.identity


@pytest.mark.traces("ST04-D3", "DO11-2")
def test_recorded_eligibility_is_indeterminate_for_a_missing_or_continued_resolution() -> None:
    """No `RC-14` occurrence is missing; an entry following the completing one is not a
    chain the frozen M1 graph produces (`M1-3`), so neither is read as a result."""
    e = Epoch("broken-m1")
    missing = dv.derive_recorded_eligibility(e.snapshot(), RootResolutionId(value="none"))
    assert isinstance(missing, dv.Indeterminate)
    assert missing.cause == dv.IndeterminacyCause.MISSING_RECORD

    record = e.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=e.root)))
    completing = e.records[-1]
    assert isinstance(completing, M1PositionEntry)
    e.records.append(
        completing.model_copy(
            update={
                "identity": completing.identity.model_copy(update={"discriminator": token()}),
                "predecessor": present(completing.identity),
            }
        )
    )
    continued = dv.derive_recorded_eligibility(e.snapshot(), record.identity)
    assert isinstance(continued, dv.Indeterminate)
    assert continued.cause == dv.IndeterminacyCause.INCONSISTENT_RECORDS


# --- purity -------------------------------------------------------------------------------


def all_derivations(a: Remediated) -> list[object]:
    resolution = a.epoch.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=a.epoch.root)))
    records = a.snapshot()
    return [
        dv.derive_prior_authorized_state(records, a.closure.identity),
        dv.derive_closure_scope(records, a.closure.identity),
        dv.derive_cycle_bound(records, a.epoch.root),
        dv.derive_liveness(records, a.epoch.root),
        dv.derive_recorded_eligibility(records, resolution.identity),
        dv.derive_obligation_force(records, a.o1),
        dv.derive_m1_position(records, resolution.identity),
        dv.derive_m2_position(records, a.epoch.root),
        dv.derive_m3_position(records, a.closure.envelope),
        dv.derive_m4_position(records, a.epoch.root),
        dv.derive_outstanding_halts(records),
        dv.derive_closure_scope_series(records, a.epoch.root),
    ]


@pytest.mark.traces("ST04-T1", "DV-12", "ST04-N2", "DO11-1")
def test_every_derivation_is_a_pure_function_of_its_records() -> None:
    """`DV-12`, `NV11-11`: the same records give the same result on every call and in
    every read order, and the input is left exactly as it was — nothing in it is read as
    an ordering, and nothing is written to it or kept from one call to the next."""
    a = Remediated()
    refusal = a.epoch.refusal()
    a.epoch.halt(refusal.refusal.identity, S.S7_CLOSURE_ACTIVE)
    a.epoch.suspend(a.epoch.root, refusal.refusal.identity)
    a.epoch.waive(a.o3)
    a.epoch.resolution((M1Edge.A2, ResolvedRootResult(resolved_root=a.epoch.root)))
    records = a.snapshot()
    snapshot = dv.AuthoritativeRecords(tuple(records.records), records.unreadable)
    reference = [
        dv.derive_prior_authorized_state(records, a.closure.identity),
        dv.derive_cycle_bound(records, a.epoch.root),
        dv.derive_liveness(records, a.epoch.root),
        dv.derive_obligation_force(records, a.o3),
        dv.derive_closure_scope_series(records, a.epoch.root),
        dv.derive_outstanding_halts(records),
    ]
    assert not any(isinstance(outcome, dv.Indeterminate) for outcome in reference)
    for view in permutations(records) * 2:
        assert [
            dv.derive_prior_authorized_state(view, a.closure.identity),
            dv.derive_cycle_bound(view, a.epoch.root),
            dv.derive_liveness(view, a.epoch.root),
            dv.derive_obligation_force(view, a.o3),
            dv.derive_closure_scope_series(view, a.epoch.root),
            dv.derive_outstanding_halts(view),
        ] == reference
    assert records == snapshot
    assert all(not isinstance(o, dv.Indeterminate) for o in all_derivations(a))


@pytest.mark.traces("ST04-N2", "DV-12", "DV-14", "ST04-D1")
def test_the_derivations_module_reads_no_clock_environment_or_hidden_state() -> None:
    """`DV-12`, `DV-14`, `NV11-11`: structurally — the module imports only the standard
    library's `dataclasses`, `enum` and `typing`, pydantic, and GP-AUTO's own ST-01 …
    ST-03 modules; names no clock, randomness, environment, file, process or network
    facility; keeps no module-level mutable state and declares no `global`; and touches
    the store only through `enumerate`, a read."""
    tree = ast.parse(inspect.getsource(dv))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {
        "__future__", "dataclasses", "enum", "typing", "pydantic",
        "gpauto.absence", "gpauto.authorization", "gpauto.coordination_identity",
        "gpauto.coordination_records", "gpauto.coordination_vocabulary", "gpauto.governance",
        "gpauto.identity", "gpauto.repository", "gpauto.review", "gpauto.store",
        "gpauto.vocabulary",
    }, imported  # fmt: skip
    forbidden = {
        "time", "datetime", "random", "uuid", "secrets", "os", "sys", "subprocess", "socket",
        "urllib", "http", "pathlib", "open", "sqlite3", "functools", "lru_cache", "cache",
        "id", "hash", "globals", "environ", "mint_value", "minting",
    }  # fmt: skip
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & forbidden, names & forbidden
    assert not {n for n in ast.walk(tree) if isinstance(n, ast.Global | ast.Nonlocal)}
    assert not attributes & {
        "create", "create_unit", "execute", "_execute", "_connection", "_transaction", "read",
    }  # fmt: skip
    assert "enumerate" in attributes
    for statement in tree.body:
        if isinstance(statement, ast.Assign | ast.AnnAssign):
            value = statement.value
            assert not isinstance(value, ast.List | ast.Dict | ast.Set | ast.ListComp), ast.dump(
                statement
            )[:80]


@pytest.mark.traces("ST04-N4", "DV-13", "DO11-7")
def test_no_derivation_reads_a_version_so_definitions_are_not_versioned_data() -> None:
    """`DV-13`, `VM-4`, `DO11-7`: no schema version, storage version, record format or
    configuration is named, so no stored value can change what a derivation means."""
    source = inspect.getsource(dv)
    tree = ast.parse(source)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    assert not {
        n for n in names if "VERSION" in n.upper() or "FORMAT" in n.upper() or "CONFIG" in n.upper()
    }


@pytest.mark.traces("ST04-N1", "DV-14", "DO11-1")
def test_every_derivation_result_is_a_frozen_value_and_never_a_record_model() -> None:
    """`DV-14`, `RC-54`: a result is a frozen dataclass, never a pydantic record model, so
    the store — whose write surface is keyed by record class — has no operation for it."""
    a = Remediated()
    for outcome in all_derivations(a):
        assert not isinstance(outcome, dv.Indeterminate), outcome
        params = getattr(type(outcome), "__dataclass_params__", None)
        assert params is not None and params.frozen, type(outcome)
        assert not isinstance(outcome, BaseModel), type(outcome)


@pytest.mark.traces("DO11-1", "ST04-D1")
def test_derivation_outcomes_carry_cycle_occurrence_identities_as_recorded() -> None:
    """The series names each occurrence by its minted identity — never an index or count
    (`CO-12`, `RC-53`)."""
    series = Cycled()
    outcome = dv.derive_closure_scope_series(series.epoch.snapshot(), series.epoch.root)
    assert isinstance(outcome, dv.ClosureScopeSeries)
    assert all(isinstance(step.cycle_occurrence, CycleOccurrenceId) for step in outcome.steps)
    assert all(
        not isinstance(getattr(step, name, None), int)
        for step in outcome.steps
        for name in ("index", "number", "count")
    )
    assert M3PositionEntry in dv.DERIVATION_INPUTS and M4PositionEntry in dv.DERIVATION_INPUTS
