"""`GP-AUTO-ST-07`: the `B2` act — one write-once boundary per resolved root.

Design basis: AP-09 `OB9-7`, `OB9-12`…`OB9-14`, `OB9-17`, `GR9-7`; AP-07 §9.1 (`RS7-1`…`RS7-5`),
`WP-11`, `WP-12`, `MC-3`, `MC-19`; AP-04 `B2`, `V-14`, `RP-4`; AP-11 §16 `GP-AUTO-ST-07`
(Tests: *"entry observation once per resolved root, after resolution and before any
derivation; dirty and staged-at-entry repositories supported and recorded"*; Negative tests:
`AV11-14`); `AP03-I08`; plan §6.1, §6.3, §6.4, §9.

The boundary is created with its `S2` position entry as one unit, only from `S1`, and only
once: a second call finds it by its key — the resolved root — and reads nothing from the
repository. A new root gets its own boundary, and the old one is not touched. ST-06's
envelope derivation consumes the boundary ST-07 wrote.
"""

from __future__ import annotations

import os

import pytest

import st06_world as w
import st07_world as x
from gpauto import authority, observation
from gpauto import derivations as dv
from gpauto.absence import KnownAbsent, Present
from gpauto.coordination_identity import M2PositionEntryId
from gpauto.coordination_records import (
    AuthorityEnvelopeRecord,
    EntryStateBoundaryRecord,
    M2PositionEntry,
    WorkerActivationRecord,
)
from gpauto.coordination_vocabulary import M2Edge, M2Position
from gpauto.identity import EntryStateBoundaryId
from gpauto.observation import (
    Determinate,
    Fixed,
    Indeterminate,
    NotFixed,
    NotFixedReason,
    ObservationCause,
    Replayed,
)
from gpauto.repository import EntryStateBoundary
from gpauto.state_machine import edge_rule
from gpauto.state_machine_model import (
    BOUNDARY_FIXED,
    FALSE,
    NO_BOUNDARY_FOR_ROOT,
    NOT_A_WORKER_ACTIVATION,
    OBSERVATION_FIXED,
    OBSERVATION_READ_ONLY,
    RP_4,
    TRUE,
    UNACCOUNTED_MUTATION,
)
from gpauto.store import CoordinationStore
from gpauto.vocabulary import Role
from st03_world import fresh_store

GPAUTO_STAGE = "GP-AUTO-ST-07"


def _entries(store: CoordinationStore) -> list[M2PositionEntry]:
    return [e for e in store.enumerate(M2PositionEntry) if isinstance(e, M2PositionEntry)]


def _boundaries(store: CoordinationStore) -> list[EntryStateBoundaryRecord]:
    return [
        b
        for b in store.enumerate(EntryStateBoundaryRecord)
        if isinstance(b, EntryStateBoundaryRecord)
    ]


def _fixed(store: CoordinationStore, epoch: x.Epoch) -> Fixed:
    found = observation.fix_entry_boundary(store, epoch.root)
    assert isinstance(found, Fixed), found
    return found


@pytest.mark.traces("ST07-T1", "OB9-7", "GR9-7")
def test_the_boundary_is_fixed_after_resolution_and_before_any_derivation() -> None:
    """`OB9-7`: no envelope can be derived before `B2` — ST-06 finds no boundary — and after
    it the IMPLEMENTER envelope names the boundary ST-07 wrote. `B2` itself derives no
    envelope and starts no activation (`GR9-7`)."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        step = M2Position.S3_IMPLEMENTATION_ACTIVE
        supplied = {BOUNDARY_FIXED.name: FALSE, UNACCOUNTED_MUTATION.name: FALSE}
        early = authority.record_envelope(
            store, epoch.root, Role.IMPLEMENTER, step, epoch.s1.identity, w.ABSENT, supplied
        )
        assert isinstance(early, dv.Indeterminate), early
        fixed = _fixed(store, epoch)
        assert not store.enumerate(AuthorityEnvelopeRecord)
        assert not store.enumerate(WorkerActivationRecord)
        facts = observation.boundary_facts(dv.read_authoritative_records(store), epoch.root)
        supplied = {
            BOUNDARY_FIXED.name: facts[BOUNDARY_FIXED.name],
            UNACCOUNTED_MUTATION.name: FALSE,
        }
        derived = authority.record_envelope(
            store, epoch.root, Role.IMPLEMENTER, step, fixed.entry.identity, w.ABSENT, supplied
        )
        assert isinstance(derived, authority.EnvelopeRecorded), derived
        assert derived.record.envelope.entry_boundary == fixed.boundary.boundary.identity


@pytest.mark.traces("ST07-M3", "ST07-T1", "OB9-7")
def test_b2_is_refused_from_any_position_but_s1() -> None:
    """`B2` leaves `S1` only. An epoch never opened, and an epoch halted from `S1`, are each
    refused — from records, before a single repository byte is read."""
    with x.workspace() as base:
        repo = x.repository(base)
        with fresh_store() as store:
            epoch = x.epoch_at_s1(store, repo, opened=False)
            reader = x.CountingReader()
            found = observation.fix_entry_boundary(store, epoch.root, reader)
            assert found == NotFixed(NotFixedReason.EPOCH_NOT_AT_S1)
            assert reader.calls == []
        with fresh_store() as store:
            epoch = x.epoch_at_s1(store, repo)
            store.create(w.m2(epoch.root, M2Position.S9_EPOCH_HALTED, M2Edge.B9, epoch.s1))
            reader = x.CountingReader()
            found = observation.fix_entry_boundary(store, epoch.root, reader)
            assert found == NotFixed(NotFixedReason.EPOCH_NOT_AT_S1)
            assert reader.calls == []
            assert not _boundaries(store)


@pytest.mark.traces("ST07-M3", "ST07-D4", "RS7-1", "OB9-13")
def test_boundary_and_s2_entry_are_one_unit() -> None:
    """`WP-12`: the `RC-17` boundary and the `S2` entry are written together — the entry is
    `B2` from the `S1` entry — and nothing else is written."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        before = x.store_state(store)
        fixed = _fixed(store, epoch)
        assert _boundaries(store) == [fixed.boundary]
        s2 = [e for e in _entries(store) if e.edge == M2Edge.B2]
        assert s2 == [fixed.entry]
        assert fixed.entry.state == M2Position.S2_ENTRY_BOUNDARY_FIXED
        assert fixed.entry.predecessor == Present[M2PositionEntryId](value=epoch.s1.identity)
        assert isinstance(fixed.entry.cycle_occurrence, KnownAbsent)
        after = x.store_state(store)
        changed = {k for k in after if after[k] != before[k]}
        assert changed == {"EntryStateBoundaryRecord", "M2PositionEntry"}


@pytest.mark.traces("RS7-2", "RS7-3", "ST07-T2", "OB9-12", "ST07-D4")
def test_dirty_and_staged_at_entry_repositories_are_fixed_with_three_separate_parts() -> None:
    """`RS7-2`, `RS7-3`: a repository with dirty, untracked and staged state is fixed, and
    the boundary carries three separately addressable parts — the bound baseline reference,
    the working-tree elements and the index elements — read back exactly as written."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        repo.write("a.txt", b"dirty\n")
        repo.write("untracked.txt", b"new\n")
        repo.write("src/b.py", b"staged\n")
        repo.git("add", "src/b.py")
        epoch = x.epoch_at_s1(store, repo)
        seen = observation.observe(repo.location)
        assert isinstance(seen, Determinate)
        fixed = _fixed(store, epoch)
        (stored,) = _boundaries(store)
    boundary = stored.boundary
    assert boundary.baseline == epoch.scope.baseline
    assert boundary.pre_existing_working_tree_state == seen.observation.working_tree
    assert boundary.pre_existing_index_state == seen.observation.index
    assert stored == fixed.boundary
    assert boundary.pre_existing_working_tree_state != boundary.pre_existing_index_state


@pytest.mark.supports("OB9-15", "OB9-16")
@pytest.mark.traces("ST07-M3", "ST07-N8", "AP03-I08", "OB9-14", "RS7-4")
def test_a_second_call_reads_nothing_and_returns_the_recorded_boundary() -> None:
    """`AV11-14`, `OB9-14`, `AP03-I08`: the key is read first. A second `B2` for the root
    returns the recorded boundary and entry, reads nothing from the repository — even
    after the repository changed — and writes nothing."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        fixed = _fixed(store, epoch)
        repo.write("a.txt", b"changed after entry\n")
        before = x.store_state(store)
        reader = x.CountingReader()
        again = observation.fix_entry_boundary(store, epoch.root, reader)
        assert again == Replayed(fixed.boundary, fixed.entry)
        assert reader.calls == []
        assert x.store_state(store) == before


@pytest.mark.supports("OB9-18")
@pytest.mark.traces("OB9-17", "RS7-4", "AP03-I08", "ST07-D4")
def test_a_new_root_gets_its_own_boundary_and_the_old_one_is_untouched() -> None:
    """`OB9-17`: a new authorization resolves a new root, observed afresh by the same
    mechanics. State unaccounted for in the old context is pre-existing entry state in the
    new one; the old boundary is neither corrected nor relabelled."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        first = x.epoch_at_s1(store, repo)
        old = _fixed(store, first)
        repo.write("between.txt", b"written between the two entries\n")
        second = x.epoch_at_s1(store, repo, tag="-2")
        new = _fixed(store, second)
        assert new.boundary.resolved_root == second.root
        assert new.boundary.boundary.identity != old.boundary.boundary.identity
        between = b"between.txt".hex()
        assert [e for e in new.boundary.boundary.pre_existing_working_tree_state if between in e]
        assert not [
            e for e in old.boundary.boundary.pre_existing_working_tree_state if between in e
        ]
        assert observation.fix_entry_boundary(store, first.root) == Replayed(
            old.boundary, old.entry
        )
        assert set(_boundaries(store)) == {old.boundary, new.boundary}


@pytest.mark.traces("ST07-D4", "RS7-1", "ST07-N8")
def test_a_torn_unit_is_inconsistent_and_nothing_is_added_to_it() -> None:
    """A boundary without its `B2` entry is not a unit ST-07 writes (`CW-2`): it is reported
    inconsistent, and neither re-observed nor completed."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        seen = observation.observe(repo.location)
        assert isinstance(seen, Determinate)
        fixed = _fixed(store, epoch)
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        store.create(
            EntryStateBoundaryRecord(boundary=fixed.boundary.boundary, resolved_root=epoch.root)
        )
        reader = x.CountingReader()
        found = observation.fix_entry_boundary(store, epoch.root, reader)
        assert found == NotFixed(NotFixedReason.INCONSISTENT_RECORDS)
        assert reader.calls == []
        assert [e.edge for e in _entries(store)] == [M2Edge.B1]


@pytest.mark.traces("ST07-D4", "RS7-5")
def test_boundary_facts_supply_v14_and_rp4_from_records_alone() -> None:
    """`V-14`, `RP-4`: `BOUNDARY_FIXED` and `RP_4` are false before `B2` and true after, read
    from records alone — the repository is never observed for them (`AV11-13`, `RS7-5`) —
    and an unreadable boundary record supplies neither."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        empty = observation.boundary_facts(dv.read_authoritative_records(store), epoch.root)
        assert empty == {BOUNDARY_FIXED.name: FALSE, RP_4.name: FALSE}
        _fixed(store, epoch)
        os.rename(repo.path, base / "moved-away")
        facts = observation.boundary_facts(dv.read_authoritative_records(store), epoch.root)
        assert facts == {BOUNDARY_FIXED.name: TRUE, RP_4.name: TRUE}
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        seen = observation.observe(repo.location)
        assert isinstance(seen, Determinate)
        stray = EntryStateBoundaryRecord(
            boundary=EntryStateBoundary(
                identity=EntryStateBoundaryId(value="0" * 32),
                baseline=epoch.scope.baseline,
                pre_existing_working_tree_state=(),
                pre_existing_index_state=(),
            ),
            resolved_root=epoch.root,
        )
        w.write_unreadable(store, stray)
        assert observation.boundary_facts(dv.read_authoritative_records(store), epoch.root) == {}
        found = observation.fix_entry_boundary(store, epoch.root)
        assert found == NotFixed(NotFixedReason.UNREADABLE_RECORDS)


@pytest.mark.traces("ST07-D4", "GR9-7")
def test_entry_facts_supply_exactly_b2_1_to_b2_4() -> None:
    """ST-05 names ST-07 as the supplier of `B2-1`…`B2-4`. The observation is read-only when
    the reader could take the mode, and never a worker activation."""
    determinate = Determinate(observation.Observation(None, None, None, (), ()))
    assert observation.entry_facts(True, determinate) == {
        NO_BOUNDARY_FOR_ROOT.name: TRUE,
        OBSERVATION_FIXED.name: TRUE,
        OBSERVATION_READ_ONLY.name: TRUE,
        NOT_A_WORKER_ACTIVATION.name: TRUE,
    }
    torn = Indeterminate((ObservationCause.TORN_READ,))
    assert observation.entry_facts(False, torn) == {
        NO_BOUNDARY_FOR_ROOT.name: FALSE,
        OBSERVATION_FIXED.name: FALSE,
        OBSERVATION_READ_ONLY.name: TRUE,
        NOT_A_WORKER_ACTIVATION.name: TRUE,
    }
    forbidden = Indeterminate((ObservationCause.FORBIDDEN_OR_UNSUPPORTED_MODE,))
    assert observation.entry_facts(True, forbidden)[OBSERVATION_READ_ONLY.name] == FALSE


@pytest.mark.traces("ST07-D4", "ST07-A1")
def test_the_b2_rule_is_st05s_and_no_guard_was_added() -> None:
    """`ST07-OWNER-DECISION-01`: the bound-referent match is observation fixability, not a new
    guard. ST-05's `B2` rule is exactly its frozen transcription — from `S1` to `S2`, the
    trigger and `B2-0`…`B2-4` — and ST-07 supplies facts to it and changes nothing in it."""
    rule = edge_rule(M2Edge.B2)
    assert rule.sources == (M2Position.S1_EPOCH_OPENED,)
    assert rule.target == M2Position.S2_ENTRY_BOUNDARY_FIXED
    (alternative,) = rule.guard.alternatives  # type: ignore[union-attr]
    assert [c.identifier for c in alternative] == ["B2-T", "B2-0", "B2-1", "B2-2", "B2-3", "B2-4"]
    assert {c.fact.name for c in alternative} == {
        "TRIGGER",
        "PREFLIGHT_PERMITTED",
        NO_BOUNDARY_FOR_ROOT.name,
        OBSERVATION_FIXED.name,
        OBSERVATION_READ_ONLY.name,
        NOT_A_WORKER_ACTIVATION.name,
    }
