"""`GP-AUTO-ST-07`: the coherence criterion, each defeat test on its own, and the honest limit.

Design basis: AP-09 `OB9-9`, `OB9-9a`…`OB9-9d`, `OB9-10`, `OB9-11`, `GR9-4`, `GR9-5`; AP-11 §16
`GP-AUTO-ST-07` (Negative tests: `AV11-2`, `AV11-2a`, `AV11-2b`, `AV11-3`, `AV11-4`;
Mutation: *"each coherence condition; each defeat test"*), §11 `FI11-9`; OWNER decisions
`ST07-OWNER-DECISION-01 = A_WITH_CONSTRAINT` and `ST07-OWNER-DECISION-02 = A`; plan §6.2,
§10, §12, §13.

Each defeat test is fired **alone**: a fault reader tampers with exactly one result of one
read — same length, same witnesses, so no other test can fire — and the observation must be
indeterminate for exactly that cause. Nothing here requires detection of a change made and
restored without an indication: that limit is asserted as retained (`AV11-2b`).
"""

from __future__ import annotations

import os
import socket
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import st06_world as w
import st07_world as x
from gpauto import authority, observation
from gpauto import derivations as dv
from gpauto.coordination_records import (
    EntryStateBoundaryRecord,
    HaltOccurrence,
    M2PositionEntry,
    RefusalRecord,
)
from gpauto.coordination_vocabulary import M2Position
from gpauto.observation import (
    Determinate,
    Indeterminate,
    NotFixed,
    NotFixedReason,
    Observation,
    ObservationCause,
)
from gpauto.scope_frame import BaselineIdentity
from gpauto.state_machine_model import OBSERVATION_FIXED
from gpauto.store import CoordinationStore
from gpauto.vocabulary import Role
from st03_world import fresh_store

GPAUTO_STAGE = "GP-AUTO-ST-07"

C = ObservationCause
HEAD = b"/.git/HEAD"


def _only(repo: x.Repository, reader: observation.Reader, cause: ObservationCause) -> None:
    """The observation is indeterminate for exactly `cause`, and for nothing else."""
    found = observation.observe(repo.location, reader)
    assert found == Indeterminate((cause,)), found


def _root(repo: x.Repository) -> bytes:
    return os.fsencode(repo.path)


# --- condition (i): internal verifiability — the index checksum and structure ---------------


@pytest.mark.traces("ST07-M1", "ST07-D2", "OB9-9b")
def test_a_corrupted_index_checksum_is_indeterminate() -> None:
    """`OB9-9a`(i), `OB9-9b`: an index failing its own checksum is not read — one body byte
    flipped with the trailer kept, and the trailer flipped with the body kept. Verification
    is the one SHA-1 use, and a correct index still fixes (N12)."""
    with x.workspace() as base:
        repo = x.repository(base)
        index = repo.path / ".git" / "index"
        raw = index.read_bytes()
        assert isinstance(observation.observe(repo.location), Determinate)
        entry_blob = 12 + 40
        body_flipped = raw[:entry_blob] + bytes([raw[entry_blob] ^ 1]) + raw[entry_blob + 1 :]
        index.write_bytes(body_flipped)
        _only(repo, observation.FILESYSTEM, C.INTEGRITY_CHECK_FAILED)
        trailer_flipped = raw[:-1] + bytes([raw[-1] ^ 1])
        index.write_bytes(trailer_flipped)
        _only(repo, observation.FILESYSTEM, C.INTEGRITY_CHECK_FAILED)


@pytest.mark.traces("ST07-M1", "ST07-D2", "OB9-9b")
def test_a_structurally_inconsistent_index_is_indeterminate() -> None:
    """A checksum that holds does not make a body well-formed: trailing bytes that are no
    entry and no extension, under a recomputed checksum, are a structural failure."""
    with x.workspace() as base:
        repo = x.repository(base)
        index = repo.path / ".git" / "index"
        raw = index.read_bytes()
        index.write_bytes(x.rechecksummed(raw[:-20] + b"\0\0\0"))
        _only(repo, observation.FILESYSTEM, C.INTEGRITY_CHECK_FAILED)
        index.write_bytes(x.with_extension(raw, b"ABCD", b"optional"))
        assert isinstance(observation.observe(repo.location), Determinate)


@pytest.mark.traces("ST07-M4", "GR9-4", "OB9-9b")
def test_split_or_sparse_index_is_indeterminate() -> None:
    """A required index extension — split index `link`, sparse `sdir`, or any unknown
    lowercase one — needs a representation this reader does not interpret: indeterminate,
    never read around. (A split index's own entries, which name their shared-index
    counterparts by position, fail the entry structure first.) An optional (uppercase)
    extension is skipped."""
    with x.workspace() as base:
        repo = x.repository(base)
        index = repo.path / ".git" / "index"
        raw = index.read_bytes()
        for signature in (b"sdir", b"zzzz"):
            index.write_bytes(x.with_extension(raw, signature))
            _only(repo, observation.FILESYSTEM, C.FORBIDDEN_OR_UNSUPPORTED_MODE)
        index.write_bytes(raw)
        repo.git("update-index", "--split-index")
        split = observation.observe(repo.location)
        assert isinstance(split, Indeterminate), split


@pytest.mark.traces("ST07-M1", "ST07-D2", "OB9-9b")
def test_a_ref_that_is_not_a_full_object_id_is_indeterminate() -> None:
    """Subjects 1 and 3 are content-addressed identities: a ref holding an abbreviated or
    upper-case object id is not one, and is never matched by prefix or normalized."""
    with x.workspace() as base:
        repo = x.repository(base)
        ref = repo.path / ".git/refs/heads/main"
        for spelling in (repo.commit[:7], repo.commit.upper(), repo.commit + "0"):
            ref.write_bytes(spelling.encode("ascii") + b"\n")
            _only(repo, observation.FILESYSTEM, C.INTEGRITY_CHECK_FAILED)
        ref.write_bytes(repo.commit.encode("ascii") + b"\n")
        assert isinstance(observation.observe(repo.location), Determinate)


# --- condition (ii): structural write-domain exclusivity, read from records -----------------


@pytest.mark.traces("ST07-M1", "ST07-D2", "ST07-M3")
def test_a_live_m3_subject_or_non_s1_position_refuses_before_reading() -> None:
    """`OB9-9a`(ii), `K-5`: exclusivity is read from records, not sampled. A live M3 subject
    of the root breaks it; and an epoch not at `S1` is refused before a single repository
    byte is read."""
    with fresh_store() as store:
        e = w.resolved_epoch(store, w.scope())
        derived = e.derive(Role.IMPLEMENTER, M2Position.S3_IMPLEMENTATION_ACTIVE)
        assert isinstance(derived, authority.EnvelopeRecorded)
        records = dv.read_authoritative_records(store)
        assert not observation.write_domain_exclusive(records, e.root)
        assert observation.write_domain_exclusive(records, w.root_id("elsewhere"))
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo, opened=False)
        reader = x.CountingReader()
        found = observation.fix_entry_boundary(store, epoch.root, reader)
        assert found == NotFixed(NotFixedReason.EPOCH_NOT_AT_S1)
        assert reader.calls == []


# --- condition (iii): each defeat test, individually (AV11-3) --------------------------------


@pytest.mark.traces("ST07-M2", "ST07-D3", "ST07-N6", "OB9-9b")
def test_a_torn_read_is_indeterminate() -> None:
    """A file read short of its own size is torn: no partial content is kept."""
    with x.workspace() as base:
        repo = x.repository(base)
        _only(repo, x.FaultReader({("read_regular", b"/a.txt", 1): x.torn}), C.TORN_READ)


@pytest.mark.traces("ST07-M2", "ST07-D3", "ST07-N6", "OB9-9b")
def test_a_subject_differing_between_the_two_reads_is_indeterminate() -> None:
    """The determination reads each subject twice; two reads that differ are two states,
    and neither is chosen."""
    with x.workspace() as base:
        repo = x.repository(base)
        fault = {("read_regular", HEAD, 3): x.same_length(b"ref: refs/heads/mair\n")}
        _only(repo, x.FaultReader(fault), C.SUBJECT_DIFFERED_BETWEEN_READS)


@pytest.mark.traces("ST07-M2", "ST07-D3", "ST07-N6", "OB9-9b")
def test_a_witness_differing_across_the_window_is_indeterminate() -> None:
    """The closing witness round differs from the opening one: the window saw a change."""
    with x.workspace() as base:
        repo = x.repository(base)
        fault = {("read_regular", HEAD, 4): x.same_length(b"ref: refs/heads/mair\n")}
        _only(repo, x.FaultReader(fault), C.WITNESS_DIFFERED)


@pytest.mark.traces("ST07-M2", "ST07-D3", "ST07-N6", "OB9-11")
def test_an_item_appearing_mid_walk_is_indeterminate() -> None:
    """`OB9-11`: at `S1` any change during the observation is external; a file created
    while the tree is walked is a defeat, never tolerated."""
    with x.workspace() as base:
        repo = x.repository(base)

        def create(found: observation.Stat) -> observation.Stat:
            (repo.path / "appeared.txt").write_bytes(b"external\n")
            return found

        _only(repo, x.FaultReader({("lstat", b"/a.txt", 1): create}), C.ITEM_APPEARED)


@pytest.mark.traces("ST07-M2", "ST07-D3", "ST07-N6", "OB9-11")
def test_an_item_disappearing_mid_walk_is_indeterminate() -> None:
    """An item listed and then gone — missing from the second listing, or absent when it is
    reached — disappeared mid-determination."""
    with x.workspace() as base:
        repo = x.repository(base)
        fault = {("list_dir", _root(repo), 2): x.minus(b"a.txt")}
        _only(repo, x.FaultReader(fault), C.ITEM_DISAPPEARED)
        _only(repo, x.FaultReader({("lstat", b"/a.txt", 1): x.absent}), C.ITEM_DISAPPEARED)


@pytest.mark.traces("ST07-M2", "ST07-D3", "ST07-N6", "OB9-9b")
def test_an_item_changing_mid_walk_is_indeterminate() -> None:
    """An item whose witness moved between its reads changed while it was read."""
    with x.workspace() as base:
        repo = x.repository(base)
        _only(repo, x.FaultReader({("lstat", b"/a.txt", 2): x.moved}), C.ITEM_CHANGED)


@pytest.mark.traces("ST07-M2", "ST07-D3", "ST07-N6", "OB9-9b")
def test_an_unreadable_subject_is_indeterminate() -> None:
    """An unreadable item is a defeat: nothing is recorded in its place."""
    with x.workspace() as base:
        repo = x.repository(base)
        fault = {("read_regular", b"/src/b.py", 1): x.unreadable}
        _only(repo, x.FaultReader(fault), C.UNREADABLE_SUBJECT)


@pytest.mark.traces("ST07-M2", "ST07-D3", "ST07-N6", "GR9-4")
def test_a_socket_in_the_tree_is_a_forbidden_mode_defeat() -> None:
    """A socket can be neither read as content nor skipped: it is readable only under a
    mode the reader does not take."""
    with x.workspace() as base:
        repo = x.repository(base)
        listener = socket.socket(socket.AF_UNIX)
        try:
            listener.bind(str(repo.path / "sock"))
            _only(repo, observation.FILESYSTEM, C.FORBIDDEN_OR_UNSUPPORTED_MODE)
        finally:
            listener.close()


@pytest.mark.traces("ST07-M4", "GR9-4", "ST07-N1")
def test_a_fifo_in_the_tree_makes_the_observation_indeterminate_without_blocking() -> None:
    """A FIFO is never opened as content: indeterminate, and nothing blocks on it."""
    with x.workspace() as base:
        repo = x.repository(base)
        os.mkfifo(repo.path / "pipe")
        _only(repo, observation.FILESYSTEM, C.FORBIDDEN_OR_UNSUPPORTED_MODE)


@pytest.mark.traces("ST07-M4", "GR9-4", "GR9-5", "OB9-9b")
def test_each_unsupported_repository_mode_is_indeterminate() -> None:
    """`OB9-9b`, §22 `I8`: a gitfile or linked worktree, reftable, SHA-256 objects, a separate
    work tree, a configuration include, a bare flag, an unknown format version or extension —
    each is a mode this reader does not take, and each fails closed rather than being
    interpreted."""
    with x.workspace() as base:
        main = x.repository(base, "main")
        main.git("worktree", "add", "-q", str(base / "linked"))
        cases: dict[str, Path] = {"linked worktree": base / "linked"}
        cases["reftable"] = x.repository(base, "reftable", None, "--ref-format=reftable").path
        cases["sha256"] = x.repository(base, "sha256", None, "--object-format=sha256").path
        for name, settings in (
            ("worktree", [("core.worktree", str(base))]),
            ("include", [("include.path", "extra.config")]),
            ("includeIf", [("includeIf.gitdir:/elsewhere/.path", "extra.config")]),
            ("bare", [("core.bare", "true")]),
            ("version", [("core.repositoryformatversion", "2")]),
            (
                "extension",
                [("core.repositoryformatversion", "1"), ("extensions.worktreeConfig", "true")],
            ),
        ):
            repo = x.repository(base, name)
            for key, value in settings:
                repo.git("config", key, value)
            cases[name] = repo.path
        for name, path in cases.items():
            found = observation.observe(str(path))
            assert isinstance(found, Indeterminate), name
            assert C.FORBIDDEN_OR_UNSUPPORTED_MODE in found.causes, name


@pytest.mark.traces("ST07-M4", "GR9-4", "OB9-9b")
def test_a_nested_repository_or_gitlink_is_indeterminate() -> None:
    """A nested repository's `.git`, and a gitlink entry in the index, are submodule state
    this reader does not interpret: indeterminate, never walked as content."""
    with x.workspace() as base:
        repo = x.repository(base)
        (repo.path / "vendor").mkdir()
        x.run_git(base, repo.path / "vendor", "init", "-q")
        _only(repo, observation.FILESYSTEM, C.FORBIDDEN_OR_UNSUPPORTED_MODE)
    with x.workspace() as base:
        repo = x.repository(base)
        repo.git("update-index", "--add", "--cacheinfo", f"160000,{repo.commit},module")
        _only(repo, observation.FILESYSTEM, C.FORBIDDEN_OR_UNSUPPORTED_MODE)


# --- witnesses establish nothing (AV11-2) ----------------------------------------------------


@pytest.mark.traces("ST07-N3", "ST07-M2", "OB9-9", "ST07-A2")
def test_matching_witnesses_do_not_override_a_mid_walk_change() -> None:
    """`AV11-2`: the opening and closing witness rounds agree, and an item appeared while
    the tree was walked — the observation is indeterminate. Witness equality is not a
    criterion and short-circuits no defeat."""
    with x.workspace() as base:
        repo = x.repository(base)
        fault = {("list_dir", _root(repo), 2): x.plus(b"zz-appeared")}
        reader = x.FaultReader(fault)
        _only(repo, reader, C.ITEM_APPEARED)
        assert reader.fired == [("list_dir", _root(repo), 2)]


@pytest.mark.traces("ST07-M1", "ST07-N4", "ST07-N7", "OB9-9b", "OB9-9")
def test_any_defeat_indication_prevents_a_determination() -> None:
    """`AV11-2a`: whichever defeat fires, alone or with others, no determination exists —
    no subject is salvaged and no value is spliced from another read."""
    with x.workspace() as base:
        repo = x.repository(base)
        faults: list[Mapping[tuple[str, bytes, int], x.Tamper]] = [
            {("read_regular", b"/a.txt", 1): x.torn},
            {("lstat", b"/a.txt", 2): x.moved},
            {("read_regular", HEAD, 4): x.same_length(b"ref: refs/heads/mair\n")},
            {("list_dir", _root(repo), 2): x.plus(b"new")},
            {
                ("read_regular", b"/a.txt", 1): x.torn,
                ("list_dir", _root(repo), 2): x.minus(b"src"),
            },
        ]
        for fault in faults:
            found = observation.observe(repo.location, x.FaultReader(fault))
            assert isinstance(found, Indeterminate), fault
            assert found.causes, fault
        assert isinstance(observation.observe(repo.location), Determinate)


@pytest.mark.supports("OB9-9a")
@pytest.mark.traces("ST07-D2", "ST07-M1", "OB9-9")
def test_each_coherence_condition_is_required_on_its_own() -> None:
    """`AV11-1`: (i) an index failing its integrity check, (ii) a write domain with a live
    subject, (iii) a defeat indication — each alone prevents a fixed boundary, and all
    three holding is what a determination needs."""
    with x.workspace() as base:
        repo = x.repository(base)
        assert isinstance(observation.observe(repo.location), Determinate)
        index = repo.path / ".git" / "index"
        raw = index.read_bytes()
        index.write_bytes(raw[:-1] + bytes([raw[-1] ^ 0xFF]))
        _only(repo, observation.FILESYSTEM, C.INTEGRITY_CHECK_FAILED)
        index.write_bytes(raw)
        _only(repo, x.FaultReader({("read_regular", b"/a.txt", 1): x.torn}), C.TORN_READ)
    with fresh_store() as store:
        e = w.resolved_epoch(store, w.scope())
        e.derive(Role.IMPLEMENTER, M2Position.S3_IMPLEMENTATION_ACTIVE)
        records = dv.read_authoritative_records(store)
        assert not observation.write_domain_exclusive(records, e.root)


@pytest.mark.supports("OB9-9d", "OB9-10")
@pytest.mark.traces("ST07-N4", "ST07-N7", "OB9-11", "OB9-9b")
def test_a_present_defeat_fixes_nothing_and_writes_nothing() -> None:
    """`AV11-2a`, `AV11-4`, `FI11-9` (Class A): an incoherent window mints no boundary and
    no `S2` entry, records no refusal or halt, and leaves the store exactly as it was. ST-05
    refuses `B2` on `OBSERVATION_FIXED`."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        epoch = x.epoch_at_s1(store, repo)
        before = x.store_state(store)
        fault = {("read_regular", HEAD, 4): x.same_length(b"ref: refs/heads/mair\n")}
        found = observation.fix_entry_boundary(store, epoch.root, x.FaultReader(fault))
        assert isinstance(found, NotFixed)
        assert found.reason == NotFixedReason.OBSERVATION_INDETERMINATE
        assert found.observation == Indeterminate((C.WITNESS_DIFFERED,))
        assert found.refused is not None
        assert OBSERVATION_FIXED.name in {u.fact for u in found.refused.unmet}
        assert x.store_state(store) == before


# --- the bound referents (ST07-OWNER-DECISION-01) ---------------------------------------------


def _nothing_written(store: CoordinationStore, before: dict[str, Any]) -> None:
    assert x.store_state(store) == before


@pytest.mark.traces("ST07-D4", "ST07-M1", "OB9-13")
def test_an_observed_commit_differing_from_the_bound_baseline_fixes_nothing() -> None:
    """`ST07-OWNER-DECISION-01`: the observed commit is exactly the root's `RC-10` identity or
    nothing is fixed. Here the branch moved past its bound baseline: the result is
    `Indeterminate(NOT_FIXABLE_AGAINST_BOUND_REFERENTS)`, with no `RC-17`, no `S2` entry, no
    refusal or halt record, and no re-binding."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        bound = repo.commit
        repo.write("a.txt", b"moved on\n")
        repo.git("commit", "-q", "-am", "moved on")
        epoch = x.epoch_at_s1(store, repo, commit=bound)
        before = x.store_state(store)
        found = observation.fix_entry_boundary(store, epoch.root)
        assert isinstance(found, NotFixed)
        assert found.observation == Indeterminate((C.NOT_FIXABLE_AGAINST_BOUND_REFERENTS,))
        _nothing_written(store, before)
        assert not store.enumerate(EntryStateBoundaryRecord)
        assert not store.enumerate(RefusalRecord) and not store.enumerate(HaltOccurrence)
        assert [e.state for e in x.stored(store, M2PositionEntry)] == [M2Position.S1_EPOCH_OPENED]
        (baseline,) = x.stored(store, BaselineIdentity)
        assert baseline.committed_history_identity == bound


@pytest.mark.traces("ST07-D4", "ST07-M1", "OB9-13")
def test_an_observed_branch_differing_from_the_bound_branch_fixes_nothing() -> None:
    """The observed branch is exactly the root's `RA-04` branch or nothing is fixed — at the
    very commit bound, on another branch, and on a detached `HEAD`, which names no branch."""
    with x.workspace() as base:
        repo = x.repository(base)
        for command in (("checkout", "-q", "-b", "other"), ("checkout", "-q", "--detach")):
            repo.git(*command)
            with fresh_store() as store:
                epoch = x.epoch_at_s1(store, repo)
                before = x.store_state(store)
                found = observation.fix_entry_boundary(store, epoch.root)
                assert isinstance(found, NotFixed), command
                assert found.observation == Indeterminate(
                    (C.NOT_FIXABLE_AGAINST_BOUND_REFERENTS,)
                ), command
                _nothing_written(store, before)


@pytest.mark.traces("ST07-D4", "ST07-M1")
def test_a_matching_unbound_baseline_record_does_not_make_the_observation_fixable() -> None:
    """Only the root's own bound referent counts: another recorded `RC-10` naming exactly the
    observed commit is not the root's baseline, and selects nothing."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        bound = repo.commit
        repo.write("a.txt", b"moved on\n")
        repo.git("commit", "-q", "-am", "moved on")
        unbound = x.other_baseline("", x.head(repo))
        epoch = x.epoch_at_s1(store, repo, commit=bound, extra=(unbound,))
        found = observation.fix_entry_boundary(store, epoch.root)
        assert isinstance(found, NotFixed)
        assert found.observation == Indeterminate((C.NOT_FIXABLE_AGAINST_BOUND_REFERENTS,))
        assert not store.enumerate(EntryStateBoundaryRecord)


# --- the honest limit, retained (AV11-2b, OB9-9c) ------------------------------------------------


@pytest.mark.traces("OB9-9c", "ST07-N5", "ST07-A2")
def test_an_unindicated_change_and_restore_is_a_retained_limit_not_a_detection() -> None:
    """`AV11-2b`: a file created and removed inside the window, leaving no indication in any
    determined subject, is **not detected** — the observation is determinate, and nothing in
    it claims that no intermediate change occurred. The limit is recorded as retained; no
    test here requires its detection."""
    with x.workspace() as base:
        repo = x.repository(base)
        ghost = repo.path / "src" / "ghost.txt"

        def create_and_restore(found: observation.Stat) -> observation.Stat:
            ghost.write_bytes(b"external\n")
            ghost.unlink()
            return found

        reader = x.FaultReader({("lstat", b"/a.txt", 1): create_and_restore})
        found = observation.observe(repo.location, reader)
        assert reader.fired
    assert isinstance(found, Determinate)
    assert not [e for e in found.observation.working_tree if b"ghost".hex() in e]
    assert set(Observation.__dataclass_fields__) == {
        "baseline",
        "branch",
        "committed_history",
        "index",
        "working_tree",
    }
    doc = observation.__doc__ or ""
    assert "retained, not closed" in doc and "is not detected" in doc
    for claim in ("snapshot", "atomic", "guarantee", "unchanged", "no_change", "detected"):
        assert not [f for f in Observation.__dataclass_fields__ if claim in f], claim
