"""`GP-AUTO-ST-03`: the root-resolution occurrence and its result carrier.

Design basis: AP-07 root-resolution clarification `RO7A-1`…`RO7A-9`, `AP07-I59`; AP-11
ST-03 follow-on amendment §3 (`RS11-14`, `RS11-34`, `SRB11-8`), `SRF11-1`, `AP11-I73`;
AP-07 §15.3 (`MC-17`), §18 (`RB-1`, `RB-10`); AP-04 §3.

The representation, and only the representation: `RC-14` is the `A1` occurrence and is
never later populated; an open resolution is a complete stored state; the completing M1
entry carries the result — `A2` the resolved-root instance, unique on that identity alone
(`MC-17`(ii)); `A3` a reference to its `Refusal`; `A4` a reference to its
`AuthorityAmbiguity` — and every other entry carries none, structurally. Whether a guard
*permits* `A2` is ST-05's and ST-06's, and nothing here evaluates one.
"""

from __future__ import annotations

import sqlite3

import pytest
from pydantic import BaseModel, ValidationError

import st03_ingest
import st03_world
from gpauto import minting, store_schema
from gpauto.absence import KnownAbsent, Present
from gpauto.authorization import AuthorityAmbiguity, CandidateExclusion, SameIdentityConflictForm
from gpauto.bounds import ActionClass
from gpauto.coordination_identity import M1PositionEntryId
from gpauto.coordination_records import (
    AmbiguityResult,
    CandidateExclusionRecord,
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
    NoResolutionResult,
    RefusalRecord,
    RefusalResult,
    ResolvedRootResult,
    RootResolutionRecord,
)
from gpauto.coordination_vocabulary import M1Edge, M1Position
from gpauto.governance import Refusal
from gpauto.identity import (
    AuthorityAmbiguityId,
    CandidateExclusionId,
    GovernedStageId,
    OwnerAuthorizationId,
    ProjectId,
    RefusalId,
    RootResolutionId,
)
from gpauto.store import CoordinationStore, WriteRefused
from gpauto.vocabulary import AuthorityBearingContentClass, GovernanceCase, RaAttribute
from st03_world import ABSENT, BRANCH, Frame, fresh_store, m1, raw

GPAUTO_STAGE = "GP-AUTO-ST-03"


def _opened(
    store: CoordinationStore, tag: str = ""
) -> tuple[Frame, RootResolutionRecord, M1PositionEntry]:
    """Ingest a frame, then create the `A1` unit: the occurrence and its `A1` entry."""
    frame, supplied = st03_world.frame(tag)
    st03_ingest.ingest(store.path, supplied)
    resolution = RootResolutionRecord(
        identity=RootResolutionId(value=minting.mint_value()),
        project=frame.project,
        stage=frame.stage,
        predecessor_terminal_entry=ABSENT,
        candidates=tuple(record.identity for record in frame.records),
    )
    a1 = m1(resolution.identity, M1Position.RESOLUTION_OPEN, M1Edge.A1, None, NoResolutionResult())
    store.create_unit((resolution, a1))
    return frame, resolution, a1


def _chain(store: CoordinationStore, resolution: RootResolutionId) -> list[M1PositionEntry]:
    """`DV-6`'s reading, test-side: the chain walked by predecessor reference from its
    affirmatively-first entry — never by latest row, storage order, row id or time."""
    entries = [
        e for e in store.enumerate(M1PositionEntry)
        if isinstance(e, M1PositionEntry) and e.identity.resolution == resolution
    ]  # fmt: skip
    successor = {e.predecessor.value: e for e in entries if isinstance(e.predecessor, Present)}
    (current,) = [e for e in entries if not isinstance(e.predecessor, Present)]
    walked = [current]
    while current.identity in successor:
        current = successor[current.identity]
        walked.append(current)
    assert len(walked) == len(entries)
    return walked


def _refusal(frame: Frame) -> RefusalRecord:
    return RefusalRecord(
        refusal=Refusal(
            identity=RefusalId(value=minting.mint_value()),
            case=GovernanceCase.CASE_A,
            stage=frame.stage,
            branch=BRANCH,
            role=KnownAbsent(basis="no role: authority is missing"),
            resolved_root=KnownAbsent(basis="zero eligible remain"),
            envelope=KnownAbsent(basis="no envelope precedes resolution"),
            condition="missing authority",
            observed_value="zero eligible",
            bound_value="exactly one eligible",
            refused_action_class=ActionClass(name="stage-entry"),
        ),
        cycle_occurrence=ABSENT,
    )


def _ambiguity(frame: Frame) -> AuthorityAmbiguity:
    return AuthorityAmbiguity(
        identity=AuthorityAmbiguityId(value=minting.mint_value()),
        stage=frame.stage,
        form=SameIdentityConflictForm(
            conflicting_identity=frame.root,
            disagreeing_content_classes=(AuthorityBearingContentClass.AUTHORITY_CEILING,),
        ),
    )


# --- the occurrence, and the open state -----------------------------------------------------


@pytest.mark.traces("AP11-I73", "ST03-RR1")
def test_an_open_resolution_is_a_complete_stored_state() -> None:
    """`SRF11-1`, `RO7A-9`: the occurrence, its `A1` entry and its exclusions are stored and
    read back whole, with **no** completing entry — nothing requires one to exist."""
    with fresh_store() as store:
        frame, resolution, a1 = _opened(store)
        exclusion = CandidateExclusionRecord(
            exclusion=CandidateExclusion(
                identity=CandidateExclusionId(
                    parent_resolution=resolution.identity, excluded_record=frame.records[2].identity
                ),
                failing_attribute=RaAttribute.RA_02_STAGE,
            ),
            predecessor=ABSENT,
        )
        store.create(exclusion)
        assert store.read(RootResolutionRecord, resolution.identity) == resolution
        assert _chain(store, resolution.identity) == [a1]
        assert a1.result == NoResolutionResult()
        assert store.enumerate(CandidateExclusionRecord) == (exclusion,)


@pytest.mark.traces("AP11-I73", "ST03-RR1")
def test_no_schema_rule_requires_a_future_completing_entry() -> None:
    """`RO7A-9`, guard before carrier: no column, key or reference of `RC-14`, `RC-15` or
    the `A1` entry names a completing entry, a resolved root or an outcome, so none can
    be *required* before it exists — the carrier is a result, never an input."""
    with fresh_store() as store:
        connection = raw(store)
        try:
            for table in ("rc14_root_resolution", "rc15_candidate_exclusion"):
                targets = {
                    str(r[2]) for r in connection.execute(f"PRAGMA foreign_key_list({table})")
                }
                assert targets <= {
                    "rc10_project", "rc10_governed_stage", "rc12_authorization_record",
                    "rc14_root_resolution", "rc15_candidate_exclusion", "rc34_m1_position_entry",
                }, table  # fmt: skip
            rc14 = {
                str(r[1]) for r in connection.execute("PRAGMA table_info(rc14_root_resolution)")
            }
            assert rc14.isdisjoint({"outcome", "resolved_root", "ambiguity", "completed", "status"})
            assert not [c for c in rc14 if "result" in c or "outcome" in c]
        finally:
            connection.close()


@pytest.mark.traces("AP11-I73", "ST03-RR1")
def test_the_occurrence_carries_no_outcome_and_can_gain_none() -> None:
    """`RO7A-1`: `RC-14` has exactly the attempt anchor and candidate set — no outcome,
    resolved root, ambiguity, status or current field — and refuses one if offered."""
    assert set(RootResolutionRecord.model_fields) == {
        "identity", "project", "stage", "predecessor_terminal_entry", "candidates"
    }  # fmt: skip
    with pytest.raises(ValidationError):
        RootResolutionRecord(
            identity=RootResolutionId(value=minting.mint_value()),
            project=ProjectId(value="p"),
            stage=GovernedStageId(value="s"),
            predecessor_terminal_entry=ABSENT,
            candidates=(),
            outcome="RESOLVED_ROOT",  # type: ignore[call-arg]
        )


# --- A2: the resolved root, and MC-17(ii) -----------------------------------------------------


@pytest.mark.traces("AP11-I73", "ST03-RR2")
def test_a2_appends_the_carrier_naming_the_resolved_instance() -> None:
    """`RO7A-2`, `RO7A-3`: the `A2` entry's subject is the occurrence, it names its
    predecessor, and it carries the resolved-root **instance** identity — which must be
    borne by an ingested record (`SRB11-10`)."""
    with fresh_store() as store:
        frame, resolution, a1 = _opened(store)
        a2 = m1(
            resolution.identity,
            M1Position.ROOT_RESOLVED,
            M1Edge.A2,
            a1,
            ResolvedRootResult(resolved_root=frame.root),
        )
        store.create(a2)
        assert _chain(store, resolution.identity) == [a1, a2]
        unknown = m1(
            resolution.identity, M1Position.ROOT_RESOLVED, M1Edge.A2, a2,
            ResolvedRootResult(resolved_root=OwnerAuthorizationId(value="no-record-bears-this")),
        )  # fmt: skip
        with pytest.raises(WriteRefused, match="GPAUTO_DANGLING_INSTANCE"):
            store.create(unknown)


@pytest.mark.traces("AP11-I73", "ST03-RR3", "ST03-N4")
def test_at_most_one_completed_resolution_names_an_instance() -> None:
    """`MC-17`(ii): a second `A2` naming the same instance — under another occurrence, or
    as a replay of the same one — is refused; replay never creates a second carrier."""
    with fresh_store() as store:
        frame, resolution, a1 = _opened(store)
        a2 = m1(
            resolution.identity,
            M1Position.ROOT_RESOLVED,
            M1Edge.A2,
            a1,
            ResolvedRootResult(resolved_root=frame.root),
        )
        store.create(a2)
        with pytest.raises(WriteRefused):
            store.create(a2)
        second = RootResolutionRecord(
            identity=RootResolutionId(value=minting.mint_value()),
            project=frame.project,
            stage=frame.stage,
            predecessor_terminal_entry=Present[M1PositionEntryId](value=a2.identity),
            candidates=(),
        )
        second_a1 = m1(
            second.identity, M1Position.RESOLUTION_OPEN, M1Edge.A1, None, NoResolutionResult()
        )
        store.create_unit((second, second_a1))
        again = m1(
            second.identity,
            M1Position.ROOT_RESOLVED,
            M1Edge.A2,
            second_a1,
            ResolvedRootResult(resolved_root=frame.root),
        )
        with pytest.raises(WriteRefused):
            store.create(again)
        other = m1(
            second.identity,
            M1Position.ROOT_RESOLVED,
            M1Edge.A2,
            second_a1,
            ResolvedRootResult(resolved_root=frame.other_root),
        )
        store.create(other)


@pytest.mark.traces("AP11-I73", "ST03-RR3")
def test_the_epoch_anchor_is_keyed_on_the_instance_identity_alone() -> None:
    """`MC-17`(ii), `RO7A-3`: the uniqueness is on the resolved-instance column and on
    nothing else — no occurrence, position, order or time element."""
    with fresh_store() as store:
        connection = raw(store)
        try:
            unique = []
            for index in connection.execute("PRAGMA index_list(rc34_m1_position_entry)"):
                columns = [str(r[2]) for r in connection.execute(f"PRAGMA index_info({index[1]})")]
                if "result__ResolvedRootResult__resolved_root" in columns:
                    unique.append((bool(index[2]), columns, index[4]))
            assert unique == [(True, ["result__ResolvedRootResult__resolved_root"], 0)]
        finally:
            connection.close()


@pytest.mark.traces("ST03-RR1")
def test_one_attempt_anchor_admits_one_occurrence() -> None:
    """`MC-17`(i): (project, stage, predecessor terminal entry or its affirmative absence)
    is unique, so a replayed `A1` finds its occurrence and mints no second one."""
    with fresh_store() as store:
        frame, resolution, _ = _opened(store)
        replay = resolution.model_copy(
            update={"identity": RootResolutionId(value=minting.mint_value())}
        )
        with pytest.raises(WriteRefused):
            store.create(replay)


# --- A3 and A4: bound, never copied, created in their unit -------------------------------------


@pytest.mark.traces("AP11-I73", "ST03-RR4")
def test_a3_binds_its_refusal_created_in_the_same_unit() -> None:
    """`RO7A-4`: the `A3` entry references the `RC-30` `Refusal` produced with it; the
    content lives only in `RC-30`. Without its refusal the unit is refused whole."""
    with fresh_store() as store:
        frame, resolution, a1 = _opened(store)
        refusal = _refusal(frame)
        a3 = m1(
            resolution.identity,
            M1Position.ROOT_ABSENT,
            M1Edge.A3,
            a1,
            RefusalResult(refusal=refusal.refusal.identity),
        )
        with pytest.raises(WriteRefused):
            store.create(a3)
        assert store.enumerate(RefusalRecord) == ()
        store.create_unit((refusal, a3))
        assert _chain(store, resolution.identity)[-1] == a3
        assert set(RefusalResult.model_fields) == {"refusal"}


@pytest.mark.traces("AP11-I73", "ST03-RR4")
def test_a4_binds_its_ambiguity_created_in_the_same_unit() -> None:
    """`RO7A-4`: the `A4` entry references the `RC-16` `AuthorityAmbiguity` produced with
    it. A unit whose entry is refused leaves no ambiguity behind."""
    with fresh_store() as store:
        frame, resolution, a1 = _opened(store)
        ambiguity = _ambiguity(frame)
        wrong = m1(
            resolution.identity,
            M1Position.ROOT_CONTESTED,
            M1Edge.A4,
            None,
            AmbiguityResult(ambiguity=ambiguity.identity),
        )
        with pytest.raises(WriteRefused):
            store.create_unit((ambiguity, wrong))
        assert store.enumerate(AuthorityAmbiguity) == ()
        a4 = m1(
            resolution.identity,
            M1Position.ROOT_CONTESTED,
            M1Edge.A4,
            a1,
            AmbiguityResult(ambiguity=ambiguity.identity),
        )
        store.create_unit((ambiguity, a4))
        assert _chain(store, resolution.identity) == [a1, a4]
        assert set(AmbiguityResult.model_fields) == {"ambiguity"}


# --- structural absence -------------------------------------------------------------------------

MISMATCHED = [
    (M1Edge.A1, "ResolvedRootResult"),
    (M1Edge.A1, "RefusalResult"),
    (M1Edge.A1, "AmbiguityResult"),
    (M1Edge.A2, "NoResolutionResult"),
    (M1Edge.A2, "RefusalResult"),
    (M1Edge.A3, "ResolvedRootResult"),
    (M1Edge.A3, "AmbiguityResult"),
    (M1Edge.A3, "NoResolutionResult"),
    (M1Edge.A4, "RefusalResult"),
    (M1Edge.A4, "NoResolutionResult"),
]


@pytest.mark.traces("AP11-I73", "ST03-RR5")
def test_a_result_binding_is_admitted_only_on_its_own_edge() -> None:
    """`RO7A-5`: the binding an entry may carry is fixed by its edge — `A2` the resolved
    root, `A3` a refusal, `A4` an ambiguity, every other edge none — so each mismatched
    pairing is refused by the store, not merely unrepresented by convention."""
    with fresh_store() as store:
        frame, resolution, a1 = _opened(store)
        refusal, ambiguity = _refusal(frame), _ambiguity(frame)
        store.create_unit((refusal, ambiguity))
        values: dict[str, BaseModel] = {
            "ResolvedRootResult": ResolvedRootResult(resolved_root=frame.root),
            "RefusalResult": RefusalResult(refusal=refusal.refusal.identity),
            "AmbiguityResult": AmbiguityResult(ambiguity=ambiguity.identity),
            "NoResolutionResult": NoResolutionResult(),
        }
        for edge, result in MISMATCHED:
            entry = m1(resolution.identity, M1Position.RESOLUTION_OPEN, edge, a1, values[result])
            with pytest.raises(WriteRefused):
                store.create(entry)
            assert _chain(store, resolution.identity) == [a1], (edge, result)


@pytest.mark.traces("AP11-I73", "ST03-RR5")
def test_two_bindings_cannot_be_carried_by_one_entry_through_any_connection() -> None:
    """At most one binding is expressible in the model (a union of four), and a raw row
    naming two is refused by the schema's presence rules."""
    with fresh_store() as store:
        frame, resolution, a1 = _opened(store)
        refusal, ambiguity = _refusal(frame), _ambiguity(frame)
        store.create_unit((refusal, ambiguity))
        connection = raw(store)
        try:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO rc34_m1_position_entry"
                    " (identity__resolution, identity__discriminator,"
                    " state, edge, predecessor__kind, predecessor__Present__state,"
                    " predecessor__Present__value__resolution,"
                    " predecessor__Present__value__discriminator,"
                    " result__kind, result__RefusalResult__refusal,"
                    " result__AmbiguityResult__ambiguity,"
                    " record_format) VALUES (?, ?, 'ROOT_ABSENT', 'A3', 'Present', 'PRESENT', ?, ?,"
                    " 'RefusalResult', ?, ?, ?)",
                    (
                        resolution.identity.value, minting.mint_value(), resolution.identity.value,
                        a1.identity.discriminator, refusal.refusal.identity.value,
                        ambiguity.identity.value, store_schema.RECORD_FORMAT,
                    ),
                )  # fmt: skip
        finally:
            connection.close()


@pytest.mark.traces("AP11-I73", "ST03-RR5")
def test_only_m1_entries_have_a_result_binding_at_all() -> None:
    """`RO7A-5`: no M2, M3 or M4 entry carries a resolution binding — the columns do not
    exist on those tables, and the models have no such field."""
    with fresh_store() as store:
        connection = raw(store)
        try:
            for table in (
                "rc34_m2_position_entry",
                "rc34_m3_position_entry",
                "rc34_m4_position_entry",
            ):
                columns = [str(r[1]) for r in connection.execute(f"PRAGMA table_info({table})")]
                assert not [c for c in columns if c.startswith("result")], table
        finally:
            connection.close()
    for entry in (M2PositionEntry, M3PositionEntry, M4PositionEntry):
        assert "result" not in entry.model_fields


# --- restart and reconstruction -----------------------------------------------------------------


@pytest.mark.traces("AP11-I73", "ST03-RR6", "ST03-R1")
def test_open_completed_refused_and_contested_resolutions_reconstruct_after_restart() -> None:
    """`RB-1`, `RB-10`: after close and re-open, each resolution's phase and result are read
    from its chain alone, walked by predecessor reference. Creation is interleaved across
    occurrences, so nothing positional — latest row, row id, storage order — could give
    the right answer by accident."""
    import tempfile
    from pathlib import Path

    from gpauto.store import create_store, open_store

    with tempfile.TemporaryDirectory(prefix="gpauto-st03-") as directory:
        path = Path(directory) / "coordination.sqlite"
        with create_store(path) as store:
            frames = [
                _opened(store, tag) for tag in ("-open", "-resolved", "-absent", "-contested")
            ]
            (_, open_r, _), (fr, res_r, res_a1), (fa, abs_r, abs_a1), (fc, con_r, con_a1) = frames
            refusal, ambiguity = _refusal(fa), _ambiguity(fc)
            a4 = m1(
                con_r.identity,
                M1Position.ROOT_CONTESTED,
                M1Edge.A4,
                con_a1,
                AmbiguityResult(ambiguity=ambiguity.identity),
            )
            store.create_unit((ambiguity, a4))
            a2 = m1(
                res_r.identity,
                M1Position.ROOT_RESOLVED,
                M1Edge.A2,
                res_a1,
                ResolvedRootResult(resolved_root=fr.root),
            )
            store.create(a2)
            a3 = m1(
                abs_r.identity,
                M1Position.ROOT_ABSENT,
                M1Edge.A3,
                abs_a1,
                RefusalResult(refusal=refusal.refusal.identity),
            )
            store.create_unit((refusal, a3))
        with open_store(path) as reopened:
            assert [e.edge for e in _chain(reopened, open_r.identity)] == [M1Edge.A1]
            assert _chain(reopened, res_r.identity)[-1].result == ResolvedRootResult(
                resolved_root=fr.root
            )
            bound = _chain(reopened, abs_r.identity)[-1].result
            assert isinstance(bound, RefusalResult)
            assert reopened.read(RefusalRecord, bound.refusal) == refusal
            contested = _chain(reopened, con_r.identity)[-1].result
            assert isinstance(contested, AmbiguityResult)
            assert reopened.read(AuthorityAmbiguity, contested.ambiguity) == ambiguity
