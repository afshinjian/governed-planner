"""`GP-AUTO-ST-06`: `M1` root resolution — `A1`, the exclusions, and `A2` / `A3` / `A4`.

Design basis: AP-11 §16 `GP-AUTO-ST-06` (Tests: *"Exactly one eligible ⇒ `ROOT_RESOLVED`;
exclusion alongside a valid candidate still resolves"*; Negative tests: *"Zero ⇒
`ROOT_ABSENT`; multiple distinct or same-identity-conflicting ⇒ `ROOT_CONTESTED`"*);
AP-04 §3 (`A1`…`A4`, `M1-1`…`M1-9`), §11 (`V-16`…`V-18`); AP-07 `MC-17`, `EQ-6`,
`RO7A-1`…`RO7A-9`; the frozen ST-06 clarification S6G3-1…S6G3-7, §17.

Every case runs the real acts against a real store: the outside party ingests, `A1` opens
the occurrence, and the completing act records exactly what ST-05 admits. The records a
case leaves behind are what it asserts on, because the result of a resolution is its
records (`RO7A-2`).
"""

from __future__ import annotations

import pytest

import st03_ingest
import st06_world as w
from gpauto import authority, equivalence
from gpauto import derivations as dv
from gpauto.absence import KnownAbsent, Present
from gpauto.authorization import (
    AuthorityAmbiguity,
    AuthorityBearingContent,
    AuthorizationRecord,
    CandidateExclusion,
    DistinctMultiplicityForm,
    SameIdentityConflictForm,
)
from gpauto.bounds import ActionClass
from gpauto.coordination_identity import M1PositionEntryId
from gpauto.coordination_records import (
    AmbiguityResult,
    CandidateExclusionRecord,
    DispositionEstablishingRecord,
    M1PositionEntry,
    RefusalRecord,
    RefusalResult,
    ResolvedRootResult,
    RootResolutionRecord,
)
from gpauto.coordination_vocabulary import M1Edge, M1Position
from gpauto.identity import (
    AuthorizationRecordId,
    CandidateExclusionId,
    GovernedStageId,
    StageContractId,
)
from gpauto.scope_frame import GovernedStage, StageContract
from gpauto.state_machine_model import ELIGIBLE_MULTIPLICITY, IDENTITY_RECORDS_CONSISTENT
from gpauto.store import CoordinationStore
from gpauto.vocabulary import (
    AuthorityBearingContentClass,
    BoundedPreflightPermission,
    GovernanceCase,
    RaAttribute,
    Role,
)
from st03_world import fresh_store

GPAUTO_STAGE = "GP-AUTO-ST-06"

S = w.scope()
IMPL = Role.IMPLEMENTER


def _of[R](store: CoordinationStore, kind: type[R]) -> list[R]:
    return [r for r in store.enumerate(kind) if isinstance(r, kind)]  # type: ignore[arg-type]


def _exclusions(store: CoordinationStore) -> dict[str, RaAttribute]:
    return {
        r.exclusion.identity.excluded_record.value: r.exclusion.failing_attribute
        for r in _of(store, CandidateExclusionRecord)
    }


def _completing(store: CoordinationStore) -> list[M1PositionEntry]:
    return [e for e in _of(store, M1PositionEntry) if e.edge != M1Edge.A1]


def _narrower_ceiling_record(name: str, identity: str = "root") -> AuthorizationRecord:
    """Valid, but not content-equivalent to `w.record(S, ...)`: one IMPLEMENTER token less."""
    ceiling = w.replace_member(w.ceiling(S), IMPL, action_classes=(ActionClass(name="edit"),))
    return w.record(S, name, identity, authority_ceiling=ceiling)


@pytest.mark.traces("ST06-T1", "ST06-T2", "ST06-D2", "ST06-D3", "AP03-I06", "AP04-I03", "M1-2")
def test_one_eligible_instance_resolves_and_an_invalid_sibling_is_excluded_not_fatal() -> None:
    """`A2`: exactly one eligible live instance — two equivalent records — resolves, and the
    entry names the **instance**, never a record (`AP03-I33`). An invalid record alongside
    it is excluded, naming its attribute, and neither halts the stage nor governs it."""
    with fresh_store() as store:
        w.supply(
            store,
            S,
            [
                w.record(S, "record-a"),
                w.record(S, "record-b", authority_ceiling=tuple(reversed(w.ceiling(S)))),
                w.record(S, "record-z", "other", owner_human_label_present=False),
            ],
        )
        done = w.resolve(store, S)
        assert isinstance(done, authority.Resolved) and not done.replayed
        assert done.entry.edge == M1Edge.A2
        assert done.entry.state == M1Position.ROOT_RESOLVED
        assert done.entry.result == ResolvedRootResult(resolved_root=w.root_id())
        assert _exclusions(store) == {"record-z": RaAttribute.RA_08_OWNER_HUMAN_LABEL}
        assert not _of(store, RefusalRecord) and not _of(store, AuthorityAmbiguity)


@pytest.mark.traces("ST06-N1", "AP03-I06", "AP04-I03", "M1-5", "ST06C-I05")
def test_zero_eligible_is_root_absent_with_a_missing_authority_refusal() -> None:
    """`A3` (`V-16`): when every candidate is invalid, exclusion manufactures nothing — the
    outcome is missing authority, recorded as a Case A refusal the `A3` entry binds."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a", authorized_roles=())])
        done = w.resolve(store, S)
        assert isinstance(done, authority.Resolved)
        assert (done.entry.edge, done.entry.state) == (M1Edge.A3, M1Position.ROOT_ABSENT)
        (refusal,) = _of(store, RefusalRecord)
        assert done.entry.result == RefusalResult(refusal=refusal.refusal.identity)
        assert refusal.refusal.case == GovernanceCase.CASE_A
        assert refusal.refusal.condition == "V-16"
        assert (refusal.refusal.observed_value, refusal.refusal.bound_value) == ("ZERO", "ONE")
        assert isinstance(refusal.refusal.resolved_root, KnownAbsent)
        assert isinstance(refusal.refusal.envelope, KnownAbsent)
        assert _exclusions(store) == {"record-a": RaAttribute.RA_06_AUTHORIZED_ROLES}


@pytest.mark.traces("ST06-N2", "AP03-I02", "M1-6", "M1-8", "M1-9", "ST06-D3")
def test_distinct_eligible_identities_are_contested_naming_every_one_and_no_winner() -> None:
    """`A4` (`V-17a`): two distinct eligible live identities are named, both, in an inert
    canonical order. A third, non-live identity is never named. The ambiguity suspends
    no competing instance: ST-06 writes no disposition record (`M1-9`)."""
    with fresh_store() as store:
        w.supply(
            store,
            S,
            [
                w.record(S, "record-a", "root"),
                w.record(S, "record-b", "other"),
                w.record(S, "record-c", "revoked"),
            ],
        )
        w.revoke(store, S, w.root_id("revoked"))
        dispositions = _of(store, DispositionEstablishingRecord)
        done = w.resolve(store, S)
        assert isinstance(done, authority.Resolved)
        assert (done.entry.edge, done.entry.state) == (M1Edge.A4, M1Position.ROOT_CONTESTED)
        (ambiguity,) = _of(store, AuthorityAmbiguity)
        assert done.entry.result == AmbiguityResult(ambiguity=ambiguity.identity)
        assert ambiguity.form == DistinctMultiplicityForm(
            competing_identities=(w.root_id("other"), w.root_id("root"))
        )
        assert ambiguity.stage == S.stage
        assert _of(store, DispositionEstablishingRecord) == dispositions
        assert _exclusions(store) == {}


@pytest.mark.traces("ST06-N2", "ST06-D3", "M1-6", "ST06-M1")
def test_one_identity_whose_valid_records_conflict_is_contested_naming_the_classes() -> None:
    """`A4` (`V-17b`): one eligible identity, two valid records that are not equivalent —
    no instance is constituted, and the ambiguity names the identity and the disagreeing
    class. A valid record of the identity that does not match binding is still compared:
    constitution turns on validity alone (S6G3-5)."""
    other = StageContract(
        **{**S.contract.model_dump(), "identity": StageContractId(value="other-contract")}
    )
    with fresh_store() as store:
        w.supply(store, S, [other, w.record(S, "record-a"), _narrower_ceiling_record("record-b")])
        done = w.resolve(store, S)
        assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A4
        (ambiguity,) = _of(store, AuthorityAmbiguity)
        assert ambiguity.form == SameIdentityConflictForm(
            conflicting_identity=w.root_id(),
            disagreeing_content_classes=(AuthorityBearingContentClass.AUTHORITY_CEILING,),
        )
    with fresh_store() as store:
        w.supply(
            store,
            S,
            [other, w.record(S, "record-a"), w.record(S, "record-b", contract=other.identity)],
        )
        done = w.resolve(store, S)
        assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A4
        (ambiguity,) = _of(store, AuthorityAmbiguity)
        assert isinstance(ambiguity.form, SameIdentityConflictForm)
        assert ambiguity.form.disagreeing_content_classes == (
            AuthorityBearingContentClass.CONTRACT,
        )


@pytest.mark.traces("EQ-6", "ST06-N2", "ST06-M1")
def test_an_indeterminate_same_identity_comparison_is_contested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`EQ-6`: indeterminate is never equivalence. An identity whose records cannot be
    compared constitutes no instance; the ambiguity names it and the classes, and the
    stage does not begin."""
    ceiling = (AuthorityBearingContent, "authority_ceiling")
    trimmed = frozenset(e for e in equivalence.SET_VALUED_FIELDS if e != ceiling)
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a"), w.record(S, "record-b")])
        monkeypatch.setattr(equivalence, "SET_VALUED_FIELDS", trimmed)
        done = w.resolve(store, S)
        assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A4
        (ambiguity,) = _of(store, AuthorityAmbiguity)
        assert isinstance(ambiguity.form, SameIdentityConflictForm)
        assert ambiguity.form.conflicting_identity == w.root_id()
        assert AuthorityBearingContentClass.AUTHORITY_CEILING in (
            ambiguity.form.disagreeing_content_classes
        )


@pytest.mark.traces("AP03-I06", "ST06-M1", "ST06C-I05")
def test_an_invalid_record_never_enters_constitution_or_conflict() -> None:
    """AP-03 §4.1, S6G3-5: an invalid record of the eligible identity differs from its valid
    sibling, yet it is excluded, not compared — the stage resolves."""
    with fresh_store() as store:
        invalid = w.record(
            S, "record-z", preflight_permission=BoundedPreflightPermission.NOT_PERMITTED
        )
        w.supply(store, S, [w.record(S, "record-a"), invalid])
        done = w.resolve(store, S)
        assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A2
        assert _exclusions(store) == {"record-z": RaAttribute.RA_09_PREFLIGHT_PERMISSION}


@pytest.mark.traces("ST06C-I06", "ST06-M2", "M1-2", "AP03-I06")
def test_binding_mismatch_and_non_liveness_make_a_valid_candidate_ineligible_never_excluded() -> (
    None
):
    """S6G3-4, `V-10`, `V-01`/`V-09`: a valid record bound to another stage and a revoked
    instance are **not eligible**, with no `RC-15` and no stored per-candidate fact. With
    nothing else eligible the outcome is missing authority."""
    elsewhere = GovernedStageId(value="stage-elsewhere")
    with fresh_store() as store:
        w.supply(
            store,
            S,
            [
                GovernedStage(identity=elsewhere, project=S.project),
                w.record(
                    w.Scope(S.project, elsewhere, S.contract, S.repository, S.baseline),
                    "record-a",
                    "bound-elsewhere",
                ),
                w.record(S, "record-b", "revoked"),
            ],
        )
        w.revoke(store, S, w.root_id("revoked"))
        done = w.resolve(store, S)
        assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A3
        assert _exclusions(store) == {}


def _unreadable(store: CoordinationStore, identity: str) -> None:
    with st03_ingest.external_connection(store.path) as connection:
        st03_ingest.write(
            connection,
            w.record(S, identity, "unknowable"),
            record_format="gpauto.coordination-record/999",
        )


@pytest.mark.traces("ST06C-I05", "ST06-M2", "ST06-R1")
def test_an_unreadable_candidate_leaves_the_resolution_open_with_nothing_false_recorded() -> None:
    """S6G3-7: an unreadable `RC-12` is named in the candidate set by its record identity,
    gets no `RC-15`, and makes the multiplicity indeterminate. ST-05 then refuses `A2`,
    `A3` and `A4` alike: no completing entry, no refusal, no ambiguity — never `A2`
    beside a valid record. The decoded invalid record is still excluded."""
    with fresh_store() as store:
        w.supply(
            store,
            S,
            [w.record(S, "record-a"), w.record(S, "record-z", owner_human_label_present=False)],
        )
        _unreadable(store, "record-u")
        done = w.resolve(store, S)
        assert isinstance(done, authority.StillOpen), done
        assert done.evaluation.multiplicity == "INDETERMINATE"
        assert {r.edge for r in done.refused} == {M1Edge.A2, M1Edge.A3, M1Edge.A4}
        (occurrence,) = _of(store, RootResolutionRecord)
        assert AuthorizationRecordId(value="record-u") in occurrence.candidates
        assert _completing(store) == []
        assert not _of(store, RefusalRecord) and not _of(store, AuthorityAmbiguity)
        assert _exclusions(store) == {"record-z": RaAttribute.RA_08_OWNER_HUMAN_LABEL}
        facts = authority.resolution_facts(done.evaluation)
        assert ELIGIBLE_MULTIPLICITY.name not in facts
        assert IDENTITY_RECORDS_CONSISTENT.name not in facts


@pytest.mark.traces("ST06C-I05", "ST06-M2")
def test_an_unstable_read_is_indeterminate_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S6G3-7: two read passes that disagree keep nothing — the read is unstable, the
    resolution is not evaluated, and nothing is written."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a")])
        opened = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened)
        original = CoordinationStore.enumerate
        calls = {"n": 0}

        def drifting(self: CoordinationStore, kind: type) -> tuple[object, ...]:
            found = original(self, kind)
            if kind is AuthorizationRecord:
                calls["n"] += 1
                return found[: calls["n"] % 2]
            return found

        monkeypatch.setattr(CoordinationStore, "enumerate", drifting)
        records = authority.read_authority_records(store)
        assert records.unstable and records.records == ()
        done = authority.complete_resolution(store, opened.resolution)
        assert isinstance(done, dv.Indeterminate)
        monkeypatch.setattr(CoordinationStore, "enumerate", original)
        assert _completing(store) == [] and _exclusions(store) == {}


@pytest.mark.traces("ST06C-I07", "ST06-M2", "ST06-D3")
def test_exclusions_are_appended_in_canonical_byte_order_whatever_the_storage_order() -> None:
    """S6G3-6: each exclusion names the previous one, in ascending canonical (JCS) byte order
    of the excluded record — not the store's collation. `a"` sorts before `a#` by raw bytes
    and after it by JCS bytes, which escape the quote."""
    names = ('a"', "a#", "b")
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, name, owner_human_label_present=False) for name in names])
        w.resolve(store, S)
        chain = {
            r.exclusion.identity.excluded_record.value: r.predecessor
            for r in _of(store, CandidateExclusionRecord)
        }
        (resolution,) = [r.identity for r in _of(store, RootResolutionRecord)]

        def previous(name: str) -> Present[CandidateExclusionId]:
            return Present[CandidateExclusionId](
                value=CandidateExclusionId(
                    parent_resolution=resolution,
                    excluded_record=AuthorizationRecordId(value=name),
                )
            )

        assert isinstance(chain["a#"], KnownAbsent)
        assert chain['a"'] == previous("a#")
        assert chain["b"] == previous('a"')


@pytest.mark.traces("ST06-R1", "M1-7", "M1-3", "ST06-D2")
def test_a_completed_resolution_is_never_re_resolved() -> None:
    """`M1-7`, `RO7A-6`(b): a completed resolution returns its recorded result and writes
    nothing — even when a second eligible identity has since become visible."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a")])
        first = w.resolve(store, S)
        assert isinstance(first, authority.Resolved)
        st03_ingest.ingest(store.path, [w.record(S, "record-b", "late")])
        again = authority.complete_resolution(store, first.resolution)
        assert isinstance(again, authority.Resolved) and again.replayed
        assert again.entry == first.entry
        assert len(_completing(store)) == 1 and not _of(store, AuthorityAmbiguity)


@pytest.mark.traces("ST06-R1", "M1-3", "M1-7")
def test_a1_is_found_by_its_anchor_and_a_new_attempt_follows_the_terminal_entry() -> None:
    """`MC-17`(i): a repeated stage-entry attempt while the resolution is open finds it and
    mints nothing. `ROOT_ABSENT` is never left on its own; a **new** attempt is a new
    occurrence anchored on the prior attempt's terminal entry, and it resolves only because
    what is visible changed."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-x", "unlabelled", owner_human_label_present=False)])
        opened = authority.open_resolution(store, S.project, S.stage)
        again = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened) and isinstance(again, authority.Opened)
        assert (again.resolution, again.replayed) == (opened.resolution, True)
        absent = authority.complete_resolution(store, opened.resolution)
        assert isinstance(absent, authority.Resolved) and absent.entry.edge == M1Edge.A3
        st03_ingest.ingest(store.path, [w.record(S, "record-a")])
        retry = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(retry, authority.Opened) and not retry.replayed
        assert retry.resolution != opened.resolution
        (anchored,) = [
            r for r in _of(store, RootResolutionRecord) if r.identity == retry.resolution
        ]
        assert anchored.predecessor_terminal_entry == Present[M1PositionEntryId](
            value=absent.entry.identity
        )
        done = authority.complete_resolution(store, retry.resolution)
        assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A2
        parents = [
            r.exclusion.identity.parent_resolution for r in _of(store, CandidateExclusionRecord)
        ]
        assert sorted(p.value for p in parents) == sorted(
            [opened.resolution.value, retry.resolution.value]
        )


@pytest.mark.traces("M1-7", "ST06-R1", "ST06-M2")
def test_a_resolution_ranges_over_its_recorded_candidates_only() -> None:
    """`M1-7`: uniqueness is a resolution-time property over the candidates `A1` recorded. A
    record ingested after `A1` is not among them, and is neither counted nor feared."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a")])
        opened = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened)
        st03_ingest.ingest(store.path, [w.record(S, "record-late", "late")])
        done = authority.complete_resolution(store, opened.resolution)
        assert isinstance(done, authority.Resolved), done
        assert done.entry.result == ResolvedRootResult(resolved_root=w.root_id())


@pytest.mark.traces("ST06C-I05", "ST06-M2", "ST06-R1")
def test_recorded_exclusions_that_are_not_the_canonical_prefix_are_inconsistent() -> None:
    """`MC-3`: an exclusion already recorded must be the one recomputation yields. A
    different one — here naming another attribute — is inconsistent, and nothing more is
    written."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-z", owner_human_label_present=False)])
        opened = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened)
        wrong = CandidateExclusionRecord(
            exclusion=CandidateExclusion(
                identity=CandidateExclusionId(
                    parent_resolution=opened.resolution,
                    excluded_record=AuthorizationRecordId(value="record-z"),
                ),
                failing_attribute=RaAttribute.RA_09_PREFLIGHT_PERMISSION,
            ),
            predecessor=authority.EXCLUSION_CHAIN_START,
        )
        store.create(wrong)
        done = authority.complete_resolution(store, opened.resolution)
        assert isinstance(done, dv.Indeterminate)
        assert done.cause == dv.IndeterminacyCause.INCONSISTENT_RECORDS
        assert _completing(store) == []


@pytest.mark.traces("ST06-M2", "ST06C-I05")
def test_indeterminate_liveness_leaves_the_resolution_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P-04: a valid, binding-matched identity whose liveness cannot be derived is neither
    eligible nor ineligible — the multiplicity is indeterminate, and no edge is taken."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a")])
        unknown = dv.Indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "RC-35")
        monkeypatch.setattr(dv, "derive_liveness", lambda records, identity: unknown)
        done = w.resolve(store, S)
        assert isinstance(done, authority.StillOpen)
        assert done.evaluation.indeterminacy == unknown
        assert _completing(store) == []


@pytest.mark.traces("ST06-D2", "ST06-M1")
def test_the_multiplicity_and_consistency_facts_are_read_by_st05_alone() -> None:
    """ST-06 supplies `ELIGIBLE_MULTIPLICITY` and `IDENTITY_RECORDS_CONSISTENT`; which edge
    they admit is ST-05's. Each value admits exactly the frozen edge."""
    with fresh_store() as store:
        w.supply(store, S, [w.record(S, "record-a"), _narrower_ceiling_record("record-b")])
        opened = authority.open_resolution(store, S.project, S.stage)
        assert isinstance(opened, authority.Opened)
        records = authority.read_authority_records(store)
        evaluation = authority.evaluate_resolution(records, opened.resolution)
        assert isinstance(evaluation, authority.ResolutionEvaluation)
        assert authority.resolution_facts(evaluation) == {
            "TRIGGER": "COORDINATOR",
            ELIGIBLE_MULTIPLICITY.name: "ONE",
            IDENTITY_RECORDS_CONSISTENT.name: "FALSE",
        }
