"""`GP-AUTO-ST-06`: `RA-00`…`RA-09` validity, `G1` binding and same-identity consistency.

Design basis: AP-11 §16 `GP-AUTO-ST-06` (Deliverables: *"Eligibility evaluation over
`RA-00`…`RA-09`"*); the frozen ST-06 clarification S6G2-2(a)…(k), S6G3-1…S6G3-5, §4 (`G1`),
§17 (test obligations); AP-07 `EQ-6`; AP-03 §4.1, §4.5.

Each case is one defect in an otherwise valid role-indexed authorization, so the case shows
that the one changed thing is what decides. Validity is a function of one decoded record's
content; binding is `G1`'s match against the attempt and the recorded referents; conflict is
ST-02's one comparator, with `INDETERMINATE` counted as conflict.
"""

from __future__ import annotations

from typing import Any

import pytest

import st03_ingest
import st06_world as w
from gpauto import authority, equivalence
from gpauto.absence import Carried, KnownAbsent, NotApplicable
from gpauto.authorization import AuthorityBearingContent
from gpauto.bounds import ActionClass, ReadBoundary, ToolCategory, WriteBoundary
from gpauto.coordination_records import RootResolutionRecord
from gpauto.derivations import IndeterminacyCause, Indeterminate
from gpauto.identity import (
    BaselineIdentityId,
    GovernedStageId,
    ProjectId,
    RepositoryBoundaryId,
    RootResolutionId,
    StageContractId,
)
from gpauto.scope_frame import GovernedStage, Project
from gpauto.vocabulary import (
    AuthorityBearingContentClass,
    BoundedPreflightPermission,
    ExternalActionClass,
    GitCapabilityClass,
    RaAttribute,
    Role,
    WriteMode,
)
from st03_world import fresh_store

GPAUTO_STAGE = "GP-AUTO-ST-06"

S = w.scope()
IMPL, DR, REM, BCV = w.WORKERS
RA07 = RaAttribute.RA_07_AUTHORITY_CEILING


def _ceiling(role: Role, **changes: Any) -> dict[str, Any]:
    return {"authority_ceiling": w.replace_member(w.ceiling(S), role, **changes)}


CLAUSE_CASES: tuple[tuple[str, str | tuple[str, ...], dict[str, Any]], ...] = (
    (
        "a: a role repeated",
        "a_distinct",
        {"authority_ceiling": (*w.ceiling(S), w.reviewer(S, BCV))},
    ),
    (
        "b: a member for a role outside RA-06",
        "b_covers_worker_roles",
        {"authorized_roles": (IMPL, DR, REM)},
    ),
    (
        "b: an RA-06 worker role with no member",
        "b_covers_worker_roles",
        {"authority_ceiling": w.ceiling(S)[:3]},
    ),
    ("c: writer READ_ONLY", "c_d_role_shapes", _ceiling(IMPL, write_mode=WriteMode.READ_ONLY)),
    (
        "c: writer without E-12 (which (f) also compares)",
        ("c_d_role_shapes", "f_remediator_within_implementer"),
        _ceiling(IMPL, write_boundary=NotApplicable()),
    ),
    (
        "c: writer carrying E-20",
        "c_d_role_shapes",
        _ceiling(
            IMPL, authoritative_input_designation=w.reviewer(S).authoritative_input_designation
        ),
    ),
    (
        "c: writer with Git BOUNDED_READ",
        "c_d_role_shapes",
        _ceiling(IMPL, git_capability_class=GitCapabilityClass.BOUNDED_READ),
    ),
    ("d: reviewer WRITING", "c_d_role_shapes", _ceiling(DR, write_mode=WriteMode.WRITING)),
    (
        "d: reviewer carrying E-12",
        "c_d_role_shapes",
        _ceiling(DR, write_boundary=w.writer(S).write_boundary),
    ),
    (
        "d: reviewer without E-20 (which (e) also reads)",
        ("c_d_role_shapes", "e_designation_within_read"),
        _ceiling(DR, authoritative_input_designation=NotApplicable()),
    ),
    (
        "d: reviewer with Git NONE",
        "c_d_role_shapes",
        _ceiling(BCV, git_capability_class=GitCapabilityClass.NONE),
    ),
    (
        "e: E-20 outside E-11",
        "e_designation_within_read",
        _ceiling(
            DR,
            authoritative_input_designation=Carried[Any](
                value=w.reviewer(S).authoritative_input_designation.value.model_copy(  # type: ignore[union-attr]
                    update={"designated_scopes": ("docs/",)}
                )
            ),
        ),
    ),
    (
        "f: REMEDIATOR writes wider",
        "f_remediator_within_implementer",
        _ceiling(REM, write_boundary=Carried[WriteBoundary](value=WriteBoundary(scopes=("x/",)))),
    ),
    (
        "f: REMEDIATOR reads wider",
        "f_remediator_within_implementer",
        _ceiling(REM, read_boundary=ReadBoundary(scopes=("src/", "docs/"))),
    ),
    (
        "f: REMEDIATOR tools wider",
        "f_remediator_within_implementer",
        _ceiling(REM, tool_categories=(ToolCategory(name="shell"),)),
    ),
    (
        "f: REMEDIATOR actions wider",
        "f_remediator_within_implementer",
        _ceiling(REM, action_classes=(ActionClass(name="deploy"),)),
    ),
    (
        "f: REMEDIATOR without IMPLEMENTER",
        "f_remediator_within_implementer",
        {"authorized_roles": (DR, REM, BCV), "authority_ceiling": w.ceiling(S)[1:]},
    ),
    *(
        (
            f"g: {external.value} in a member",
            "g_side_effects_declarable",
            _ceiling(IMPL, external_action_classes=(external,)),
        )
        for external in (
            ExternalActionClass.EGRESS,
            ExternalActionClass.INSTALL,
            ExternalActionClass.EXTERNAL_MUTATION,
        )
    ),
    (
        "h: another baseline in the scope frame",
        "h_scope_frame",
        _ceiling(
            BCV,
            scope_frame=S.frame().model_copy(update={"baseline": BaselineIdentityId(value="x")}),
        ),
    ),
)
"""Each case violates exactly one `S6G2-2` clause and nothing else (clarification §17) — save
an IMPLEMENTER without `E-12`, which (f) also compares, and a reviewer without `E-20`, which
(e) also reads."""


@pytest.mark.traces("ST06C-I01", "ST06-D1")
def test_a_valid_role_indexed_authorization_fails_no_attribute() -> None:
    """The fixture is valid: every worker role in `RA-06`, one member each, each shaped as
    S6G2-2(c)/(d) require. It may also carry the declarable side-effect class, and `RA-06`
    may name COORDINATOR, whose absence from the ceiling is correct (S6G2-2(b), (g))."""
    for record in (
        w.record(S, "valid"),
        w.record(S, "with-side-effect", **_ceiling(IMPL, external_action_classes=(w.SIDE_EFFECT,))),
        w.record(S, "with-coordinator", authorized_roles=(*w.WORKERS, Role.COORDINATOR)),
    ):
        assert authority.ra_failures(record) == frozenset(), record.identity
        assert authority.failing_attribute(record) is None
        assert authority.ceiling_clauses(record.content).holds()


@pytest.mark.traces("ST06C-I01", "ST06-D1", "ST06-M5", "ST06-M3", "AP03-I18")
def test_each_ceiling_clause_violated_alone_fails_ra07_and_that_clause_alone() -> None:
    """S6G2-2(a)…(h), each violated alone: exactly `RA-07` fails, named by the exclusion,
    and exactly that clause is false. DR/BCV Git `NONE`, `E-20 ⊄ E-11`, REMEDIATOR ⊄
    IMPLEMENTER, and egress / install / external mutation are each excluded (§17)."""
    assert authority.ceiling_clauses(w.content(S)).holds()
    for name, clause, changes in CLAUSE_CASES:
        record = w.record(S, "defective", **changes)
        clauses = vars(authority.ceiling_clauses(record.content))
        expected = [clause] if isinstance(clause, str) else list(clause)
        assert [c for c, holds in clauses.items() if not holds] == expected, name
        assert authority.ra_failures(record) == {RA07}, name
        assert authority.failing_attribute(record) == RA07, name


@pytest.mark.traces("ST06C-I05", "ST06-D1", "ST06-M2")
def test_value_expressed_incompleteness_is_invalid_and_names_its_attribute() -> None:
    """S6G3-1(ii): a missing label, a refused preflight and an empty role set are values
    of a decoded record, so each is an exclusion naming its own attribute."""
    cases = (
        ({"owner_human_label_present": False}, RaAttribute.RA_08_OWNER_HUMAN_LABEL),
        (
            {"preflight_permission": BoundedPreflightPermission.NOT_PERMITTED},
            RaAttribute.RA_09_PREFLIGHT_PERMISSION,
        ),
        ({"authorized_roles": ()}, RaAttribute.RA_06_AUTHORIZED_ROLES),
    )
    for changes, attribute in cases:
        record = w.record(S, "incomplete", **changes)
        assert authority.failing_attribute(record) == attribute, attribute
        assert attribute in authority.ra_failures(record)
    empty_roles = w.record(S, "no-roles", authorized_roles=())
    assert authority.ra_failures(empty_roles) == {RaAttribute.RA_06_AUTHORIZED_ROLES, RA07}


@pytest.mark.traces("ST06C-I05", "ST06-M2")
def test_a_multi_failure_record_names_the_lowest_ra_index() -> None:
    """S6G3-3: the reported attribute is the minimum by the frozen `RA` enumeration — never
    the highest, and never whichever was evaluated first."""
    record = w.record(
        S,
        "many",
        owner_human_label_present=False,
        preflight_permission=BoundedPreflightPermission.NOT_PERMITTED,
        **_ceiling(IMPL, write_mode=WriteMode.READ_ONLY),
    )
    assert authority.ra_failures(record) == {
        RA07,
        RaAttribute.RA_08_OWNER_HUMAN_LABEL,
        RaAttribute.RA_09_PREFLIGHT_PERMISSION,
    }
    assert authority.failing_attribute(record) == RA07


def _occurrence(project: ProjectId, stage: GovernedStageId) -> RootResolutionRecord:
    return RootResolutionRecord(
        identity=RootResolutionId(value="attempt"),
        project=project,
        stage=stage,
        predecessor_terminal_entry=KnownAbsent(basis="first"),
        candidates=(),
    )


@pytest.mark.traces("ST06-D1", "ST06-M2", "M1-2")
def test_binding_matches_the_attempt_and_the_recorded_ingest_referents() -> None:
    """`G1 = INGEST_REFERENT_MATCH`: `RA-01`/`RA-02` against the attempt, and the stage,
    contract, repository boundary and baseline against the recorded referents. Each
    mismatch alone makes the record not match, which is not invalidity (S6G3-4)."""
    other_project = ProjectId(value="project-other")
    other_stage = GovernedStageId(value="stage-other")
    with fresh_store() as store:
        w.supply(
            store,
            S,
            [
                Project(identity=other_project),
                GovernedStage(identity=other_stage, project=S.project),
            ],
        )
        records = authority.read_authority_records(store)
        attempt = _occurrence(S.project, S.stage)
        assert authority.binding_match(w.record(S, "r"), attempt, records) is True
        cases = (
            (
                "attempt names another project",
                w.record(S, "r"),
                _occurrence(other_project, S.stage),
            ),
            ("record names another stage", w.record(S, "r", stage=other_stage), attempt),
            (
                "stage recorded under another project",
                w.record(S, "r", project=other_project),
                _occurrence(other_project, S.stage),
            ),
            (
                "contract not recorded",
                w.record(S, "r", contract=StageContractId(value="unrecorded")),
                attempt,
            ),
            (
                "repository not recorded",
                w.record(S, "r", repository_boundary=RepositoryBoundaryId(value="unrecorded")),
                attempt,
            ),
            (
                "baseline not recorded",
                w.record(S, "r", baseline=BaselineIdentityId(value="unrecorded")),
                attempt,
            ),
        )
        for name, record, occurrence in cases:
            assert authority.ra_failures(record) - {RA07} == frozenset(), name
            assert authority.binding_match(record, occurrence, records) is False, name


@pytest.mark.traces("ST06-D1", "ST06-M2")
def test_an_unreadable_ingest_referent_makes_binding_indeterminate() -> None:
    """P-04: a referent the store cannot interpret might be the one that decides."""
    with fresh_store() as store:
        w.supply(store, S, [])
        with st03_ingest.external_connection(store.path) as connection:
            st03_ingest.write(
                connection,
                Project(identity=ProjectId(value="unreadable")),
                record_format="gpauto.coordination-record/999",
            )
        records = authority.read_authority_records(store)
        found = authority.binding_match(w.record(S, "r"), _occurrence(S.project, S.stage), records)
        assert isinstance(found, Indeterminate)
        assert found.cause == IndeterminacyCause.UNREADABLE_INPUT


@pytest.mark.traces("ST06-D2", "ST06-M1", "ST06C-I01")
def test_same_identity_consistency_uses_the_one_comparator() -> None:
    """Records equal after normalization — members permuted, a token repeated — are
    consistent; a real difference is a conflict naming exactly the disagreeing class."""
    first = w.record(S, "first")
    permuted = w.record(S, "permuted", authority_ceiling=tuple(reversed(w.ceiling(S))))
    assert authority.identity_consistency((first, permuted)) == authority.Consistency(True, ())
    differing = w.record(
        S, "differing", **_ceiling(IMPL, tool_categories=(ToolCategory(name="file-edit"),) * 2)
    )
    assert authority.identity_consistency((first, differing)).consistent
    narrower = w.record(S, "narrower", **_ceiling(IMPL, action_classes=(ActionClass(name="edit"),)))
    found = authority.identity_consistency((first, permuted, narrower))
    assert found == authority.Consistency(False, (AuthorityBearingContentClass.AUTHORITY_CEILING,))


@pytest.mark.traces("EQ-6", "ST06-M1")
def test_an_indeterminate_comparison_is_a_conflict_naming_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`EQ-6`: a projection that cannot be normalized is **not** equivalence. The records
    are treated as conflicting, and the classes the comparison could not settle are named."""
    first, second = w.record(S, "first"), w.record(S, "second")
    assert authority.identity_consistency((first, second)).consistent
    ceiling = (AuthorityBearingContent, "authority_ceiling")
    trimmed = frozenset(e for e in equivalence.SET_VALUED_FIELDS if e != ceiling)
    monkeypatch.setattr(equivalence, "SET_VALUED_FIELDS", trimmed)
    assert (
        equivalence.compare_records(first, second) == equivalence.EquivalenceOutcome.INDETERMINATE
    )
    found = authority.identity_consistency((first, second))
    assert not found.consistent
    assert AuthorityBearingContentClass.AUTHORITY_CEILING in found.disagreeing
