"""The negative tests `GP-AUTO-ST-01` names, and the refusals they rest on.

Design basis: AP-03 §4.1 (what an authorization does not carry), §4.3 (the closed
projection), §5.2 (what an envelope does not carry), §12 (`GE-1`, `GE-2`), §14
(role/provider); `AP03-I17`, `AP03-I21`, `AP03-I28`; AP-11 §7 (`NV11-6`), §16
(`GP-AUTO-ST-01` negative tests).

The four the stage contract names — undeclared field refused, `list` where `tuple` is
required refused, identity kinds not interchangeable, provider absent from every
bounds structure — plus the refusals the model's own structure is supposed to
produce. Identity non-interchangeability has its own module (`test_ga02`); the row
here is the one the contract asks for over the entity layer.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

import fixtures
from gpauto.absence import KnownAbsent, Present
from gpauto.activation import (
    BaselineIdentityReference,
    EntryStateBoundaryReference,
    FrozenFindingSetReference,
    ObjectiveProductionReference,
    ProviderAssignment,
    StageContractPartReference,
    StageContractReference,
    WorkerActivation,
)
from gpauto.authorization import (
    DistinctMultiplicityForm,
    OwnerAuthorization,
    SameIdentityConflictForm,
)
from gpauto.bounds import AuthorityBounds
from gpauto.envelope import AuthorityEnvelope
from gpauto.governance import (
    AuthorizingDecision,
    EnvelopeViolation,
    NonAuthorizingDecision,
    OwnerDecision,
    Refusal,
)
from gpauto.identity import GovernedStageId, OwnerAuthorizationId
from gpauto.review import Finding, FrozenFindingSet
from gpauto.schema import DomainModel
from gpauto.vocabulary import (
    GovernanceCase,
    GovernedFactKind,
    OwnerDecisionKind,
    Provenance,
    Role,
    StageContractPart,
)
from introspect import annotation_atoms, fields_of, model_classes, reachable_models

PROVIDER_WORDS = ("provider", "vendor", "model_name", "session")

PROVIDER_BEARING_CLASSES = frozenset({ProviderAssignment, WorkerActivation})
"""The only two places AP-03 §14 permits a provider to appear at all."""


@pytest.mark.parametrize("cls", model_classes(), ids=lambda c: c.__qualname__)
@pytest.mark.traces("ST01-N1")
def test_every_model_refuses_an_undeclared_field(cls: type[DomainModel]) -> None:
    """`extra="forbid"`, on every structure, not only the ones a test remembered.

    AP-03 §4.3 rule 1 is fail-closed: content the frozen projection does not place is
    authority-bearing. A structure that accepted and dropped an unknown field would
    decide an authority question by discarding it.
    """
    assert cls.model_config.get("extra") == "forbid"
    assert cls.model_config.get("strict") is True
    assert cls.model_config.get("frozen") is True


@pytest.mark.traces("ST01-N1")
def test_an_undeclared_field_is_refused_on_construction() -> None:
    """The configuration above, observed as a refusal."""
    base = fixtures.owner_authorization()
    with pytest.raises(ValidationError) as caught:
        OwnerAuthorization(**{**base.__dict__, "expires_at": "2026-09-23T00:00:00Z"})
    assert caught.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.traces("ST01-N2")
def test_a_list_is_refused_where_a_tuple_is_required() -> None:
    """The reason `json.loads` + `model_validate` is forbidden package-wide.

    Strict validation refuses a `list` for a `tuple[...]` field, and `json.loads`
    produces lists — so the two-step decode fails at run time on a *valid* artifact,
    and only on the decode path. `model_validate_json` is the one permitted entry
    point, and it maps arrays to tuples while keeping strict member checking.
    """
    contract = fixtures.stage_contract()
    with pytest.raises(ValidationError) as caught:
        contract.model_copy(update={}).__class__(
            **{**contract.__dict__, "deliverable_boundary": ["a list"]}
        )
    assert caught.value.errors()[0]["type"] == "tuple_type"


@pytest.mark.traces("ST01-N2")
def test_the_permitted_json_entry_point_accepts_the_array_the_tuple_field_needs() -> None:
    """The positive counterpart: arrays decode to tuples through the JSON-aware path."""
    contract = fixtures.stage_contract()
    decoded = type(contract).model_validate_json(contract.model_dump_json())
    assert isinstance(decoded.deliverable_boundary, tuple)


@pytest.mark.traces("AP03-I17", "ST01-N4")
def test_provider_appears_in_no_bounds_structure() -> None:
    """`NV11-6`: provider appears in no bounds value, at any depth.

    Checked over the whole reachable closure of `AuthorityBounds`, because a provider
    field hidden inside a dimension would satisfy a shallow check while defeating the
    guarantee. If provider appeared here, a change of vendor would change authority.
    """
    offenders = [
        f"{cls.__qualname__}.{field}"
        for cls, field in fields_of(reachable_models(AuthorityBounds))
        if any(word in field.lower() for word in PROVIDER_WORDS)
    ]
    assert offenders == []


@pytest.mark.traces("AP03-I17", "ST01-N4")
def test_provider_appears_in_no_envelope_and_no_authorization() -> None:
    """*"Never in an envelope, never in a bounds value, never in an authorization."*"""
    for root in (AuthorityEnvelope, OwnerAuthorization):
        offenders = [
            f"{cls.__qualname__}.{field}"
            for cls, field in fields_of(reachable_models(root))
            if any(word in field.lower() for word in PROVIDER_WORDS)
        ]
        assert offenders == [], root.__qualname__


@pytest.mark.traces("AP03-I17", "ST01-N4")
def test_provider_appears_only_on_the_activation_annotation() -> None:
    """The whole of AP-03 §14's *where it appears* row, asserted over the package."""
    bearing = {
        cls
        for cls, field in fields_of(frozenset(model_classes()))
        if any(word in field.lower() for word in PROVIDER_WORDS)
    }
    assert bearing == PROVIDER_BEARING_CLASSES


@pytest.mark.traces("AP03-I17")
def test_no_relation_exists_between_activations_sharing_a_provider() -> None:
    """*"Two activations naming the same provider are related by nothing."*

    The structure offers no field linking one activation to another, so role
    inheritance and *"the same agent already checked this"* are inexpressible rather
    than merely discouraged.
    """
    shared = Present[ProviderAssignment](
        value=ProviderAssignment(provider_reference="one-vendor-session")
    )
    first = fixtures.worker_activation().model_copy(update={"provider": shared})
    second = first.model_copy(
        update={
            "identity": type(first.identity)(value="second-activation"),
            "role": Role.DISCOVERY_REVIEWER,
            "provider": shared,
        }
    )
    assert first.provider == second.provider
    assert first.identity != second.identity

    linking_fields = [
        field
        for field in WorkerActivation.model_fields
        if "activation" in field and field != "identity"
    ]
    assert linking_fields == []


@pytest.mark.supports("AP03-I28")
@pytest.mark.traces("ST01-D1")
def test_the_case_marker_is_neither_optional_nor_inferable() -> None:
    """`GE-2`: a record may not assert prevention that did not occur.

    Both case markers must be stated at construction, and each is pinned to its own
    case, so a Case B record can never be built carrying Case A.
    """
    for cls in (Refusal, EnvelopeViolation):
        assert cls.model_fields["case"].is_required()

    violation = fixtures.envelope_violation()
    with pytest.raises(ValidationError):
        EnvelopeViolation(**{**violation.__dict__, "case": GovernanceCase.CASE_A})


@pytest.mark.supports("AP03-I28")
@pytest.mark.traces("ST01-D1")
def test_the_not_prevented_marker_must_be_stated() -> None:
    """An honest non-prevention may never read as a block (`P-14`, `MB-25`)."""
    assert EnvelopeViolation.model_fields["not_prevented"].is_required()
    violation = fixtures.envelope_violation()
    fields = dict(violation.__dict__)
    del fields["not_prevented"]
    with pytest.raises(ValidationError) as caught:
        EnvelopeViolation(**fields)
    assert caught.value.errors()[0]["type"] == "missing"


@pytest.mark.traces("AP03-I21")
def test_a_finding_cannot_originate_from_any_role_but_discovery_review() -> None:
    """Sole origination, as an unconstructible value rather than a refused one."""
    base = fixtures.finding()
    with pytest.raises(ValidationError):
        Finding(**{**base.__dict__, "originating_role": Role.IMPLEMENTER})


@pytest.mark.traces("AP03-I21")
def test_a_frozen_set_cannot_admit_a_post_freeze_candidate_or_an_owner_decision() -> None:
    """Membership's domain is `Finding`, so neither is a refused member — both are
    unexpressible ones (`AP03-I21`, `GE-3`)."""
    base = fixtures.frozen_finding_set()
    for intruder in (fixtures.CANDIDATE_ID, fixtures.DECISION_ID):
        with pytest.raises(ValidationError) as caught:
            FrozenFindingSet(**{**base.__dict__, "members": (intruder,)})
        assert caught.value.errors()[0]["type"] == "model_type"


@pytest.mark.traces("ST01-D1")
def test_an_ambiguity_of_distinct_multiplicity_needs_more_than_one_identity() -> None:
    """One identity is not a multiplicity; the form would be a mis-record."""
    with pytest.raises(ValidationError) as caught:
        DistinctMultiplicityForm(competing_identities=(OwnerAuthorizationId(value="only"),))
    assert caught.value.errors()[0]["type"] == "too_short"


@pytest.mark.traces("ST01-D1")
def test_a_same_identity_conflict_must_name_a_disagreeing_content_class() -> None:
    """*"Naming the identity and the content classes that disagree"* (AP-03 §4.6)."""
    with pytest.raises(ValidationError) as caught:
        SameIdentityConflictForm(
            conflicting_identity=OwnerAuthorizationId(value="a"),
            disagreeing_content_classes=(),
        )
    assert caught.value.errors()[0]["type"] == "too_short"


@pytest.mark.traces("ST01-D1")
def test_an_authorization_must_be_constituted_by_at_least_one_record() -> None:
    """GP-AUTO never sees an authorization directly; it sees records (AP-03 §4.1)."""
    base = fixtures.owner_authorization()
    with pytest.raises(ValidationError) as caught:
        OwnerAuthorization(**{**base.__dict__, "constituting_records": ()})
    assert caught.value.errors()[0]["type"] == "too_short"


@pytest.mark.traces("ST01-D1")
@pytest.mark.supports("AP03-I02")
def test_an_authorization_covers_exactly_one_stage() -> None:
    """`RA-02` is singular, so *"this authorization, those stages"* is unexpressible."""
    annotation = OwnerAuthorization.model_fields["stage"].annotation
    assert annotation is GovernedStageId


# --- Admissibility is tied to provenance, not asserted beside it -----------------


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-N5")
def test_a_worker_authored_production_cannot_be_offered_as_objective_basis() -> None:
    """`EA-1`: the admissibility relation's domain excludes worker-authored productions.

    Not by a flag the reference asserts about a referent that does not carry it, but by
    the referent's own provenance. AP-03 §18.4 rests the whole guarantee on *"passing
    the admissibility relation"*, so the relation is what has to refuse.
    """
    with pytest.raises(ValidationError) as caught:
        ObjectiveProductionReference(
            production=fixtures.worker_authored_production()  # type: ignore[arg-type]
        )
    assert caught.value.errors()[0]["type"] == "literal_error"


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-N5")
def test_asserting_objective_beside_a_worker_authored_production_is_not_possible() -> None:
    """The specific defect: annotate `OBJECTIVE` and wrap it anyway.

    There is no provenance field on the reference to write it into, so the attempt is
    refused as an undeclared field rather than accepted and believed. `mypy --strict`
    rejects the same call statically, which is why it is spelled through a mapping
    here — the refusal being demonstrated is the run-time one.
    """
    smuggled: dict[str, Any] = {
        "production": fixtures.worker_authored_production(),
        "provenance": Provenance.OBJECTIVE,
    }
    with pytest.raises(ValidationError) as caught:
        ObjectiveProductionReference(**smuggled)
    assert {error["type"] for error in caught.value.errors()} >= {"extra_forbidden"}


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-N5")
def test_the_json_decode_path_refuses_a_worker_authored_objective_reference() -> None:
    """The path an unchecked referent would actually arrive by.

    A payload naming a production whose provenance is worker-authored is refused by
    `model_validate_json`, so the exclusion holds where decoding happens and not only
    where objects are built in memory.
    """
    admissible = ObjectiveProductionReference(production=fixtures.artifact_production())
    assert (
        ObjectiveProductionReference.model_validate_json(admissible.model_dump_json())
        == admissible
    )

    smuggled = admissible.model_dump_json().replace("OBJECTIVE", "WORKER_AUTHORED")
    with pytest.raises(ValidationError) as caught:
        ObjectiveProductionReference.model_validate_json(smuggled)
    assert caught.value.errors()[0]["type"] == "literal_error"


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-N5")
def test_identical_content_from_two_occurrences_carries_two_standings() -> None:
    """`AP03-I19`: neither production inherits the other's standing.

    The two fixtures deliberately bind the same `ArtifactContentId`. The objective one
    is admissible basis; the worker-authored one is not, and the identical bytes change
    nothing about that.
    """
    objective = fixtures.artifact_production()
    authored = fixtures.worker_authored_production()
    assert objective.content == authored.content
    assert objective.identity != authored.identity
    assert {objective.provenance, authored.provenance} == {
        Provenance.OBJECTIVE,
        Provenance.WORKER_AUTHORED,
    }


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-N6")
def test_a_governed_fact_kind_cannot_carry_another_kinds_identity() -> None:
    """AP-03 §8.2: each kind admits only its permitted referent identity type."""
    with pytest.raises(ValidationError) as caught:
        FrozenFindingSetReference(frozen_set=fixtures.BASELINE_ID)  # type: ignore[arg-type]
    assert caught.value.errors()[0]["type"] == "model_type"

    with pytest.raises(ValidationError):
        EntryStateBoundaryReference(entry_boundary=fixtures.FROZEN_SET_ID)  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        StageContractReference(contract=fixtures.BOUNDARY_ID)  # type: ignore[arg-type]


@pytest.mark.traces("ST01-N6")
def test_a_governed_fact_variant_cannot_be_relabelled_with_another_kind() -> None:
    """The kind is pinned, so a variant cannot wear a kind that is not its own."""
    with pytest.raises(ValidationError):
        StageContractReference(
            fact_kind=GovernedFactKind.BASELINE_IDENTITY,  # type: ignore[arg-type]
            contract=fixtures.CONTRACT_ID,
        )


@pytest.mark.traces("ST01-N6")
def test_a_governed_fact_variant_cannot_carry_another_variants_referent_field() -> None:
    """Field names are part of the binding: a baseline reference has no contract slot."""
    with pytest.raises(ValidationError) as caught:
        BaselineIdentityReference(contract=fixtures.CONTRACT_ID)  # type: ignore[call-arg]
    assert {error["type"] for error in caught.value.errors()} == {"extra_forbidden", "missing"}


@pytest.mark.traces("ST01-N6")
def test_a_contract_part_reference_names_which_part() -> None:
    """*"A named part of it"* has to name which part, from a closed vocabulary."""
    reference = StageContractPartReference(
        contract=fixtures.CONTRACT_ID, part=StageContractPart.ACCEPTANCE_CRITERIA
    )
    assert reference.part is StageContractPart.ACCEPTANCE_CRITERIA

    with pytest.raises(ValidationError):
        StageContractPartReference(
            contract=fixtures.CONTRACT_ID,
            part="acceptance criteria",  # type: ignore[arg-type]
        )


# --- Acceptance never produces authority ----------------------------------------


@pytest.mark.traces("AP03-I25", "ST01-N7")
def test_a_stage_outcome_acceptance_cannot_produce_an_authorization() -> None:
    """`SO-1`, `AP03-I25`: acceptance settles the past and confers nothing forward.

    *"No derivation relation from a StageOutcome or OwnerDecision to an
    OwnerAuthorization."* Representing acceptance as producing new authority is the
    collapse that *"looks adjacent in any record"*, so the pairing is not a value the
    model can hold.
    """
    with pytest.raises(ValidationError) as caught:
        NonAuthorizingDecision(
            kind=OwnerDecisionKind.STAGE_OUTCOME_ACCEPTANCE,
            produced_authorization=Present[OwnerAuthorizationId](  # type: ignore[arg-type]
                value=fixtures.AUTHORIZATION_ID
            ),
        )
    assert caught.value.errors()[0]["type"] == "model_type"


@pytest.mark.traces("AP03-I25", "ST01-N7")
def test_acceptance_cannot_be_recorded_as_an_authorizing_act() -> None:
    """The other direction: the authorizing form does not admit the acceptance kind."""
    with pytest.raises(ValidationError):
        AuthorizingDecision(
            kind=OwnerDecisionKind.STAGE_OUTCOME_ACCEPTANCE,  # type: ignore[arg-type]
            produced_authorization=Present[OwnerAuthorizationId](
                value=fixtures.AUTHORIZATION_ID
            ),
        )


@pytest.mark.traces("AP03-I25", "ST01-N7")
def test_the_whole_acceptance_decision_is_refused_on_the_json_path() -> None:
    """An acceptance carrying a produced authorization does not decode either."""
    smuggled = (
        '{"identity": {"value": "d"}, "stage": {"value": "s"}, '
        '"act": {"kind": "STAGE_OUTCOME_ACCEPTANCE", '
        '"produced_authorization": {"state": "PRESENT", "value": {"value": "a"}}}}'
    )
    with pytest.raises(ValidationError):
        OwnerDecision.model_validate_json(smuggled)


@pytest.mark.traces("AP03-I25", "ST01-N7")
def test_every_owner_decision_kind_is_admissible_in_exactly_one_act_form() -> None:
    """AP-03 §11.2's classification, complete and non-overlapping.

    Complete, so no OWNER act becomes unrecordable; non-overlapping, so no act can be
    recorded in the form that contradicts its row.
    """
    from gpauto.governance import ExceptionalRecoveryDecision

    forms = (AuthorizingDecision, NonAuthorizingDecision, ExceptionalRecoveryDecision)
    admissible: dict[OwnerDecisionKind, int] = {kind: 0 for kind in OwnerDecisionKind}
    for form in forms:
        for atom in annotation_atoms(form.model_fields["kind"].annotation):
            if isinstance(atom, OwnerDecisionKind):
                admissible[atom] += 1
    assert all(count == 1 for count in admissible.values()), admissible


@pytest.mark.traces("AP03-I25", "ST01-N7")
def test_an_authorizing_act_cannot_record_an_absent_authorization() -> None:
    """Acts AP-03 §11.2 classifies as producing one are not a form that produces none."""
    with pytest.raises(ValidationError):
        AuthorizingDecision(
            kind=OwnerDecisionKind.NEXT_STAGE_AUTHORIZATION,
            produced_authorization=KnownAbsent(basis="none"),  # type: ignore[arg-type]
        )
