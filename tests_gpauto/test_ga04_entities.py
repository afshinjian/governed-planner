"""Every AP-03 entity is constructible and round-trips, and no other entity exists.

Design basis: AP-03 §2.1–§2.7 (entity inventory), §16 (relationships); AP-11 §16
(`GP-AUTO-ST-01` tests and acceptance — every AP-03 entity representable, no entity
outside AP-03 introduced).

Round-trip goes **through the JSON path this package permits and no other**:
`model_dump_json` out, `model_validate_json` back. `json.loads` + `model_validate` is
forbidden package-wide — strict models with `tuple[...]` fields refuse the `list`
that `json.loads` produces — and the GP-AUTO decode/import gate in `test_ga07`
enforces the rule by imports rather than by call shape.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

import fixtures
import st02_support
from gpauto import bounds
from gpauto.absence import NotApplicable
from gpauto.authorization import OwnerAuthorization
from gpauto.bounds import AuthorityBounds, AuthorityCeilingMember
from gpauto.schema import DomainEntity, DomainValue
from gpauto.vocabulary import Role
from introspect import entity_classes

AP03_ENTITY_INVENTORY = frozenset(
    {
        # §2.1 scope-frame
        "Project",
        "GovernedStage",
        "StageContract",
        "RepositoryBoundary",
        "BaselineIdentity",
        # §2.2 authorization
        "OwnerAuthorization",
        "AuthorizationRecord",
        "RootResolution",
        "CandidateExclusion",
        "AuthorityAmbiguity",
        # §2.3 derived authority
        "AuthorityEnvelope",
        "WorkerActivation",
        "InputPackage",
        # §2.4 repository state
        "EntryStateBoundary",
        "ActivationEffect",
        "UnaccountedMutation",
        # §2.5 artifacts
        "ArtifactContent",
        "ArtifactProduction",
        # §2.6 review / finding
        "Finding",
        "FrozenFindingSet",
        "RemediationObligation",
        "ClosureAssessment",
        "PostFreezeCandidate",
        # §2.7 governance events and OWNER
        "Refusal",
        "EnvelopeViolation",
        "OwnerDecision",
        "StageOutcome",
    }
)
"""AP-03 §2's retained entities, transcribed from the frozen inventory."""


@pytest.mark.traces("ST01-A2")
def test_the_package_declares_exactly_ap03s_entities() -> None:
    """Neither short nor extended.

    Short would mean an AP-03 entity is unrepresentable; extended would mean an entity
    AP-03 does not have, which is an invented requirement (`TR11-7`, `AP-00 §4.3`).
    """
    declared = {cls.__name__ for cls in entity_classes()}
    assert declared == AP03_ENTITY_INVENTORY


@pytest.mark.traces("ST01-T1")
def test_every_entity_has_one_well_formed_instance_in_the_fixtures() -> None:
    """The round-trip test below is only as complete as this enumeration."""
    assert {name for name, _ in fixtures.EVERY_ENTITY} == AP03_ENTITY_INVENTORY


@pytest.mark.parametrize(("name", "instance"), fixtures.EVERY_ENTITY, ids=lambda v: str(v)[:32])
@pytest.mark.traces("ST01-T1", "ST01-A1")
def test_every_entity_constructs_and_round_trips(name: str, instance: DomainEntity) -> None:
    """Construction and round-trip, per entity, through the permitted JSON path."""
    encoded = instance.model_dump_json()
    decoded = type(instance).model_validate_json(encoded)
    assert decoded == instance, name
    assert decoded.model_dump_json() == encoded, name


@pytest.mark.traces("ST01-T1")
def test_both_ambiguity_forms_round_trip() -> None:
    """One entity, two forms (AP-03 §2.2) — both must survive the JSON path."""
    for instance in (
        fixtures.authority_ambiguity_distinct(),
        fixtures.authority_ambiguity_same_identity(),
    ):
        assert type(instance).model_validate_json(instance.model_dump_json()) == instance


@pytest.mark.traces("AP03-I22", "ST01-T1")
def test_a_zero_finding_frozen_set_is_a_real_fully_identified_object() -> None:
    """The zero-finding PASS is a set with empty membership, not an absent set."""
    empty = fixtures.empty_frozen_finding_set()
    assert empty.members == ()
    assert empty.identity.value
    assert type(empty).model_validate_json(empty.model_dump_json()) == empty


@pytest.mark.traces("AP03-I22")
def test_two_empty_frozen_sets_are_two_sets() -> None:
    """Set identity is not derived from membership (AP-03 §3.1 row 6).

    Were it derived, every zero-finding stage in the system would share one identity,
    and *"stage A froze empty"* would be the same fact as *"stage B froze empty"*.
    """
    from gpauto.identity import FrozenFindingSetId

    first = fixtures.empty_frozen_finding_set()
    second = first.model_copy(update={"identity": FrozenFindingSetId(value="another-empty-set")})
    assert first.members == second.members == ()
    assert first != second


@pytest.mark.traces("ST01-T1")
@pytest.mark.supports("AP03-I35")
def test_a_consumed_or_suspended_authorization_is_still_an_instance() -> None:
    """*"Existence is not eligibility"* (`AP03-I35`).

    A disposition is a statement about governing capacity. The instance keeps its
    identity and every binding under all of them, which is what lets *"under what
    authority was this effect produced?"* stay answerable after the authority ends.
    """
    live = fixtures.owner_authorization()
    for variant in (fixtures.consumed_authorization(), fixtures.suspended_authorization()):
        assert variant.identity == live.identity
        assert variant.stage == live.stage
        assert variant.constituting_records == live.constituting_records
        assert type(variant).model_validate_json(variant.model_dump_json()) == variant


@pytest.mark.traces("AP03-I23")
def test_obligation_identity_is_addressable_apart_from_set_membership() -> None:
    """A waiver must be able to extinguish an obligation without touching membership.

    The obligation is identified by the `(frozen set, finding)` pair, so it is
    addressable on its own — and the frozen set's `members` tuple is untouched by
    anything that happens to it (`FS-2`, `FS-5`).
    """
    obligation = fixtures.remediation_obligation()
    frozen_set = fixtures.frozen_finding_set()
    assert obligation.identity.parent_frozen_set == frozen_set.identity
    assert obligation.identity.member_finding in frozen_set.members
    assert "obligation" not in set(type(frozen_set).model_fields)


@pytest.mark.supports("AP03-I24")
@pytest.mark.traces("ST01-D2")
def test_closure_is_assessed_per_finding_and_per_closure_activation() -> None:
    """*"Three of five verified"* is statable because closure has membership."""
    assessment = fixtures.closure_assessment()
    assert assessment.identity.assessed_finding == fixtures.FINDING_ID
    assert assessment.identity.closure_activation == fixtures.ACTIVATION_ID


@pytest.mark.traces("AP03-I25", "ST01-T1")
def test_all_three_owner_decision_act_forms_round_trip() -> None:
    """The valid forms survive encode and decode as themselves (AP-03 §11.2).

    Constraining acceptance must not cost the representation of the acts that do
    produce an authorization, nor of the one conditional act. All three are built and
    round-tripped here so the constraint is shown to be a narrowing and not a loss.
    """
    for decision in (
        fixtures.owner_decision(),
        fixtures.authorizing_owner_decision(),
        fixtures.exceptional_recovery_decision(),
    ):
        encoded = decision.model_dump_json()
        assert type(decision).model_validate_json(encoded) == decision
        assert type(decision).model_validate_json(encoded).model_dump_json() == encoded


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-T1")
def test_both_production_provenances_round_trip_as_themselves() -> None:
    """One entity, two parametrizations, and neither decodes as the other."""
    objective = fixtures.artifact_production()
    authored = fixtures.worker_authored_production()
    for production in (objective, authored):
        encoded = production.model_dump_json()
        assert type(production).model_validate_json(encoded) == production

    with pytest.raises(ValidationError):
        type(objective).model_validate_json(authored.model_dump_json())


@pytest.mark.traces("ST01-T1", "ST01-N6")
def test_every_governed_fact_reference_variant_round_trips() -> None:
    """Eight variants, eight kinds, each surviving the JSON path as itself."""
    from gpauto.activation import (
        AcceptanceCriteriaReference,
        ActivationEffectReference,
        BaselineIdentityReference,
        EntryStateBoundaryReference,
        FrozenFindingSetReference,
        RemediationObligationReference,
        StageContractPartReference,
        StageContractReference,
    )
    from gpauto.identity import ActivationEffectId, RemediationObligationId
    from gpauto.vocabulary import StageContractPart

    variants = (
        StageContractReference(contract=fixtures.CONTRACT_ID),
        StageContractPartReference(
            contract=fixtures.CONTRACT_ID, part=StageContractPart.REVIEW_INSTRUCTIONS
        ),
        AcceptanceCriteriaReference(contract=fixtures.CONTRACT_ID),
        BaselineIdentityReference(baseline=fixtures.BASELINE_ID),
        EntryStateBoundaryReference(entry_boundary=fixtures.BOUNDARY_ID),
        FrozenFindingSetReference(frozen_set=fixtures.FROZEN_SET_ID),
        RemediationObligationReference(
            obligation=RemediationObligationId(
                parent_frozen_set=fixtures.FROZEN_SET_ID, member_finding=fixtures.FINDING_ID
            )
        ),
        ActivationEffectReference(
            effect=ActivationEffectId(
                parent_activation=fixtures.ACTIVATION_ID, local_discriminator="e"
            )
        ),
    )
    for reference in variants:
        assert type(reference).model_validate_json(reference.model_dump_json()) == reference


# --- ST06PC-1: the role-indexed ceiling (SP6-V1, SP6-V2, SP6-V6(b)) ----------------------


@pytest.mark.traces("SP6-V1")
def test_st06pc1_a_ceiling_member_is_the_ten_conveyed_dimensions_and_nothing_else() -> None:
    """SP6-V1: exactly `AuthorityBounds`' fields minus `frozen_set_reference`, in its
    relative order, each annotated with the identical object the same-named
    `AuthorityBounds` field carries (`is`, never structural equality — SP6A-7, SP6A-V1),
    and the five generic dimensions with the module's shared alias; one direct base,
    `DomainValue`; not an entity and no identity field; strict, closed and frozen."""
    member_fields = AuthorityCeilingMember.model_fields
    bounds_fields = AuthorityBounds.model_fields
    assert list(member_fields) == [
        "role_applicability",
        "action_classes",
        "read_boundary",
        "write_mode",
        "write_boundary",
        "tool_categories",
        "external_action_classes",
        "git_capability_class",
        "scope_frame",
        "authoritative_input_designation",
    ]
    assert list(member_fields) == [n for n in bounds_fields if n != "frozen_set_reference"]
    for name, info in member_fields.items():
        assert info.annotation is bounds_fields[name].annotation, name
    aliases: dict[str, object] = {
        "action_classes": bounds.ActionClasses,
        "write_boundary": bounds.RoleConditionalWriteBoundary,
        "tool_categories": bounds.ToolCategories,
        "external_action_classes": bounds.ExternalActionClasses,
        "authoritative_input_designation": bounds.RoleConditionalAuthoritativeInputDesignation,
    }
    for name, alias in aliases.items():
        assert member_fields[name].annotation is alias, name
        assert bounds_fields[name].annotation is alias, name
    assert AuthorityCeilingMember.__bases__ == (DomainValue,)
    assert not issubclass(AuthorityCeilingMember, DomainEntity)
    assert "identity" not in member_fields
    assert AuthorityCeilingMember.model_config == {
        "strict": True,
        "extra": "forbid",
        "frozen": True,
    }


@pytest.mark.traces("SP6-V2")
def test_st06pc1_a_ceiling_member_and_bounds_never_stand_in_for_each_other() -> None:
    """SP6-V2: no inheritance in either direction, so strict validation accepts neither
    where the other is annotated — an `AuthorityBounds` is not a ceiling member, and a
    ceiling member is not an envelope's bounds."""
    assert not issubclass(AuthorityCeilingMember, AuthorityBounds)
    assert not issubclass(AuthorityBounds, AuthorityCeilingMember)
    with pytest.raises(ValidationError) as as_member:
        st02_support.rebuilt(
            fixtures.authority_bearing_content(), authority_ceiling=(fixtures.writing_bounds(),)
        )
    assert ("model_type", ("authority_ceiling", 0)) in [
        (e["type"], e["loc"]) for e in as_member.value.errors()
    ]
    with pytest.raises(ValidationError) as as_bounds:
        st02_support.rebuilt(
            fixtures.authority_envelope(), bounds=fixtures.implementer_ceiling_member()
        )
    assert [e["type"] for e in as_bounds.value.errors()] == ["model_type"]


def _authorization_json_with_ceiling(ceiling: str) -> str:
    authorization = fixtures.owner_authorization()
    members = ",".join(m.model_dump_json() for m in authorization.authority_ceiling)
    text = authorization.model_dump_json()
    current = '"authority_ceiling":[' + members + "]"
    assert text.count(current) == 1
    return text.replace(current, '"authority_ceiling":' + ceiling)


@pytest.mark.traces("SP6-V6")
def test_st06pc1_owner_authorization_carries_a_role_indexed_ceiling() -> None:
    """SP6-V6(b), at model level: `OwnerAuthorization` has no codec path and none is added.
    A non-empty role-indexed ceiling constructs and round-trips equal through the test
    tree's `model_dump_json` / `model_validate_json`, each member an
    `AuthorityCeilingMember`; an empty ceiling, and a member carrying `E-14` or another
    undeclared field, are refused at construction and at `model_validate_json`."""
    authorization = fixtures.owner_authorization()
    assert [m.role_applicability for m in authorization.authority_ceiling] == [
        Role.IMPLEMENTER,
        Role.DISCOVERY_REVIEWER,
    ]
    decoded = OwnerAuthorization.model_validate_json(authorization.model_dump_json())
    assert decoded == authorization
    assert all(type(m) is AuthorityCeilingMember for m in decoded.authority_ceiling)

    with pytest.raises(ValidationError) as empty:
        st02_support.rebuilt(authorization, authority_ceiling=())
    assert [e["type"] for e in empty.value.errors()] == ["too_short"]
    with pytest.raises(ValidationError) as empty_json:
        OwnerAuthorization.model_validate_json(_authorization_json_with_ceiling("[]"))
    assert [e["type"] for e in empty_json.value.errors()] == ["too_short"]

    implementer, reviewer = authorization.authority_ceiling
    fields: dict[str, Any] = {
        name: getattr(implementer, name) for name in AuthorityCeilingMember.model_fields
    }
    for extra, value, text in (
        ("frozen_set_reference", NotApplicable(), NotApplicable().model_dump_json()),
        ("rationale", "prose", '"prose"'),
    ):
        with pytest.raises(ValidationError) as constructed:
            AuthorityCeilingMember(**{**fields, extra: value})
        assert [e["type"] for e in constructed.value.errors()] == ["extra_forbidden"], extra
        widened = (
            "[" + implementer.model_dump_json()[:-1] + f',"{extra}":{text}' + "},"
            + reviewer.model_dump_json() + "]"
        )
        with pytest.raises(ValidationError) as decoded_json:
            OwnerAuthorization.model_validate_json(_authorization_json_with_ceiling(widened))
        assert [e["type"] for e in decoded_json.value.errors()] == ["extra_forbidden"], extra
