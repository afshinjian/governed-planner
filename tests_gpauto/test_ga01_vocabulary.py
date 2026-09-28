"""Closed vocabularies: every member accepted, everything else refused.

Design basis: AP-03 §2.3, §4.1, §4.5, §4.8.1, §8.1, §11.2, §12, §13, §14; AP-11 §4
(`VL11-2` — closed vocabularies), §16 (`GP-AUTO-ST-01` tests).

A vocabulary is *closed* when its members are exactly what the frozen text names and
nothing else is accepted. Both halves are tested: membership is enumerated against
AP-03's own lists, and a plausible near-miss string is refused by a strict model
field rather than coerced.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gpauto.bounds import GIT_GRANTABILITY
from gpauto.schema import DomainValue
from gpauto.vocabulary import (
    AmbiguityForm,
    AuthorityBearingContentClass,
    AuthorizationDisposition,
    BoundedPreflightPermission,
    ExternalActionClass,
    GitActionClass,
    GitCapabilityClass,
    GitGrantabilityTier,
    GovernanceCase,
    GovernedFactKind,
    IdentityKind,
    OwnerDecisionKind,
    Provenance,
    RaAttribute,
    Role,
    RootResolutionOutcome,
    StageOutcomeDisposition,
    WriteMode,
)

EVERY_VOCABULARY = (
    IdentityKind,
    Role,
    RaAttribute,
    AuthorityBearingContentClass,
    AuthorizationDisposition,
    BoundedPreflightPermission,
    RootResolutionOutcome,
    AmbiguityForm,
    GovernanceCase,
    WriteMode,
    ExternalActionClass,
    GitActionClass,
    GitGrantabilityTier,
    GitCapabilityClass,
    Provenance,
    GovernedFactKind,
    OwnerDecisionKind,
    StageOutcomeDisposition,
)


class RoleHolder(DomainValue):
    role: Role


@pytest.mark.parametrize("vocabulary", EVERY_VOCABULARY, ids=lambda v: v.__name__)
@pytest.mark.traces("ST01-D3")
def test_every_member_value_is_its_own_name(vocabulary: type[Role]) -> None:
    """The token is the same in source, in a record and on the wire.

    Following the spike's `states.py` convention: a value that differed from its name
    would be a translation table, and a translation table can drift from the names it
    translates.
    """
    assert [member.value for member in vocabulary] == [member.name for member in vocabulary]


@pytest.mark.traces("ST01-D3")
def test_the_six_roles_are_exactly_ap03s_six() -> None:
    """AP-03 §2.3 and §14: a closed enumeration of six, and a role confers nothing."""
    assert [member.value for member in Role] == [
        "OWNER",
        "COORDINATOR",
        "IMPLEMENTER",
        "DISCOVERY_REVIEWER",
        "REMEDIATOR",
        "BOUNDED_CLOSURE_VERIFIER",
    ]


@pytest.mark.traces("AP03-I05")
def test_the_dispositions_carry_no_superseded_member() -> None:
    """Supersession is expressed only by explicit revocation or binding change.

    Never inferred — not from recency, not from arrival order, and not from the
    existence of a later record (`AP03-I05`, AP-03 §4.1). A `SUPERSEDED` member would
    be a place for exactly that inference to be recorded.
    """
    assert [member.value for member in AuthorizationDisposition] == [
        "LIVE",
        "CONSUMED",
        "REVOKED",
        "SUSPENDED",
    ]


@pytest.mark.traces("AP03-I16")
def test_the_git_grantable_value_space_is_none_or_bounded_read() -> None:
    """*"Today's grantable Git value space is therefore: none, or bounded read."*

    The grantable enumeration is the **whole** admissible value space of the Git
    dimension, so staging, commit, tag, push and history mutation are not merely
    refused in a bounds value — they are inexpressible in one (AP-03 §4.8.1).
    """
    assert [member.value for member in GitCapabilityClass] == ["NONE", "BOUNDED_READ"]


@pytest.mark.traces("AP03-I16")
def test_the_three_git_tiers_are_all_present_and_none_has_moved() -> None:
    """The reserved middle tier is retained rather than collapsed (`AP03-I16`).

    Collapsing staging and commit into the permanent tier would decide, against AP-01
    and AP-02, that a scope change the OWNER reserved could never be expressed.
    Retaining it grants nothing: neither class is in the grantable value space above.
    """
    by_tier: dict[GitGrantabilityTier, list[str]] = {tier: [] for tier in GitGrantabilityTier}
    for action, tier in GIT_GRANTABILITY.items():
        by_tier[tier].append(action.value)

    assert by_tier[GitGrantabilityTier.CURRENTLY_GRANTABLE] == [
        "READ_STATUS",
        "READ_DIFF",
        "READ_LOG",
        "READ_SHOW",
        "READ_REV_PARSE",
    ]
    assert by_tier[GitGrantabilityTier.CURRENTLY_NON_GRANTABLE_RESERVED] == ["STAGING", "COMMIT"]
    assert by_tier[GitGrantabilityTier.PERMANENTLY_NON_GRANTABLE] == [
        "TAG",
        "PUSH",
        "HISTORY_MUTATION",
    ]


@pytest.mark.traces("AP03-I16")
def test_every_observable_git_action_class_has_a_tier() -> None:
    """The observable vocabulary is complete, so any observed act is recordable."""
    assert set(GIT_GRANTABILITY) == set(GitActionClass)


@pytest.mark.traces("AP03-I20")
def test_provenance_has_exactly_two_values_and_no_third_for_forbidden_material() -> None:
    """Hidden reasoning and copied conclusions get **no provenance value** (`AP03-I20`).

    A third member would be the container whose absence is the control: containment
    rests on not supplying and on placement, not on detection.
    """
    assert [member.value for member in Provenance] == ["OBJECTIVE", "WORKER_AUTHORED"]


@pytest.mark.traces("ST01-D3")
def test_the_four_resolution_outcomes_are_the_only_ones_admitted() -> None:
    """AP-03 §4.5's outcome table, and nothing beside it."""
    assert [member.value for member in RootResolutionOutcome] == [
        "AUTHORIZATION_MISSING",
        "RESOLVED_ROOT",
        "AMBIGUITY_DISTINCT_MULTIPLICITY",
        "AMBIGUITY_SAME_IDENTITY_CONFLICT",
    ]


@pytest.mark.traces("ST01-T2")
def test_a_closed_vocabulary_accepts_every_member_on_a_strict_field() -> None:
    """Acceptance, the positive half."""
    for member in Role:
        assert RoleHolder(role=member).role is member


@pytest.mark.traces("ST01-T2")
def test_a_closed_vocabulary_refuses_a_near_miss_on_construction() -> None:
    """Refusal, the negative half.

    Under `strict=True` a bare `str` is refused before membership is even considered
    (`is_instance_of`), which is stricter than an enum-membership check: a member's
    *value* passed as a plain string is refused too, so no vocabulary can be entered
    by spelling rather than by naming.
    """
    with pytest.raises(ValidationError) as caught:
        RoleHolder(role="REVIEWER")  # type: ignore[arg-type]
    assert caught.value.errors()[0]["type"] == "is_instance_of"

    with pytest.raises(ValidationError):
        RoleHolder(role="IMPLEMENTER")  # type: ignore[arg-type]


@pytest.mark.traces("ST01-T2")
def test_a_closed_vocabulary_refuses_a_near_miss_on_the_json_path() -> None:
    """The decode path is where an unknown token would actually arrive.

    `model_validate_json` is the only JSON entry point this package permits, so the
    refusal that matters is the one it gives: a non-member token is an `enum` error,
    and a member token decodes.
    """
    assert RoleHolder.model_validate_json('{"role": "IMPLEMENTER"}').role is Role.IMPLEMENTER

    with pytest.raises(ValidationError) as caught:
        RoleHolder.model_validate_json('{"role": "REVIEWER"}')
    assert caught.value.errors()[0]["type"] == "enum"


@pytest.mark.traces("AP03-I16", "ST01-N8")
def test_the_git_grantability_mapping_cannot_be_mutated() -> None:
    """`AP03-I16`: no tier moved here, and none movable later at run time.

    `Final` stops the name being rebound and does nothing about the object behind it,
    so a plain `dict` would leave the frozen three-tier classification editable — one
    assignment could move staging into the grantable tier, or collapse the reserved
    tier into the permanent one. Both are changes to a frozen boundary.
    """
    before = dict(GIT_GRANTABILITY)

    with pytest.raises(TypeError):
        GIT_GRANTABILITY[GitActionClass.STAGING] = (  # type: ignore[index]
            GitGrantabilityTier.CURRENTLY_GRANTABLE
        )
    with pytest.raises(TypeError):
        del GIT_GRANTABILITY[GitActionClass.TAG]  # type: ignore[attr-defined]

    for method in ("update", "clear", "pop", "popitem", "setdefault"):
        assert not hasattr(GIT_GRANTABILITY, method), method

    assert dict(GIT_GRANTABILITY) == before
    assert GIT_GRANTABILITY[GitActionClass.STAGING] is (
        GitGrantabilityTier.CURRENTLY_NON_GRANTABLE_RESERVED
    )


@pytest.mark.traces("AP03-I16", "ST01-N8")
def test_no_mutable_backing_object_for_the_grantability_mapping_is_exposed() -> None:
    """A read-only view over a dict something else still holds is not read-only.

    The mapping is built from a literal bound to no other name, so no module attribute
    exposes an editable copy of it — which is what `R05`'s introspection clause asks
    for.
    """
    from gpauto import bounds

    assert not isinstance(GIT_GRANTABILITY, dict)
    exposed = [
        name
        for name, value in vars(bounds).items()
        if isinstance(value, dict) and value == dict(GIT_GRANTABILITY)
    ]
    assert exposed == []


@pytest.mark.traces("AP03-I16", "ST01-N8")
def test_a_copy_of_the_grantability_mapping_is_not_the_mapping() -> None:
    """Copying is permitted and changes nothing: the table itself is unaffected."""
    detached = dict(GIT_GRANTABILITY)
    detached[GitActionClass.PUSH] = GitGrantabilityTier.CURRENTLY_GRANTABLE
    assert GIT_GRANTABILITY[GitActionClass.PUSH] is (GitGrantabilityTier.PERMANENTLY_NON_GRANTABLE)


@pytest.mark.traces("ST01-D3", "AP03-I25", "AP03-I34")
@pytest.mark.traces('SC01-V5')
def test_st01c2_exact_decision_and_outcome_vocabularies() -> None:
    assert {kind.value for kind in OwnerDecisionKind} == {
        "STAGE_ENTRY_AUTHORIZATION",
        "NEXT_STAGE_AUTHORIZATION",
        "SCOPE_CHANGE",
        "AUTHORITY_EXPANSION",
        "FINDING_DISPUTE",
        "WAIVER",
        "DEFERRAL",
        "OBLIGATION_CHANGE",
        "EXCEPTIONAL_RECOVERY",
        "STAGE_OUTCOME",
        "REFUSAL_RESOLUTION",
        "REVOCATION",
    }
    assert {outcome.value for outcome in StageOutcomeDisposition} == {
        "ACCEPTED",
        "REFUSED",
        "ABANDONED",
        "ACCEPT_PARTIAL",
    }


@pytest.mark.traces("SP6-V5", "ST01-D3")
def test_st06pc1_the_external_action_classes_are_exactly_four() -> None:
    """SP6-V5: AP-03 §4.8's three, then AP-06 `XA-1`'s area, each value its name.

    A ceiling member and an envelope carrying the fourth class each construct and
    round-trip. No validator refuses `EGRESS`, `INSTALL` or `EXTERNAL_MUTATION` in a member
    at the type level: that a member carrying one is invalid is `RA-07` validity, which
    is `GP-AUTO-ST-06`'s (SP6-12).
    """
    import fixtures
    import st02_support

    assert [member.value for member in ExternalActionClass] == [
        "EGRESS",
        "INSTALL",
        "EXTERNAL_MUTATION",
        "BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA",
    ]
    assert [member.name for member in ExternalActionClass] == [
        member.value for member in ExternalActionClass
    ]
    area = (ExternalActionClass.BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA,)
    member = st02_support.rebuilt(
        fixtures.implementer_ceiling_member(), external_action_classes=area
    )
    envelope = st02_support.rebuilt(
        fixtures.authority_envelope(),
        bounds=st02_support.rebuilt(fixtures.writing_bounds(), external_action_classes=area),
    )
    structurally_admitted = [
        st02_support.rebuilt(fixtures.implementer_ceiling_member(), external_action_classes=(cls,))
        for cls in (
            ExternalActionClass.EGRESS,
            ExternalActionClass.INSTALL,
            ExternalActionClass.EXTERNAL_MUTATION,
        )
    ]
    for instance in (member, envelope, *structurally_admitted):
        assert type(instance).model_validate_json(instance.model_dump_json()) == instance
