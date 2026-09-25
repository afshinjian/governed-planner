"""Identity kinds: declared as AP-03 declares them, and never interchangeable.

Design basis: AP-03 §3 (identity model and its table), §3.1 (the seven identity
confusions the brief requires resolved), §4.2; `AP03-I03`, `AP03-I12`, `AP03-I33`;
AP-11 §16 (`GP-AUTO-ST-01` negative tests — identity kinds not interchangeable).

AP-03 §3.1 resolves seven confusions, and each is a claim that two identities must
not stand in for one another. This module tests all seven as *refusals produced by
the types*, not as naming conventions: the evidence is a `ValidationError`, and the
error type is `model_type` — a class mismatch — rather than a value complaint.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from gpauto import identity as gid
from gpauto.identity import DomainIdentity
from gpauto.vocabulary import IdentityKind
from introspection_support import holder_for

EXPECTED_KINDS: dict[str, tuple[IdentityKind, ...]] = {
    "ProjectId": (IdentityKind.SUPPLIED,),
    "GovernedStageId": (IdentityKind.SUPPLIED,),
    "RepositoryBoundaryId": (IdentityKind.SUPPLIED,),
    "BaselineIdentityId": (IdentityKind.SUPPLIED,),
    "OwnerAuthorizationId": (IdentityKind.SUPPLIED,),
    "OwnerDecisionId": (IdentityKind.SUPPLIED,),
    "AuthorizationRecordId": (IdentityKind.MINTED, IdentityKind.SUPPLIED),
    "StageContractId": (IdentityKind.CONTENT,),
    "ArtifactContentId": (IdentityKind.CONTENT,),
    "EntryStateBoundaryId": (IdentityKind.MINTED,),
    "RootResolutionId": (IdentityKind.MINTED,),
    "AuthorityEnvelopeId": (IdentityKind.MINTED,),
    "WorkerActivationId": (IdentityKind.MINTED,),
    "InputPackageId": (IdentityKind.MINTED,),
    "ArtifactProductionId": (IdentityKind.MINTED,),
    "FindingId": (IdentityKind.MINTED,),
    "FrozenFindingSetId": (IdentityKind.MINTED,),
    "PostFreezeCandidateId": (IdentityKind.MINTED,),
    "RefusalId": (IdentityKind.MINTED,),
    "EnvelopeViolationId": (IdentityKind.MINTED,),
    "AuthorityAmbiguityId": (IdentityKind.MINTED,),
    "UnaccountedMutationId": (IdentityKind.MINTED,),
    "CandidateExclusionId": (IdentityKind.DEPENDENT,),
    "ActivationEffectId": (IdentityKind.DEPENDENT,),
    "RemediationObligationId": (IdentityKind.DEPENDENT,),
    "ClosureAssessmentId": (IdentityKind.DEPENDENT,),
    "StageOutcomeId": (IdentityKind.DEPENDENT,),
}
"""AP-03 §3's identity table as kind data. Keys are the concrete identity types.

The tuple lists *alternative* kinds, not a composition, so it is not the whole of every
row. `StageOutcomeId` is AP-03's *minted, dependent on GovernedStage*: it is recorded as
`DEPENDENT`, like `ActivationEffectId`, and its minted-per-occurrence part is a field —
`local_discriminator` — beside its parent, not a second kind here. The row is therefore
not a one-field transcription of AP-03 §3; the tests below assert the field shape.
"""

ABSTRACT_IDENTITY_NAMES = frozenset(
    {
        "DomainIdentity",
        "OpaqueIdentity",
        "SuppliedIdentity",
        "MintedIdentity",
        "ContentIdentity",
        "DependentIdentity",
    }
)


def concrete_identity_types() -> dict[str, type[DomainIdentity]]:
    found: dict[str, type[DomainIdentity]] = {}
    for name, attribute in vars(gid).items():
        if (
            isinstance(attribute, type)
            and issubclass(attribute, DomainIdentity)
            and name not in ABSTRACT_IDENTITY_NAMES
        ):
            found[name] = attribute
    return found


@pytest.mark.traces("ST01-D2", "ST01-A1")
def test_every_identity_ap03_names_exists_and_no_other_does() -> None:
    """The identity set is AP-03's, neither short nor extended."""
    assert set(concrete_identity_types()) == set(EXPECTED_KINDS)


@pytest.mark.traces("AP03-I03")
@pytest.mark.parametrize("name", sorted(EXPECTED_KINDS))
def test_each_identity_declares_the_kind_ap03_gives_it(name: str) -> None:
    """AP-03 §3's table is the authority; the class records it as data.

    `OwnerAuthorizationId` in particular is **supplied, deliberately not
    content-derived**: a content-derived identity would make *"same identity,
    conflicting content"* impossible by construction, and AP-02 requires that case to
    be representable and halting (`AP03-I03`).
    """
    assert concrete_identity_types()[name].IDENTITY_KINDS == EXPECTED_KINDS[name]


@pytest.mark.traces("AP03-I03")
def test_the_authorization_identity_is_not_content_derived() -> None:
    """Two authorization identities with identical content are still two identities.

    Nothing in the type derives the identity value from anything; it is supplied, and
    equal content does not make equal identity.
    """
    one = gid.OwnerAuthorizationId(value="alpha")
    two = gid.OwnerAuthorizationId(value="beta")
    assert one != two
    assert gid.OwnerAuthorizationId(value="alpha") == one


CONFUSIONS: tuple[tuple[str, type[DomainIdentity], DomainIdentity], ...] = (
    (
        "1 authorization identity vs the record asserting it",
        gid.OwnerAuthorizationId,
        gid.AuthorizationRecordId(value="x"),
    ),
    (
        "2 envelope identity vs the bounds it carries",
        gid.AuthorityEnvelopeId,
        gid.OwnerAuthorizationId(value="x"),
    ),
    (
        "3 activation identity vs envelope identity",
        gid.WorkerActivationId,
        gid.AuthorityEnvelopeId(value="x"),
    ),
    (
        "4 stage identity vs stage-contract identity",
        gid.GovernedStageId,
        gid.StageContractId(value="x"),
    ),
    (
        "5 project identity vs repository identity",
        gid.ProjectId,
        gid.RepositoryBoundaryId(value="x"),
    ),
    (
        "6 finding identity vs finding-set identity",
        gid.FindingId,
        gid.FrozenFindingSetId(value="x"),
    ),
    (
        "7 content identity vs production identity",
        gid.ArtifactContentId,
        gid.ArtifactProductionId(value="x"),
    ),
)


@pytest.mark.traces("AP03-I33", "ST01-N3")
@pytest.mark.supports("AP03-I12")
@pytest.mark.parametrize(("label", "expected", "wrong"), CONFUSIONS, ids=lambda v: str(v)[:40])
def test_the_seven_identity_confusions_are_refused_by_the_types(
    label: str, expected: type[DomainIdentity], wrong: DomainIdentity
) -> None:
    """Each of AP-03 §3.1's seven rows, as a refusal rather than a convention."""
    holder = holder_for(expected)
    with pytest.raises(ValidationError) as caught:
        holder(slot=wrong)
    assert caught.value.errors()[0]["type"] == "model_type", label


@pytest.mark.traces("AP03-I33", "ST01-N3")
def test_baseline_identity_and_the_entry_observation_are_not_interchangeable() -> None:
    """AP-01 requires baseline identity and the entry observation to be distinct
    modelled concepts rather than one *"repository state"* blob (AP-03 §7.1)."""
    holder = holder_for(gid.BaselineIdentityId)
    with pytest.raises(ValidationError):
        holder(slot=gid.EntryStateBoundaryId(value="x"))


@pytest.mark.traces("ST01-N3")
def test_two_identities_of_one_kind_are_still_not_interchangeable() -> None:
    """Sharing a kind is not sharing a type.

    `ProjectId` and `GovernedStageId` are both supplied; substituting one for the
    other is still refused, so the kind is an annotation on the type rather than a
    class of interchangeable things.
    """
    assert gid.ProjectId.IDENTITY_KINDS == gid.GovernedStageId.IDENTITY_KINDS
    holder = holder_for(gid.ProjectId)
    with pytest.raises(ValidationError):
        holder(slot=gid.GovernedStageId(value="x"))


@pytest.mark.traces("ST01-D2")
def test_a_dependent_identity_cannot_be_built_without_its_parent() -> None:
    """*"Identified only relative to a named parent"* is structural, not documentary."""
    with pytest.raises(ValidationError) as caught:
        gid.RemediationObligationId(parent_frozen_set=gid.FrozenFindingSetId(value="s"))  # type: ignore[call-arg]
    assert caught.value.errors()[0]["type"] == "missing"


@pytest.mark.traces("ST01-N3")
def test_a_dependent_identity_refuses_a_parent_of_the_wrong_kind() -> None:
    """The parent reference is typed, so the dependency cannot be miswired."""
    with pytest.raises(ValidationError):
        gid.ClosureAssessmentId(
            assessed_finding=gid.PostFreezeCandidateId(value="c"),  # type: ignore[arg-type]
            closure_activation=gid.WorkerActivationId(value="a"),
        )


@pytest.mark.traces("ST01-D2")
def test_a_dependent_identity_is_equal_only_when_its_whole_pair_is() -> None:
    """The pair *is* the identity (AP-03 §3), so neither half alone names it."""
    first = gid.RemediationObligationId(
        parent_frozen_set=gid.FrozenFindingSetId(value="s1"),
        member_finding=gid.FindingId(value="f1"),
    )
    same = gid.RemediationObligationId(
        parent_frozen_set=gid.FrozenFindingSetId(value="s1"),
        member_finding=gid.FindingId(value="f1"),
    )
    other_set = gid.RemediationObligationId(
        parent_frozen_set=gid.FrozenFindingSetId(value="s2"),
        member_finding=gid.FindingId(value="f1"),
    )
    assert first == same
    assert first != other_set


def _outcome_id(stage: str, discriminator: str) -> gid.StageOutcomeId:
    return gid.StageOutcomeId(
        parent_stage=gid.GovernedStageId(value=stage), local_discriminator=discriminator
    )


@pytest.mark.traces("ST01-D2")
def test_a_stage_outcome_identity_is_its_stage_and_a_minted_discriminator() -> None:
    """AP-03 §3: *minted, dependent on GovernedStage*; AP-07 `ID-8`: stored as
    (parent, discriminator), never flattened. The shape is exactly that pair."""
    assert gid.StageOutcomeId.IDENTITY_KINDS == (IdentityKind.DEPENDENT,)
    assert issubclass(gid.StageOutcomeId, gid.DependentIdentity)
    assert not issubclass(gid.StageOutcomeId, gid.OpaqueIdentity)
    fields = gid.StageOutcomeId.model_fields
    assert set(fields) == {"parent_stage", "local_discriminator"}
    assert fields["parent_stage"].annotation is gid.GovernedStageId
    assert fields["local_discriminator"].annotation is str


@pytest.mark.traces("ST01-D2")
def test_two_outcomes_of_one_stage_are_two_identities() -> None:
    """One stage may settle once per authorization epoch, each settlement its own
    outcome; a parent-only identity would make the second one the first."""
    first = _outcome_id("stage", "outcome-1")
    second = _outcome_id("stage", "outcome-2")
    assert first.parent_stage == second.parent_stage
    assert first != second
    assert first.model_dump_json() != second.model_dump_json()
    assert len({first, second}) == 2


@pytest.mark.traces("ST01-D2")
def test_local_discriminator_participates_in_stage_outcome_id_hashing() -> None:
    """Changing only the discriminator changes the hash.

    Set size alone cannot show this: a hash over `parent_stage` alone still yields two
    set members, because equality separates them after the collision. The hash values
    themselves must differ.
    """
    stage = gid.GovernedStageId(value="stage")
    outcome_a = gid.StageOutcomeId(parent_stage=stage, local_discriminator="outcome-a")
    outcome_b = gid.StageOutcomeId(parent_stage=stage, local_discriminator="outcome-b")
    assert outcome_a != outcome_b
    assert hash(outcome_a) != hash(outcome_b)


@pytest.mark.traces("ST01-D2")
def test_a_stage_outcome_identity_is_equal_only_when_its_whole_pair_is() -> None:
    """Same parent and same discriminator is one identity, however often built; a
    different parent under the same discriminator is another."""
    first = _outcome_id("stage", "outcome")
    same = _outcome_id("stage", "outcome")
    other_stage = _outcome_id("other-stage", "outcome")
    assert first == same
    assert hash(first) == hash(same)
    assert first.model_dump_json() == same.model_dump_json()
    assert first != other_stage
    assert first.model_dump_json() != other_stage.model_dump_json()


@pytest.mark.traces("ST01-D2")
def test_a_stage_outcome_identity_round_trips_with_its_discriminator() -> None:
    """The discriminator survives the permitted JSON path, and decoding keeps it
    distinguishing: two outcomes of one stage decode to two identities."""
    first = _outcome_id("stage", "outcome-1")
    second = _outcome_id("stage", "outcome-2")
    for identity in (first, second):
        encoded = identity.model_dump_json()
        assert '"local_discriminator"' in encoded
        decoded = gid.StageOutcomeId.model_validate_json(encoded)
        assert decoded == identity
        assert decoded.model_dump_json() == encoded
    assert gid.StageOutcomeId.model_validate_json(
        first.model_dump_json()
    ) != gid.StageOutcomeId.model_validate_json(second.model_dump_json())


@pytest.mark.traces("ST01-D2")
def test_a_stage_outcome_identity_cannot_be_built_from_its_stage_alone() -> None:
    """The discriminator is required, so the collapsed single-parent form is refused."""
    with pytest.raises(ValidationError) as caught:
        gid.StageOutcomeId(parent_stage=gid.GovernedStageId(value="s"))  # type: ignore[call-arg]
    assert caught.value.errors()[0]["type"] == "missing"
    with pytest.raises(ValidationError) as decoded:
        gid.StageOutcomeId.model_validate_json('{"parent_stage": {"value": "s"}}')
    assert decoded.value.errors()[0]["type"] == "missing"


MALFORMED_DISCRIMINATORS: tuple[object, ...] = (1, None, b"outcome", ("outcome",))


@pytest.mark.traces("ST01-N3")
@pytest.mark.parametrize("owner", [gid.StageOutcomeId, gid.ActivationEffectId])
@pytest.mark.parametrize("malformed", MALFORMED_DISCRIMINATORS, ids=repr)
def test_a_malformed_discriminator_is_refused_as_the_precedent_refuses_it(
    owner: type[gid.DependentIdentity], malformed: object
) -> None:
    """`ActivationEffectId` is the accepted dependent-plus-discriminator precedent;
    `StageOutcomeId` refuses exactly what it refuses, with the same error type."""
    parent_field, discriminator_field = owner.model_fields
    parent: Any = (
        gid.GovernedStageId(value="s")
        if owner is gid.StageOutcomeId
        else gid.WorkerActivationId(value="a")
    )
    with pytest.raises(ValidationError) as caught:
        owner(**{parent_field: parent, discriminator_field: malformed})
    assert caught.value.errors()[0]["type"] == "string_type"


@pytest.mark.traces("ST01-N3")
def test_a_stage_outcome_identity_refuses_a_parent_of_the_wrong_kind() -> None:
    """Dependent on a GovernedStage — not a project, not an authorization."""
    for wrong in (gid.ProjectId(value="s"), gid.OwnerAuthorizationId(value="s")):
        with pytest.raises(ValidationError):
            gid.StageOutcomeId(parent_stage=wrong, local_discriminator="o")  # type: ignore[arg-type]


@pytest.mark.traces("AP03-I25")
def test_a_stage_outcome_identity_names_no_authorization() -> None:
    """`SO-1`: the discriminator is not derived from the authorization, and the
    identity has no slot that could name one or its record."""
    for field_info in gid.StageOutcomeId.model_fields.values():
        assert field_info.annotation not in (gid.OwnerAuthorizationId, gid.AuthorizationRecordId)
    with pytest.raises(ValidationError) as caught:
        gid.StageOutcomeId(
            parent_stage=gid.GovernedStageId(value="s"),
            local_discriminator="o",
            authorization=gid.OwnerAuthorizationId(value="a"),  # type: ignore[call-arg]
        )
    assert caught.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.traces("ST01-D1")
def test_identities_are_frozen() -> None:
    """An identity that could be edited in place would not be stable across anything."""
    project = gid.ProjectId(value="p")
    with pytest.raises(ValidationError):
        project.value = "q"


@pytest.mark.traces("ST01-N3")
def test_a_model_built_on_a_base_would_be_substitutable_which_is_why_none_is_annotated() -> None:
    """The reason `test_ga06` asserts no field is annotated with a base class.

    Demonstrated rather than asserted in prose: annotating a base **does** admit any
    subclass, so the guarantee in this module rests entirely on no field doing it.
    """
    permissive = holder_for(DomainIdentity)
    accepted: Any = permissive(slot=gid.ProjectId(value="p"))
    assert accepted.slot == gid.ProjectId(value="p")
    also_accepted: Any = permissive(slot=gid.FindingId(value="f"))
    assert also_accepted.slot == gid.FindingId(value="f")
