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
"""AP-03 §3's identity table, transcribed. Keys are the concrete identity types."""

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
