"""Three-valued absence is expressible, and each value is a different fact.

Design basis: AP-03 §4.8.2, §5.3 `EV-6`, §7.3, §10.1, §12; `AP03-I15`, `AP03-I30`,
`AP03-I36`; AP-11 §2 (`VP11-5`), §4 (`VL11-2`), §16 (`GP-AUTO-ST-01` tests —
three-valued absence expressible).

Two-valued absence is the failure mode these tests exist to close. *Known to be
absent* and *not observed* are different governance facts, and AP-03 forbids the
inference that turns one into the other: an `UnaccountedMutation` may never claim no
producer exists merely because none is named, and `VP11-5` says the same of every
record.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gpauto.absence import (
    AbsenceState,
    Carried,
    Determined,
    DimensionApplicability,
    KnownAbsent,
    NotApplicable,
    NotObserved,
    Observable,
    Perhaps,
    Present,
)
from gpauto.identity import FrozenFindingSetId, OwnerAuthorizationId, WorkerActivationId
from gpauto.schema import DomainValue


class ThreeValued(DomainValue):
    slot: Perhaps[FrozenFindingSetId]


class TwoValuedDetermined(DomainValue):
    slot: Determined[OwnerAuthorizationId]


class TwoValuedObservable(DomainValue):
    slot: Observable[WorkerActivationId]


class RoleConditionalHolder(DomainValue):
    slot: Carried[FrozenFindingSetId] | NotApplicable


@pytest.mark.traces("ST01-D4", "ST01-T3")
def test_all_three_absence_states_are_expressible_on_one_field() -> None:
    """The positive requirement: three values, one field, no coercion between them."""
    present = ThreeValued(slot=Present[FrozenFindingSetId](value=FrozenFindingSetId(value="s")))
    known_absent = ThreeValued(slot=KnownAbsent(basis="discovery returned malformed output"))
    not_observed = ThreeValued(slot=NotObserved())

    assert present.slot.state is AbsenceState.PRESENT
    assert known_absent.slot.state is AbsenceState.KNOWN_ABSENT
    assert not_observed.slot.state is AbsenceState.NOT_OBSERVED
    assert len({present.slot.state, known_absent.slot.state, not_observed.slot.state}) == 3


@pytest.mark.traces("ST01-T3")
def test_known_absent_and_not_observed_are_not_equal() -> None:
    """The whole point: they are two facts, and nothing makes them one.

    They are disjoint types, so `mypy --strict` rejects even comparing them directly
    as a non-overlapping equality check — the comparison here is between the two
    records that carry them, which is the comparison that actually happens in use.
    """
    assert ThreeValued(slot=KnownAbsent(basis="anything")) != ThreeValued(slot=NotObserved())


@pytest.mark.traces("ST01-T3")
@pytest.mark.supports("AP03-I36")
def test_known_absent_must_say_what_established_the_absence() -> None:
    """An absence with no basis is what `NotObserved` is for.

    Allowing a basis-less `KnownAbsent` would let *"we did not look"* be recorded as
    *"there is none"* — the claim AP-03 §12 forbids.
    """
    with pytest.raises(ValidationError) as caught:
        KnownAbsent()  # type: ignore[call-arg]
    assert caught.value.errors()[0]["type"] == "missing"


@pytest.mark.traces("ST01-T3")
@pytest.mark.supports("AP03-I36")
def test_no_set_exists_an_empty_set_exists_and_not_yet_observed_are_three_facts() -> None:
    """`no set exists` ≠ `an empty set exists` (`AP03-I36`), and neither is *not yet*.

    A zero-finding PASS is `Present` naming a real, empty set. A discovery activation
    that failed structurally is `KnownAbsent`. One still running is `NotObserved`. A
    model with two values would have to fold one of these into another, and since an
    empty set reads as *"discovery passed with no findings"*, the fold would be a
    manufactured pass.
    """
    empty_set_exists = ThreeValued(
        slot=Present[FrozenFindingSetId](value=FrozenFindingSetId(value="empty-set"))
    )
    no_set_exists = ThreeValued(slot=KnownAbsent(basis="discovery halted on a refusal"))
    still_running = ThreeValued(slot=NotObserved())

    assert empty_set_exists != no_set_exists
    assert no_set_exists != still_running
    assert empty_set_exists != still_running


@pytest.mark.traces("ST01-T3")
@pytest.mark.supports("AP03-I30")
def test_absence_of_an_envelope_is_recorded_as_correct_not_as_unknown() -> None:
    """*"Absence is correct and is not a stripped authority"* (`EV-6`, `AP03-I30`)."""
    recorded = TwoValuedDetermined(
        slot=KnownAbsent(basis="role not activated on the branch taken")
    )
    assert recorded.slot.state is AbsenceState.KNOWN_ABSENT
    assert isinstance(recorded.slot, KnownAbsent)
    assert recorded.slot.basis == "role not activated on the branch taken"


@pytest.mark.traces("ST01-T3")
def test_a_determined_field_refuses_not_observed() -> None:
    """Case A records what GP-AUTO knows: it controlled the point of action.

    A refusal's root is either resolved or established absent. *Unobserved* is not one
    of the things a refusal can say about it, so the type does not offer it.
    """
    with pytest.raises(ValidationError):
        TwoValuedDetermined(slot=NotObserved())  # type: ignore[arg-type]


@pytest.mark.traces("ST01-T3")
def test_an_observable_field_refuses_known_absent() -> None:
    """An unaccounted mutation's producer is named or unknown — never *"none exists"*.

    AP-03 §12 forbids *"a claim that no producer exists merely because none is
    named"*, so the value that would record that claim is not constructible here
    (`VP11-4`).
    """
    with pytest.raises(ValidationError):
        TwoValuedObservable(slot=KnownAbsent(basis="no producer"))  # type: ignore[arg-type]

    named = TwoValuedObservable(
        slot=Present[WorkerActivationId](value=WorkerActivationId(value="a"))
    )
    unknown = TwoValuedObservable(slot=NotObserved())
    assert named.slot.state is AbsenceState.PRESENT
    assert unknown.slot.state is AbsenceState.NOT_OBSERVED


@pytest.mark.traces("ST01-D4")
@pytest.mark.supports("AP03-I15")
def test_applicability_is_two_valued_and_not_an_absence() -> None:
    """AP-03 §4.8.2 states applicability two-valued; observation does not enter it.

    A bounds value is authored and derived, never observed, so *not observed* must not
    be expressible for a dimension — otherwise an unobserved dimension could read as
    an inapplicable one, and `AP03-I15`'s *malformed, not wider* would lose its
    meaning.
    """
    assert [member.value for member in DimensionApplicability] == ["APPLICABLE", "INAPPLICABLE"]

    carried = RoleConditionalHolder(
        slot=Carried[FrozenFindingSetId](value=FrozenFindingSetId(value="s"))
    )
    inapplicable = RoleConditionalHolder(slot=NotApplicable())
    assert carried.slot.applicability is DimensionApplicability.APPLICABLE
    assert inapplicable.slot.applicability is DimensionApplicability.INAPPLICABLE

    with pytest.raises(ValidationError):
        RoleConditionalHolder(slot=NotObserved())  # type: ignore[arg-type]


@pytest.mark.traces("ST01-D4")
@pytest.mark.supports("AP03-I15")
def test_an_inapplicable_dimension_has_no_field_to_carry_a_value() -> None:
    """*"Malformed, not wider"* is closed by there being nowhere to put the value."""
    assert "value" not in NotApplicable.model_fields
    with pytest.raises(ValidationError) as caught:
        NotApplicable(value=FrozenFindingSetId(value="s"))  # type: ignore[call-arg]
    assert caught.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.traces("ST01-T3")
def test_absence_values_round_trip_through_the_json_path() -> None:
    """Each state survives encode and decode as itself."""
    for original in (
        ThreeValued(slot=Present[FrozenFindingSetId](value=FrozenFindingSetId(value="s"))),
        ThreeValued(slot=KnownAbsent(basis="established")),
        ThreeValued(slot=NotObserved()),
    ):
        assert ThreeValued.model_validate_json(original.model_dump_json()) == original
