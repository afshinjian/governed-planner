"""GP-01 — `ScopeSpec` is a validated Pydantic model.

Design basis: design/GP-SPK-001-governance-kernel.md §13.1 requirement 1, §4, §6.

Two sections, kept apart deliberately:

* **Section 1 is GP-01 proper** — the spike requirement. It asserts only `ScopeSpec`.
* **Section 2 is the ST-2 foundational contract** — the shape of the error hierarchy
  and the behaviour of `require()`. It establishes the utilities this stage is
  authorized to add and asserts **no later-stage semantics**: nothing here touches
  canonicalization, transitions, approvals, replay, storage or DBOS. Those belong to
  the stages that implement them.

`ScopeSpec` is content only. What it *lacks* is the architectural property: no digest,
no workflow id, no state, no timestamp, no approval data, no derived identity field.
Identity is a pure function of content, so the model contains nothing about itself —
which is what removes any need for a field-exclusion list when it is later hashed.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gplanner import errors
from gplanner.artifacts import ScopeSpec
from gplanner.errors import (
    ApprovalBindingError,
    GovernedPlannerError,
    StaleApproval,
)
from gplanner.require import require

VALID = {
    "title": "Governance kernel feasibility",
    "problem_statement": "Prove the authority model without any LLM in the loop.",
    "in_scope": ("scope drafting", "human approval"),
    "out_of_scope": ("signing",),
    "acceptance_criteria": ("an approval binds exactly one digest",),
}


def spec(**overrides: object) -> ScopeSpec:
    return ScopeSpec(**{**VALID, **overrides})  # type: ignore[arg-type]


def first_error(**overrides: object) -> str:
    """The pydantic error *type* for a single-fault construction."""
    with pytest.raises(ValidationError) as excinfo:
        spec(**overrides)
    return str(excinfo.value.errors()[0]["type"])


# --- Section 1: GP-01 — ScopeSpec ------------------------------------------------


def test_a_correct_scope_spec_validates() -> None:
    model = spec()
    assert model.title == VALID["title"]
    assert model.acceptance_criteria == VALID["acceptance_criteria"]
    assert model.assumptions == (), "assumptions defaults to empty, not None"


def test_an_empty_acceptance_criteria_is_rejected() -> None:
    """A scope nobody can judge complete is not a scope."""
    assert first_error(acceptance_criteria=()) == "too_short"


def test_an_extra_field_is_rejected() -> None:
    """Undeclared content must never be accepted and then silently dropped."""
    assert first_error(unexpected_field="x") == "extra_forbidden"


def test_a_wrong_field_type_is_rejected() -> None:
    assert first_error(title=5) == "string_type"
    assert first_error(problem_statement=None) == "string_type"


def test_a_non_string_tuple_member_is_rejected() -> None:
    """Strictness reaches inside the sequence, not just at its boundary."""
    with pytest.raises(ValidationError) as excinfo:
        spec(in_scope=("valid", 5))
    error = excinfo.value.errors()[0]
    assert error["type"] == "string_type"
    assert error["loc"] == ("in_scope", 1)


def test_an_empty_title_is_rejected() -> None:
    assert first_error(title="") == "string_too_short"
    assert first_error(problem_statement="") == "string_too_short"


def test_a_scope_spec_is_frozen() -> None:
    model = spec()
    with pytest.raises(ValidationError) as excinfo:
        model.title = "mutated"
    assert excinfo.value.errors()[0]["type"] == "frozen_instance"


def test_tuple_fields_stay_tuples_under_direct_construction() -> None:
    """Immutable sequences in, immutable sequences out -- no silent conversion."""
    model = spec()
    assert type(model.in_scope) is tuple
    assert type(model.out_of_scope) is tuple
    assert type(model.acceptance_criteria) is tuple
    assert type(model.assumptions) is tuple


def test_a_list_is_rejected_for_a_tuple_field() -> None:
    """`strict=True` refuses the coercion.

    This is the behaviour that forces every JSON ingestion through
    `model_validate_json` rather than `json.loads` + `model_validate` (design §7).
    Pinning it here means a later relaxation of strictness breaks loudly.
    """
    assert first_error(in_scope=["a list", "not a tuple"]) == "tuple_type"


def test_the_schema_version_is_exactly_the_design_value() -> None:
    assert spec().schema_version == "gplanner.scope/v1"
    assert first_error(schema_version="gplanner.scope/v2") == "literal_error"


def test_sequence_order_is_significant_and_never_sorted() -> None:
    """Sorting would silently merge semantically different specs.

    Asserted before anything hashes a `ScopeSpec`, because once a digest depends on
    field order, a normalization added later is a silent identity change.
    """
    forward = spec(in_scope=("first", "second"))
    reversed_ = spec(in_scope=("second", "first"))
    assert forward.in_scope == ("first", "second")
    assert reversed_.in_scope == ("second", "first")
    assert forward != reversed_


def test_a_scope_spec_carries_no_identity_or_lifecycle_fields() -> None:
    """The architectural constraint is what the model does NOT have (design §4)."""
    forbidden = {
        "digest",
        "workflow_id",
        "state",
        "created_at",
        "updated_at",
        "timestamp",
        "approval",
        "approved_by",
    }
    assert forbidden.isdisjoint(ScopeSpec.model_fields)


# --- Section 2: ST-2 foundational contract ---------------------------------------
# Shape and behaviour only. No later-stage semantics are implemented or asserted.

ERROR_CLASSES = sorted(
    (
        name
        for name, obj in vars(errors).items()
        if isinstance(obj, type)
        and issubclass(obj, BaseException)
        and obj is not GovernedPlannerError
    ),
)


def test_the_error_hierarchy_has_a_single_root() -> None:
    assert issubclass(GovernedPlannerError, Exception)


@pytest.mark.parametrize("name", ERROR_CLASSES)
def test_every_error_descends_from_the_root(name: str) -> None:
    """Parametrized over the module's own exports, so a stray class cannot slip in."""
    assert issubclass(getattr(errors, name), GovernedPlannerError)


def test_stale_approval_is_a_kind_of_approval_binding_error() -> None:
    """The one nested relationship in the hierarchy."""
    assert issubclass(StaleApproval, ApprovalBindingError)
    assert not issubclass(ApprovalBindingError, StaleApproval)


def test_require_is_a_no_op_when_the_condition_holds() -> None:
    require(True, "never raised")  # must not raise


def test_require_raises_the_requested_error_with_the_supplied_reason() -> None:
    with pytest.raises(StaleApproval) as excinfo:
        require(False, "digest does not match the case", error=StaleApproval)
    assert str(excinfo.value) == "digest does not match the case"


def test_require_defaults_to_the_root_error() -> None:
    with pytest.raises(GovernedPlannerError):
        require(False, "no error class supplied")
