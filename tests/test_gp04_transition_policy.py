"""GP-04 — invalid transitions are rejected by deterministic policy.

Design basis: design/GP-SPK-001-governance-kernel.md §13.1 requirement 6, §3, §4, §9.

The requirement is stated over the **table**, not over call sites. There are 9 ordered
pairs across 3 states; exactly 2 are legal (§3 rows `SPK1-1` and `SPK1-2`) and the other
7 refuse. Asserting that no edge names `ActorKind.LLM` is a property of the transition
graph itself, which is strictly stronger evidence than "no LLM was called here" -- the
latter is only ever true of the call sites that happen to exist today (§11, GK-INV-5).

The matrix is **derived from `list(ScopeState)`**, never typed out pair by pair, so a
fourth state added tomorrow enlarges the matrix instead of quietly escaping it. The
derived illegal set is then pinned against an explicit enumeration of the seven §3
categories, so derivation and intent have to agree.

Scope discipline. This file asserts deterministic policy only. It knows nothing about
approval records, digests, workflow identity, storage or DBOS: `requires_approval` is
checked as *metadata carried by a rule*, never as a statement about any approval that
might satisfy it. Those bindings belong to GP-05 onward.
"""

from __future__ import annotations

import ast
import dataclasses
import itertools
import sys
from enum import StrEnum
from pathlib import Path

import pytest

from gplanner import policy, states
from gplanner.errors import AuthorityDenied, GovernedPlannerError, IllegalTransition
from gplanner.policy import LEGAL_TRANSITIONS, Outcome, Resolution, TransitionRule
from gplanner.states import ActorKind, ScopeState

SRC = Path(__file__).resolve().parents[1] / "src" / "gplanner"

# --- The matrix, derived and then pinned -----------------------------------------

#: Every ordered pair over the *current* state enum. Derived, so a new state widens it.
ALL_PAIRS: tuple[tuple[ScopeState, ScopeState], ...] = tuple(
    itertools.product(list(ScopeState), list(ScopeState))
)

#: The two edges §3 declares legal, written out independently of `LEGAL_TRANSITIONS`.
EXPECTED_LEGAL_PAIRS: frozenset[tuple[ScopeState, ScopeState]] = frozenset(
    {
        (ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_REVIEW_PENDING),
        (ScopeState.SCOPE_REVIEW_PENDING, ScopeState.SCOPE_APPROVED),
    }
)

#: The seven §3 refusal categories, enumerated by name rather than by subtraction.
SELF_LOOPS: frozenset[tuple[ScopeState, ScopeState]] = frozenset(
    {
        (ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_DRAFTING),
        (ScopeState.SCOPE_REVIEW_PENDING, ScopeState.SCOPE_REVIEW_PENDING),
        (ScopeState.SCOPE_APPROVED, ScopeState.SCOPE_APPROVED),
    }
)
BACKWARD_EDGES: frozenset[tuple[ScopeState, ScopeState]] = frozenset(
    {
        (ScopeState.SCOPE_REVIEW_PENDING, ScopeState.SCOPE_DRAFTING),
        (ScopeState.SCOPE_APPROVED, ScopeState.SCOPE_REVIEW_PENDING),
    }
)
FORWARD_SKIP: tuple[ScopeState, ScopeState] = (
    ScopeState.SCOPE_DRAFTING,
    ScopeState.SCOPE_APPROVED,
)
BACKWARD_SKIP: tuple[ScopeState, ScopeState] = (
    ScopeState.SCOPE_APPROVED,
    ScopeState.SCOPE_DRAFTING,
)
EXPECTED_ILLEGAL_PAIRS: frozenset[tuple[ScopeState, ScopeState]] = (
    SELF_LOOPS | BACKWARD_EDGES | {FORWARD_SKIP, BACKWARD_SKIP}
)

#: The authority §3 names for each legal edge.
EXPECTED_AUTHORITY: dict[tuple[ScopeState, ScopeState], ActorKind] = {
    (ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_REVIEW_PENDING): ActorKind.SYSTEM,
    (ScopeState.SCOPE_REVIEW_PENDING, ScopeState.SCOPE_APPROVED): ActorKind.HUMAN,
}

ALL_ACTORS: tuple[ActorKind, ...] = tuple(ActorKind)

#: Every (legal edge, actor) combination in which the actor lacks that edge's authority.
WRONG_AUTHORITY_CASES: tuple[tuple[tuple[ScopeState, ScopeState], ActorKind], ...] = tuple(
    (pair, actor_kind)
    for pair in sorted(EXPECTED_LEGAL_PAIRS)
    for actor_kind in ALL_ACTORS
    if actor_kind is not EXPECTED_AUTHORITY[pair]
)


def outcome(
    from_state: ScopeState, to_state: ScopeState, actor_kind: ActorKind
) -> Outcome:
    return policy.resolve(from_state, to_state, actor_kind).outcome


def top_level_imports(module_name: str) -> set[str]:
    """Root module names imported by a production module, read from its source."""
    tree = ast.parse((SRC / f"{module_name}.py").read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            roots.add(node.module or "")
    return roots


# --- Section A: `states.py` is data only -----------------------------------------


def test_a_scope_state_has_exactly_the_three_spike_states() -> None:
    assert [member.name for member in ScopeState] == [
        "SCOPE_DRAFTING",
        "SCOPE_REVIEW_PENDING",
        "SCOPE_APPROVED",
    ]


def test_a_actor_kind_has_exactly_human_system_llm() -> None:
    assert [member.name for member in ActorKind] == ["HUMAN", "SYSTEM", "LLM"]


@pytest.mark.parametrize("enum_cls", [ScopeState, ActorKind])
def test_a_enum_member_values_equal_their_names(enum_cls: type[StrEnum]) -> None:
    # The wire form and the source form are the same token, so a state persisted by one
    # build is readable by the next without a translation table to drift.
    assert issubclass(enum_cls, StrEnum)
    assert all(member.value == member.name for member in enum_cls)


def test_a_states_module_declares_no_logic() -> None:
    """`states.py` holds data. A function there would be policy in the wrong module."""
    tree = ast.parse((SRC / "states.py").read_text(encoding="utf-8"))
    assert not [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    classes = [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
    assert classes == ["ScopeState", "ActorKind"]
    assert top_level_imports("states") <= {"__future__", "enum"}


# --- Section B: the declarative table --------------------------------------------


def test_b_legal_transitions_is_an_immutable_tuple_of_exactly_two_rules() -> None:
    assert isinstance(LEGAL_TRANSITIONS, tuple)
    assert len(LEGAL_TRANSITIONS) == 2


def test_b_legal_transitions_contains_exactly_the_two_frozen_edges() -> None:
    """The whole table, field by field, against §3 rows SPK1-1 and SPK1-2."""
    assert [dataclasses.astuple(rule) for rule in LEGAL_TRANSITIONS] == [
        (
            ScopeState.SCOPE_DRAFTING,
            ScopeState.SCOPE_REVIEW_PENDING,
            ActorKind.SYSTEM,
            False,
            "SPK1-1",
        ),
        (
            ScopeState.SCOPE_REVIEW_PENDING,
            ScopeState.SCOPE_APPROVED,
            ActorKind.HUMAN,
            True,
            "SPK1-2",
        ),
    ]


def test_b_declared_edges_are_exactly_the_two_expected_pairs() -> None:
    declared = {(rule.from_state, rule.to_state) for rule in LEGAL_TRANSITIONS}
    assert declared == EXPECTED_LEGAL_PAIRS
    assert len(declared) == len(LEGAL_TRANSITIONS)  # no edge declared twice


def test_b_design_row_coordinates_are_unique() -> None:
    rows = [rule.row for rule in LEGAL_TRANSITIONS]
    assert sorted(rows) == ["SPK1-1", "SPK1-2"]


def test_b_no_edge_names_actor_kind_llm() -> None:
    """GK-INV-5, asserted over the table rather than over today's call sites."""
    assert ActorKind.LLM not in {rule.authority for rule in LEGAL_TRANSITIONS}


def test_b_transition_rule_is_frozen() -> None:
    rule = LEGAL_TRANSITIONS[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.authority = ActorKind.LLM  # type: ignore[misc]


def test_b_resolution_is_frozen() -> None:
    verdict = policy.resolve(
        ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_REVIEW_PENDING, ActorKind.SYSTEM
    )
    assert isinstance(verdict, Resolution)
    with pytest.raises(dataclasses.FrozenInstanceError):
        verdict.outcome = Outcome.REFUSE_AUTHORITY  # type: ignore[misc]


def test_b_outcome_has_exactly_three_verdicts() -> None:
    assert [member.name for member in Outcome] == [
        "ALLOW",
        "REFUSE_NOT_IN_GRAPH",
        "REFUSE_AUTHORITY",
    ]


# --- Section C: the exhaustive 3x3 ordered matrix --------------------------------


def test_c_matrix_is_derived_from_the_state_enum() -> None:
    states_list = list(ScopeState)
    assert len(ALL_PAIRS) == len(states_list) ** 2 == 9
    assert len(set(ALL_PAIRS)) == 9


def test_c_exactly_two_of_nine_pairs_are_legal() -> None:
    legal = {pair for pair in ALL_PAIRS if pair in EXPECTED_LEGAL_PAIRS}
    assert len(legal) == 2
    assert len(set(ALL_PAIRS) - legal) == 7


def test_c_derived_illegal_set_matches_the_seven_named_categories() -> None:
    """Derivation and §3's enumeration must agree, or one of them is wrong."""
    derived = set(ALL_PAIRS) - set(EXPECTED_LEGAL_PAIRS)
    assert derived == set(EXPECTED_ILLEGAL_PAIRS)
    assert len(derived) == 7
    assert SELF_LOOPS <= derived and len(SELF_LOOPS) == 3
    assert BACKWARD_EDGES <= derived and len(BACKWARD_EDGES) == 2
    assert FORWARD_SKIP in derived
    assert BACKWARD_SKIP in derived


@pytest.mark.parametrize("pair", sorted(EXPECTED_ILLEGAL_PAIRS))
@pytest.mark.parametrize("actor_kind", ALL_ACTORS)
def test_c_every_illegal_pair_refuses_for_every_actor_kind(
    pair: tuple[ScopeState, ScopeState], actor_kind: ActorKind
) -> None:
    """An absent edge is absent for everyone: authority cannot conjure one."""
    assert outcome(pair[0], pair[1], actor_kind) is Outcome.REFUSE_NOT_IN_GRAPH


@pytest.mark.parametrize("pair,actor_kind", sorted(EXPECTED_AUTHORITY.items()))
def test_c_every_legal_pair_allows_under_its_own_authority(
    pair: tuple[ScopeState, ScopeState], actor_kind: ActorKind
) -> None:
    assert outcome(pair[0], pair[1], actor_kind) is Outcome.ALLOW


def test_c_full_matrix_outcome_census() -> None:
    """All 9 pairs x 3 actor kinds at once: 2 ALLOW, 21 not-in-graph, 4 authority."""
    verdicts = [
        outcome(frm, to, actor)
        for frm, to in ALL_PAIRS
        for actor in ALL_ACTORS
    ]
    assert len(verdicts) == 27
    assert verdicts.count(Outcome.ALLOW) == 2
    assert verdicts.count(Outcome.REFUSE_NOT_IN_GRAPH) == 21
    assert verdicts.count(Outcome.REFUSE_AUTHORITY) == 4


# --- Section D: authority ---------------------------------------------------------


@pytest.mark.parametrize("pair", sorted(EXPECTED_LEGAL_PAIRS))
@pytest.mark.parametrize("actor_kind", ALL_ACTORS)
def test_d_legal_edge_allows_only_its_declared_authority(
    pair: tuple[ScopeState, ScopeState], actor_kind: ActorKind
) -> None:
    expected = (
        Outcome.ALLOW
        if actor_kind is EXPECTED_AUTHORITY[pair]
        else Outcome.REFUSE_AUTHORITY
    )
    assert outcome(pair[0], pair[1], actor_kind) is expected


def test_d_system_cannot_approve_and_human_cannot_submit() -> None:
    """The two authorities are not interchangeable in either direction."""
    assert (
        outcome(
            ScopeState.SCOPE_REVIEW_PENDING,
            ScopeState.SCOPE_APPROVED,
            ActorKind.SYSTEM,
        )
        is Outcome.REFUSE_AUTHORITY
    )
    assert (
        outcome(
            ScopeState.SCOPE_DRAFTING,
            ScopeState.SCOPE_REVIEW_PENDING,
            ActorKind.HUMAN,
        )
        is Outcome.REFUSE_AUTHORITY
    )


@pytest.mark.parametrize("pair", sorted(set(ALL_PAIRS)))
def test_d_llm_authorizes_no_ordered_pair(pair: tuple[ScopeState, ScopeState]) -> None:
    """GK-INV-5 over every pair, legal or not -- not merely over the declared edges."""
    assert outcome(pair[0], pair[1], ActorKind.LLM) is not Outcome.ALLOW


def test_d_llm_is_refused_on_both_legal_edges_for_lacking_authority() -> None:
    """On a real edge the LLM refusal is specifically an authority refusal."""
    for pair in sorted(EXPECTED_LEGAL_PAIRS):
        assert outcome(pair[0], pair[1], ActorKind.LLM) is Outcome.REFUSE_AUTHORITY


# --- Section E: the raising wrapper ----------------------------------------------


@pytest.mark.parametrize("pair,actor_kind", sorted(EXPECTED_AUTHORITY.items()))
def test_e_wrapper_returns_the_declared_rule_for_an_authorized_edge(
    pair: tuple[ScopeState, ScopeState], actor_kind: ActorKind
) -> None:
    rule = policy.refuse_unless_allowed(pair[0], pair[1], actor_kind)
    assert isinstance(rule, TransitionRule)
    assert rule in LEGAL_TRANSITIONS
    assert (rule.from_state, rule.to_state) == pair
    assert rule.authority is actor_kind


def test_e_transition_metadata_preserves_requires_approval() -> None:
    """The flag travels with the edge; this stage asserts nothing about approvals."""
    submit = policy.refuse_unless_allowed(
        ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_REVIEW_PENDING, ActorKind.SYSTEM
    )
    approve = policy.refuse_unless_allowed(
        ScopeState.SCOPE_REVIEW_PENDING, ScopeState.SCOPE_APPROVED, ActorKind.HUMAN
    )
    assert submit.requires_approval is False
    assert approve.requires_approval is True
    assert (submit.row, approve.row) == ("SPK1-1", "SPK1-2")


def test_e_wrapper_returns_the_table_row_itself_not_a_copy() -> None:
    rule = policy.refuse_unless_allowed(
        ScopeState.SCOPE_REVIEW_PENDING, ScopeState.SCOPE_APPROVED, ActorKind.HUMAN
    )
    assert rule is LEGAL_TRANSITIONS[1]


@pytest.mark.parametrize("pair", sorted(EXPECTED_ILLEGAL_PAIRS))
@pytest.mark.parametrize("actor_kind", ALL_ACTORS)
def test_e_wrapper_raises_illegal_transition_for_every_illegal_pair(
    pair: tuple[ScopeState, ScopeState], actor_kind: ActorKind
) -> None:
    with pytest.raises(IllegalTransition) as excinfo:
        policy.refuse_unless_allowed(pair[0], pair[1], actor_kind)
    message = str(excinfo.value)
    assert pair[0].value in message and pair[1].value in message


def test_e_there_are_exactly_four_wrong_authority_cases() -> None:
    """2 legal edges x 3 actor kinds, less the 2 that hold the authority."""
    assert len(WRONG_AUTHORITY_CASES) == 4


@pytest.mark.parametrize("pair,actor_kind", WRONG_AUTHORITY_CASES)
def test_e_wrapper_raises_authority_denied_for_the_wrong_actor(
    pair: tuple[ScopeState, ScopeState], actor_kind: ActorKind
) -> None:
    with pytest.raises(AuthorityDenied) as excinfo:
        policy.refuse_unless_allowed(pair[0], pair[1], actor_kind)
    message = str(excinfo.value)
    assert EXPECTED_AUTHORITY[pair].value in message
    assert actor_kind.value in message


def test_e_absent_edge_outranks_wrong_authority() -> None:
    """A pair that is both absent and wrongly actored is refused as absent.

    Reporting `AuthorityDenied` there would imply the edge exists and only the actor
    was wrong, which would send an operator looking for the wrong fix.
    """
    with pytest.raises(IllegalTransition):
        policy.refuse_unless_allowed(
            ScopeState.SCOPE_APPROVED, ScopeState.SCOPE_APPROVED, ActorKind.LLM
        )


@pytest.mark.parametrize(
    "error_cls", [IllegalTransition, AuthorityDenied]
)
def test_e_both_refusals_are_governed_planner_errors(
    error_cls: type[GovernedPlannerError],
) -> None:
    assert issubclass(error_cls, GovernedPlannerError)


def test_e_wrapper_never_raises_for_the_two_authorized_edges() -> None:
    for pair, actor_kind in EXPECTED_AUTHORITY.items():
        policy.refuse_unless_allowed(pair[0], pair[1], actor_kind)


# --- Section F: purity, determinism, and module boundaries -----------------------


def test_f_resolve_is_deterministic_across_repeated_calls() -> None:
    for frm, to in ALL_PAIRS:
        for actor in ALL_ACTORS:
            first = policy.resolve(frm, to, actor)
            second = policy.resolve(frm, to, actor)
            assert first == second


def test_f_exercising_the_whole_matrix_does_not_mutate_the_table() -> None:
    before = tuple(LEGAL_TRANSITIONS)
    snapshot = [dataclasses.astuple(rule) for rule in LEGAL_TRANSITIONS]
    for frm, to in ALL_PAIRS:
        for actor in ALL_ACTORS:
            policy.resolve(frm, to, actor)
    assert policy.LEGAL_TRANSITIONS == before
    assert all(a is b for a, b in zip(policy.LEGAL_TRANSITIONS, before, strict=True))
    assert [dataclasses.astuple(rule) for rule in LEGAL_TRANSITIONS] == snapshot


def test_f_resolution_carries_the_row_only_when_an_edge_exists() -> None:
    allowed = policy.resolve(
        ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_REVIEW_PENDING, ActorKind.SYSTEM
    )
    denied = policy.resolve(
        ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_REVIEW_PENDING, ActorKind.LLM
    )
    absent = policy.resolve(
        ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_APPROVED, ActorKind.SYSTEM
    )
    assert allowed.row == "SPK1-1"
    assert denied.row == "SPK1-1"  # the edge exists; only the actor was wrong
    assert absent.row is None  # there is no row to cite
    assert all(verdict.reason for verdict in (allowed, denied, absent))


def test_f_policy_imports_no_later_stage_module_and_no_engine() -> None:
    """§4: legality is decidable with no I/O, no store, no engine, no LLM SDK."""
    roots = top_level_imports("policy")
    assert roots <= {
        "__future__",
        "dataclasses",
        "enum",
        "typing",
        "gplanner.states",
        "gplanner.errors",
        "gplanner.require",
    }, roots
    forbidden = {
        "dbos",
        "anthropic",
        "openai",
        "json",
        "sqlite3",
        "random",
        "time",
        "datetime",
        "gplanner.store",
        "gplanner.kernel",
        "gplanner.approvals",
        "gplanner.workflow",
        "gplanner.app",
    }
    assert not roots & forbidden


def test_f_importing_policy_does_not_pull_in_dbos_or_an_llm_sdk() -> None:
    assert states is not None and policy is not None
    assert "dbos" not in sys.modules
    assert not {"anthropic", "openai"} & sys.modules.keys()


def test_f_policy_declares_both_frozen_guard_ids() -> None:
    """D-2 guard IDs are frozen now so GP-SPK-002 ports the harness without edits."""
    source = (SRC / "policy.py").read_text(encoding="utf-8")
    for guard in ("guard:gp_transition_legal", "guard:gp_transition_authority"):
        assert source.count(f"# {guard}") == 1


# --- Section G: recorded behaviour, asserted rather than assumed -----------------


def test_g_strenum_string_spellings_resolve_identically() -> None:
    """Recorded, not endorsed: `ScopeState` is a `StrEnum`, so `"SCOPE_DRAFTING"` and
    `ScopeState.SCOPE_DRAFTING` hash and compare equal and therefore index the same
    edge. The policy layer performs no runtime type check; callers are constrained by
    `mypy --strict` and, from GP-05, by validated models. Asserted here so the property
    is a stated consequence of the frozen `StrEnum` choice rather than a surprise.
    """
    typed = policy.resolve(
        ScopeState.SCOPE_DRAFTING, ScopeState.SCOPE_REVIEW_PENDING, ActorKind.SYSTEM
    )
    untyped = policy.resolve(
        "SCOPE_DRAFTING",  # type: ignore[arg-type]
        "SCOPE_REVIEW_PENDING",  # type: ignore[arg-type]
        "SYSTEM",  # type: ignore[arg-type]
    )
    assert typed == untyped


def test_g_an_unknown_state_token_is_refused_as_absent_from_the_graph() -> None:
    """A value outside the enum names no edge, so it refuses rather than resolving."""
    assert (
        policy.resolve(
            "SCOPE_REJECTED",  # type: ignore[arg-type]
            ScopeState.SCOPE_APPROVED,
            ActorKind.HUMAN,
        ).outcome
        is Outcome.REFUSE_NOT_IN_GRAPH
    )
