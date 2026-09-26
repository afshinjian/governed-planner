"""Mutation evidence for `GP-AUTO-ST-04`'s input-selection guards — per mutant, killer named.

Design basis: AP-11 §8 (`MU11-1`…`MU11-7`), §13 (`EV11-6`); AP-11 ST-04
derivation-ownership amendment §2, Mutation cell: *"each input-selection guard in the
derivations and portions ST-04 implements, where a wrong input would still produce a
plausible value. No ST-04 mutation obligation attaches to `DV-9`, `DV-10`, the
`RA-00`…`RA-09` evaluation, or a `DV-11` comparator"* (`DO11-4`, `DO11-6`).

Each parametrization is one mutant: the registry names the fragment replaced on a line
carrying `# guard:ga_derivation_input` and the one `test_ga21` case that must kill it; the
assertion is that it **was** killed and that its control — the same substitution with no
mutation — **was not**. The harness is `mutation.py`: test code, no install (`PG11-2`). No
score, percentage or completeness claim is made (`MU11-2a`).
"""

from __future__ import annotations

import ast

import pytest

import mutation
from gpauto import derivations
from test_ga21_st04_derivations import Remediated

GPAUTO_STAGE = "GP-AUTO-ST-04"

ST04 = mutation.ST04_MUTANTS


@pytest.mark.traces("ST04-M1", "DO11-1", "DO11-2")
@pytest.mark.parametrize("mutant", ST04, ids=[m.identifier for m in ST04])
def test_each_derivation_input_selection_mutant_is_killed(mutant: mutation.LineMutant) -> None:
    """`ga_derivation_input`: the mutant is detected by its named test; its control is not."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST04-M1")
def test_every_tagged_input_selection_line_carries_at_least_one_mutant() -> None:
    """`MU11-3`: the guard is fixed in source where it is written, every tagged line is
    mutated, every mutant's fragment sits on exactly one tagged line, a line carries a
    second mutant only when that one changes a keyed selection's key, and ST-04 adds this
    guard and no other."""
    source = mutation.source_path(derivations).read_text(encoding="utf-8")
    tagged = [line for line in source.splitlines() if "# guard:ga_derivation_input" in line]
    keyed = {i for ids in mutation.ST04_KEYED_SELECTIONS.values() for i in ids}
    for line in tagged:
        on_line = [m for m in ST04 if m.original in line]
        assert on_line, line
        assert len([m for m in on_line if m.identifier not in keyed]) <= 1, line
        assert len([m for m in on_line if m.identifier in keyed]) <= 1, line
    assert sum(1 for line in tagged for m in ST04 if m.original in line) == len(ST04)
    for mutant in ST04:
        assert mutant.guard == "ga_derivation_input"
        assert mutation.mutated_source(mutant) != mutation.mutated_source(mutant, control=True)
    tags = mutation.guard_tags()
    assert all(location.startswith("derivations.py:") for location in tags["ga_derivation_input"])
    assert {g for g, guard in mutation.GUARDS.items() if guard.module is derivations} == {
        "ga_derivation_input"
    }


def _predicates(tree: ast.Module) -> list[tuple[str, int, str]]:
    """Every comprehension-filter conjunct and every `if` test in the module, with the
    function it is in and the line it starts on."""
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    found: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        tests: list[ast.expr] = []
        if isinstance(node, ast.comprehension):
            for condition in node.ifs:
                if isinstance(condition, ast.BoolOp) and isinstance(condition.op, ast.And):
                    tests.extend(condition.values)
                else:
                    tests.append(condition)
        elif isinstance(node, ast.If):
            tests.append(node.test)
        for test in tests:
            inner = max(
                (f for f in functions if f.lineno <= test.lineno <= (f.end_lineno or 0)),
                key=lambda f: f.lineno,
            )
            found.append((inner.name, test.lineno, ast.unparse(test)))
    return found


@pytest.mark.traces("ST04-M1", "DO11-1", "DO11-2")
def test_every_selection_predicate_is_mutated_or_inventoried_with_its_reason() -> None:
    """`ST04-IMPL-R02`: the input-selection inventory is complete by construction. Every
    comprehension filter and `if` test in `derivations.py` is either on a
    `ga_derivation_input` line — and so carries a mutant — or listed, with the reason it
    carries none, in `ST04_UNMUTATED_PREDICATES`; nothing is both, and nothing listed is
    stale. The two selections the review named — the assessed activation and the named
    obligation and its set — are tagged."""
    source = mutation.source_path(derivations).read_text(encoding="utf-8")
    lines = source.splitlines()
    predicates = _predicates(ast.parse(source))
    listed = mutation.ST04_UNMUTATED_PREDICATES
    tagged = {
        (function, text)
        for function, line, text in predicates
        if "# guard:ga_derivation_input" in lines[line - 1]
    }
    untagged = {(function, text) for function, _, text in predicates} - tagged
    assert untagged == set(listed), (untagged - set(listed), set(listed) - untagged)
    assert not tagged & set(listed)
    assert all(reason.strip() for reason in listed.values())
    for named in (
        ("derive_prior_authorized_state", "a.identity == assessed"),
        ("_obligation_force", "o.identity == obligation"),
        ("_obligation_force", "s.identity == obligation.parent_frozen_set"),
    ):
        assert named in tagged, named


@pytest.mark.traces("ST04-M1", "DO11-4", "DO11-6")
def test_no_st04_mutant_targets_a_capability_st04_does_not_own() -> None:
    """No mutant touches `DV-9`, `DV-10`, an `RA-00`…`RA-09` evaluation or a comparator —
    none exists in the module, and none is mutated elsewhere under ST-04's name."""
    for mutant in ST04:
        text = f"{mutant.original} {mutant.replacement} {mutant.description}".lower()
        for word in ("package", "mirror", "equivalen", "compare", "ra-0", "binding"):
            assert word not in text, (mutant.identifier, word)
    assert all(m.killer.startswith(mutation.DERIVATION_TESTS) for m in ST04)


def _keyed_accesses(tree: ast.Module) -> list[tuple[str, str]]:
    """Every keyed access in every function body — each subscript, and each `.get` or
    `.setdefault` call — with the function it is in. Annotations are types, not accesses,
    and are skipped."""
    found: list[tuple[str, str]] = []
    for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        annotations = {
            id(inner)
            for node in ast.walk(function)
            if isinstance(node, ast.AnnAssign)
            for inner in ast.walk(node.annotation)
        }
        for statement in function.body:
            for node in ast.walk(statement):
                if id(node) in annotations:
                    continue
                keyed_call = (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("get", "setdefault")
                )
                if isinstance(node, ast.Subscript) or keyed_call:
                    found.append((function.name, ast.unparse(node)))
    return found


@pytest.mark.traces("ST04-M1", "DO11-1", "DO11-2")
def test_every_keyed_access_is_a_mutated_selection_or_inventoried_with_its_class() -> None:
    """`ST04-IMPL-R02`: a keyed lookup is an input selection too. Every keyed access in
    `derivations.py` is either a keyed selection — on a `ga_derivation_input` line, with a
    mutant that replaces its key and keeps the rest — or listed, with its occurrence count,
    its class and its reason, in `ST04_UNQUALIFIED_KEYED_ACCESSES`; nothing is both, and
    nothing listed is stale. The two `DV-1` lookups the closure verifier named — the
    activation's envelope and the envelope's stratum — are keyed selections."""
    source = mutation.source_path(derivations).read_text(encoding="utf-8")
    lines = source.splitlines()
    counted: dict[tuple[str, str], int] = {}
    for access in _keyed_accesses(ast.parse(source)):
        counted[access] = counted.get(access, 0) + 1
    selections = mutation.ST04_KEYED_SELECTIONS
    unqualified = mutation.ST04_UNQUALIFIED_KEYED_ACCESSES
    assert set(counted) == set(selections) | set(unqualified), (
        set(counted) - set(selections) - set(unqualified),
        (set(selections) | set(unqualified)) - set(counted),
    )
    assert not set(selections) & set(unqualified)
    for access, (count, classification, reason) in unqualified.items():
        assert counted[access] == count, access
        assert classification in (
            mutation.NON_SELECTION,
            mutation.SINGLE_LAWFUL_VALUE,
            mutation.FAIL_CLOSED,
        ), access
        assert reason.strip(), access
    by_identifier = {m.identifier: m for m in ST04}
    for (function, text), identifiers in selections.items():
        assert counted[(function, text)] == 1, text
        (line,) = [line for line in lines if text in line]
        assert "# guard:ga_derivation_input" in line, text
        assert identifiers, text
        for identifier in identifiers:
            mutant = by_identifier[identifier]
            assert text in mutant.original, identifier
            assert text not in mutant.replacement, identifier
            key = text.split("[", 1)[0].split(".get(", 1)[0]
            assert mutant.replacement.startswith(key), identifier
    for named in (
        ("_stratum", "envelopes.get(activation.envelope)"),
        ("_stratum", "strata[envelope.predecessor_entry]"),
    ):
        assert named in selections, named


KEYED_DV1 = (
    "DI-47-another-envelope-keyed",
    "DI-48-another-stratum-keyed",
    "DI-49-another-effects-judgement-keyed",
)


@pytest.mark.traces("ST04-M1", "DV-1")
@pytest.mark.parametrize("identifier", KEYED_DV1)
def test_each_dv1_keyed_mutant_selects_a_valid_record_and_stays_determinate(
    identifier: str,
) -> None:
    """The Mutation cell's criterion, shown for each `DV-1` keyed mutant rather than
    assumed: over the valid records of one epoch, the wrong key selects another valid
    record, and `DV-1` is still a determinate `PriorAuthorizedState` — a plausible value,
    not a crash and not indeterminacy — that differs from the correct one. The envelope
    and stratum mutants give the one the closure verifier reported: three terms become
    none."""
    (mutant,) = [m for m in ST04 if m.identifier == identifier]
    a = Remediated()
    records = a.snapshot()
    correct = derivations.derive_prior_authorized_state(records, a.closure.identity)
    assert isinstance(correct, derivations.PriorAuthorizedState)
    assert len(correct.terms) == 3
    with pytest.MonkeyPatch.context() as monkeypatch:
        with mutation._line_substituted(mutant, monkeypatch, control=False):
            wrong = derivations.derive_prior_authorized_state(records, a.closure.identity)
    assert isinstance(wrong, derivations.PriorAuthorizedState), wrong
    assert wrong != correct
    if identifier != "DI-49-another-effects-judgement-keyed":
        assert wrong.terms == ()
    else:
        assert [t.activation for t in wrong.terms] == [t.activation for t in correct.terms]
