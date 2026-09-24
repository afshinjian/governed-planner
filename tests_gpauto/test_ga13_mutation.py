"""Mutation evidence for `GP-AUTO-ST-02`'s two named guards — per guard, per mutant.

Design basis: AP-11 §8 (`MU11-1`, `MU11-2a`, `MU11-2b`, `MU11-3`, `MU11-5`, `MU11-6`,
`MU11-7`), §13 (`EV11-1`(c), `EV11-6`), §16 (`GP-AUTO-ST-02` mutation row).

Each parametrization below is one mutant: its test id names the guard identifier and
the mutant, the registry names the mutation applied and the one test that must kill
it, and the assertion is that it **was** killed while its control **was not**. The
harness is `mutation.py`, which is test code and installs nothing (`PG11-2`).

A surviving mutant would be a finding about the suite, and the disposition `MU11-6`
requires is a missing negative test — never a weakened mutant or an excluded guard.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import mutation
import traceability
from gate_scope import REPOSITORY_ROOT

GPAUTO_STAGE = "GP-AUTO-ST-02"


def _node_ids(mutants: tuple[mutation.Mutant, ...]) -> list[str]:
    return [f"{mutant.guard}/{mutant.identifier}" for mutant in mutants]


EQUIVALENCE_MUTANTS = tuple(m for m in mutation.MUTANTS if m.guard == "ga_equivalence_compare")
DECODE_MUTANTS = tuple(m for m in mutation.MUTANTS if m.guard == "ga_codec_decode")


@pytest.mark.traces("ST02-M1", "EQ-0", "EQ-4", "AP03-I04")
@pytest.mark.parametrize("mutant", EQUIVALENCE_MUTANTS, ids=_node_ids(EQUIVALENCE_MUTANTS))
def test_each_equivalence_guard_mutant_is_killed_by_its_named_test(
    mutant: mutation.Mutant,
) -> None:
    """`ga_equivalence_compare`: line mutants, each killed and each control spared."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST02-M2", "DC-1", "DC-3")
@pytest.mark.parametrize("mutant", DECODE_MUTANTS, ids=_node_ids(DECODE_MUTANTS))
def test_each_decode_guard_schema_mutant_is_killed_by_its_named_test(
    mutant: mutation.Mutant,
) -> None:
    """`ga_codec_decode`: **schema** mutants (`MU11-5`), each killed, each control spared."""
    assert isinstance(mutant, mutation.SchemaMutant)
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST02-M1", "ST02-M2")
@pytest.mark.parametrize(
    "mutant",
    [EQUIVALENCE_MUTANTS[0], DECODE_MUTANTS[0]],
    ids=_node_ids((EQUIVALENCE_MUTANTS[0], DECODE_MUTANTS[0])),
)
def test_the_harness_reports_a_survivor_when_the_test_does_not_exercise_the_guard(
    mutant: mutation.Mutant,
) -> None:
    """`KILLED` is an observation, not a constant: a mutant run against a test that
    never reaches the guard survives, and the harness says so (`MU11-6`, `EV11-6`)."""
    from dataclasses import replace

    unrelated = (
        "tests_gpauto/test_ga10_content_identity.py::test_identity_names_bytes_not_denotation"
    )
    assert mutation.run(replace(mutant, killer=unrelated)) == mutation.SURVIVED


@pytest.mark.traces("ST02-M1", "ST02-M2")
def test_guard_identifiers_are_fixed_in_source_and_match_the_registry() -> None:
    """`MU11-3`: identity fixed where the guard is written, so a harness ports later
    without touching source. Every tag in the package is registered and every
    registered guard is tagged — in the module the registry says it lives in."""
    tags = mutation.guard_tags()
    assert set(tags) == set(mutation.GUARDS)
    for identifier, guard in mutation.GUARDS.items():
        module_file = mutation.source_path(guard.module).name
        assert tags[identifier], identifier
        assert all(location.startswith(f"{module_file}:") for location in tags[identifier])


@pytest.mark.traces("ST02-M1", "ST02-M2")
def test_the_decode_guard_is_model_enforced_and_its_lines_check_nothing() -> None:
    """`MU11-5`: each tagged decode line is a single `model_validate_json` call.

    That is what makes the guard model-enforced: the line performs no check of its own,
    so deleting it would remove decoding rather than weaken a refusal — and the only
    meaningful mutation is to the schema, which is what every decode mutant is.
    """
    source = mutation.source_path(mutation.GUARDS["ga_codec_decode"].module).read_text("utf-8")
    tagged = [line for line in source.splitlines() if "# guard:ga_codec_decode" in line]
    assert len(tagged) == 3
    assert all(".model_validate_json(" in line for line in tagged)
    assert all(m.guard == "ga_codec_decode" for m in DECODE_MUTANTS)
    assert all(isinstance(m, mutation.SchemaMutant) for m in DECODE_MUTANTS)
    assert all(isinstance(m, mutation.LineMutant) for m in EQUIVALENCE_MUTANTS)


@pytest.mark.traces("ST02-M1", "ST02-M2")
def test_every_guard_is_tied_to_frozen_guarantees_in_the_traceability_inventory() -> None:
    """`MU11-2b`: membership is auditable against frozen text, not asserted.

    Every guarantee a guard names is an element of the matrix's inventory — parsed from
    the frozen artifacts — so a guard with no frozen guarantee behind it would fail here.
    """
    inventory = traceability.inventory()
    for guard in mutation.GUARDS.values():
        assert guard.guarantees, guard.identifier
        assert set(guard.guarantees) <= set(inventory), guard.identifier


@pytest.mark.traces("ST02-M1", "ST02-M2")
def test_every_mutant_names_one_killing_test_that_exists_in_the_corpus() -> None:
    """`MU11-7`: evidence names the test that killed each mutant — so it must exist."""
    existing: set[str] = set()
    for path in sorted(Path(__file__).parent.glob("test_*.py")):
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.FunctionDef):
                existing.add(f"{relative}::{node.name}")
    identifiers = [mutant.identifier for mutant in mutation.MUTANTS]
    assert len(identifiers) == len(set(identifiers))
    for mutant in mutation.MUTANTS:
        assert mutant.killer in existing, mutant.identifier
        assert mutant.guard in mutation.GUARDS, mutant.identifier
    assert EQUIVALENCE_MUTANTS and DECODE_MUTANTS
