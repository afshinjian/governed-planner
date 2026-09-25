"""Mutation evidence for `GP-AUTO-ST-03`'s guards — per guard, per mutant, killer named.

Design basis: AP-11 §8 (`MU11-1`…`MU11-7`), §13 (`EV11-6`), §16 (`GP-AUTO-ST-03` Mutation
row: *"write-class enforcement; referential-integrity enforcement; stale-schema refusal"*),
as kept by the ST-03 amendment §11.1 (*"The `IV11-*` value sets introduce **no** `MU11-4`
guard"*); the follow-on amendment's `MC-17`(ii) and `RO7A-5` constraints.

Each parametrization is one mutant: the registry names the mutation applied and the one
test that must kill it; the assertion is that it **was** killed and that its control —
the same substitution with no mutation — **was not**. The harness is `mutation.py`: test
code, no install (`PG11-2`). No score, percentage or completeness claim is made
(`MU11-2a`); a kill establishes only that that mutation was detected by that test.
"""

from __future__ import annotations

import pytest

import mutation

GPAUTO_STAGE = "GP-AUTO-ST-03"


def _ids(mutants: tuple[mutation.LineMutant, ...]) -> list[str]:
    return [f"{mutant.guard}/{mutant.identifier}" for mutant in mutants]


def _of(guard: str) -> tuple[mutation.LineMutant, ...]:
    return tuple(m for m in mutation.ST03_MUTANTS if m.guard == guard)


WRITE_CLASS = _of("ga_store_write_class")
REFERENCES = _of("ga_store_referential_integrity")
STALE_SCHEMA = _of("ga_store_stale_schema")
KEYS = _of("ga_store_keys")


@pytest.mark.traces("ST03-M1", "AP11-I70")
@pytest.mark.parametrize("mutant", WRITE_CLASS, ids=_ids(WRITE_CLASS))
def test_each_write_class_mutant_is_killed(mutant: mutation.LineMutant) -> None:
    """`ga_store_write_class`: create-only triggers and the coordination-only surface."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST03-M2", "AP03-I35")
@pytest.mark.parametrize("mutant", REFERENCES, ids=_ids(REFERENCES))
def test_each_referential_integrity_mutant_is_killed(mutant: mutation.LineMutant) -> None:
    """`ga_store_referential_integrity`: foreign keys, instance rule, context pair, members."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST03-M3", "AP11-I69")
@pytest.mark.parametrize("mutant", STALE_SCHEMA, ids=_ids(STALE_SCHEMA))
def test_each_stale_schema_mutant_is_killed(mutant: mutation.LineMutant) -> None:
    """`ga_store_stale_schema`: the version and structure refusals."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST03-M4", "AP11-I73")
@pytest.mark.parametrize("mutant", KEYS, ids=_ids(KEYS))
def test_each_key_and_binding_mutant_is_killed(mutant: mutation.LineMutant) -> None:
    """`ga_store_keys`: `MC-17`(i)/(ii), the `RO7A-5` bindings, and each `SRB11-8` key."""
    assert mutation.run(mutant) == mutation.KILLED, mutant.description
    assert mutation.run(mutant, control=True) == mutation.SURVIVED, mutant.identifier


@pytest.mark.traces("ST03-M1", "ST03-M2", "ST03-M3", "ST03-M4")
def test_the_st03_guard_set_is_the_contracts_and_every_guard_is_mutated() -> None:
    """`MU11-2b`, `MU11-3`: the three contract guard classes and the key guard, each fixed
    in source where it is written, each with at least one mutant, each guarantee a row of
    the frozen inventory — and every mutant's fragment sits on a line carrying its guard."""
    guards = {m.guard for m in mutation.ST03_MUTANTS}
    assert guards == {
        "ga_store_write_class",
        "ga_store_referential_integrity",
        "ga_store_stale_schema",
        "ga_store_keys",
    }
    tags = mutation.guard_tags()
    for guard in guards:
        assert tags[guard], guard
    for mutant in mutation.ST03_MUTANTS:
        assert mutation.mutated_source(mutant) != mutation.mutated_source(mutant, control=True)
