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


@pytest.mark.traces("ST03-M2", "ST03-M4", "RC-13", "RC-35", "RC-36")
@pytest.mark.parametrize("mutant", mutation.correction_ddl_mutants(), ids=lambda m: m.identifier)
@pytest.mark.traces("SC01-V14", "SC03-V13", "SP6-V17")
def test_st03c1_each_schema_mutant_is_killed_with_surviving_control(
    mutant: mutation.CorrectionDDLMutant,
) -> None:
    import sqlite3

    from gpauto import store_schema
    from test_ga17_st03_store import assert_v4_schema

    for control in (True, False):
        statements = store_schema.schema_statements(store_schema.build_catalogue())
        assert statements.count(mutant.statement) == 1
        connection = sqlite3.connect(":memory:")
        try:
            for statement in statements:
                ddl = statement if control or statement != mutant.statement else mutant.replacement
                if ddl:
                    connection.execute(ddl)
            connection.execute("PRAGMA user_version = 4")
            if control:
                assert_v4_schema(connection)
            else:
                with pytest.raises(AssertionError):
                    assert_v4_schema(connection)
        finally:
            connection.close()


@pytest.mark.traces("ST03-M2", "RC-13")
@pytest.mark.parametrize("identifier", ["text-length-rejects-nul", "split-context-pair"])
@pytest.mark.traces("SC03-V13")
def test_st03c1_semantic_mutants_are_killed_by_behavior(identifier: str) -> None:
    import sqlite3

    import test_ga17_st03_store as evidence
    from gpauto import store_schema

    mutant = next(m for m in mutation.correction_ddl_mutants() if m.identifier == identifier)
    original = store_schema.schema_statements
    killer = getattr(evidence, mutant.killer)
    killer()  # surviving control

    def changed(catalogue: store_schema.Catalogue) -> tuple[str, ...]:
        return tuple(
            mutant.replacement if s == mutant.statement else s for s in original(catalogue)
        )

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(store_schema, "schema_statements", changed)
        with pytest.raises((AssertionError, pytest.fail.Exception, sqlite3.IntegrityError)):
            killer()


@pytest.mark.traces("SP6-V17", "RC-18")
def test_st06pc1_the_v3_check_list_mutant_is_also_killed_by_behavior() -> None:
    """SP6-V17: the RC-18 mutant restoring version 3's three-value `E-16` list is killed
    by the SP6-V10 store test as well as by the content oracle — an envelope carrying
    the declared side-effect class is refused under it. The control survives."""
    import test_ga17_st03_store as evidence
    from gpauto import store_schema

    mutant = next(
        m for m in mutation.correction_ddl_mutants() if m.identifier == "rc18-e16-check-v3-list"
    )
    killer = evidence.test_st06pc1_an_envelope_carrying_the_side_effect_class_stores_and_reads_back
    original = store_schema.schema_statements
    killer()  # surviving control

    def changed(catalogue: store_schema.Catalogue) -> tuple[str, ...]:
        return tuple(
            mutant.replacement if s == mutant.statement else s for s in original(catalogue)
        )

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(store_schema, "schema_statements", changed)
        with pytest.raises(pytest.fail.Exception, match="side-effect class was refused"):
            killer()


@pytest.mark.traces("SP6-V17", "AP11-I69")
def test_st06pc1_the_rc18_correction_mutants_exist_and_stale_schema_guards_hold_at_4() -> None:
    """SP6-V17: exactly the two RC-18 correction mutants are generated, under the ST03C-1
    label precedent (no new guard), and the `ga_store_stale_schema` line mutants are run
    against version 4 — by the parametrized test above, whose killer pins version 4."""
    from gpauto import store_schema

    rc18 = [m for m in mutation.correction_ddl_mutants() if m.identifier.startswith("rc18-")]
    assert [m.identifier for m in rc18] == ["rc18-e16-check-v3-list", "rc18-e16-check-deleted"]
    assert {m.guard for m in rc18} == {"ga_store_referential_integrity"}
    assert {m.killer for m in rc18} == {"test_st03c1_schema_content_before_digest"}
    assert store_schema.STORAGE_VERSION == 4
    assert {m.identifier for m in STALE_SCHEMA} >= {
        "SS-01-version-unchecked",
        "SS-03-refusal-ignored",
    }


@pytest.mark.traces("ST03-M2", "ST01-N7")
@pytest.mark.parametrize(
    "change",
    [
        *(
            f"literal:{name}:kind"
            for name in (
                "AuthorizingDecision",
                "DisputeResolutionDecision",
                "ObligationExtinguishingDecision",
                "ObligationChangeDecision",
                "RevocationDecision",
                "RefusalResolutionDecision",
                "StageOutcomeDecision",
                "ExceptionalRecoveryDecision",
            )
        ),
        *(
            f"optional:{name}:corrects"
            for name in (
                "AuthorizingDecision",
                "DisputeResolutionDecision",
                "ObligationExtinguishingDecision",
                "RevocationDecision",
                "RefusalResolutionDecision",
                "StageOutcomeDecision",
                "ExceptionalRecoveryDecision",
            )
        ),
        *(
            f"optional:{name}:{field}"
            for name, field in (
                ("DisputeResolutionDecision", "member"),
                ("ObligationExtinguishingDecision", "obligation"),
                ("ObligationChangeDecision", "obligation"),
                ("ObligationChangeDecision", "replacement_requirement"),
                ("RevocationDecision", "revoked"),
                ("RefusalResolutionDecision", "halt_occurrence"),
                ("StageOutcomeDecision", "context"),
                ("StageOutcomeDecision", "outcome"),
            )
        ),
        "ambiguity",
        "o6-corrects",
        *(
            f"{change}:{value}"
            for change in ("drop-outcome", "fold-outcome")
            for value in ("ACCEPTED", "REFUSED", "ABANDONED", "ACCEPT_PARTIAL")
        ),
    ],
)
@pytest.mark.traces("SC01-V9")
def test_st01c2_schema_mutations_have_surviving_controls(change: str) -> None:
    from enum import StrEnum
    from typing import Any

    from pydantic import BaseModel, create_model

    import test_ga01_vocabulary as vocabulary_evidence
    import test_ga05_negative as model_evidence
    from gpauto import authorization, governance
    from gpauto.absence import Determined
    from gpauto.identity import AuthorityAmbiguityId, OwnerDecisionId

    forms_killer = model_evidence.test_st01c2_closed_forms_required_referents_and_corrections
    outcome_killer = model_evidence.test_st01c2_outcomes_o6_and_lawful_suspension
    vocabulary_killer = vocabulary_evidence.test_st01c2_exact_decision_and_outcome_vocabularies
    killer = forms_killer
    mutant: type[BaseModel]
    with pytest.MonkeyPatch.context() as patch:
        if change.startswith(("literal:", "optional:")):
            mutation_kind, name, field = change.split(":")
            cls = getattr(governance, name)
            annotation: Any = (
                str if mutation_kind == "literal" else cls.model_fields[field].annotation
            )
            default: Any = ... if mutation_kind == "literal" else None
            fields: dict[str, Any] = {field: (annotation, default)}
            mutant = create_model(cls.__name__, __base__=cls, **fields)
            killer()
            patch.setattr(governance, cls.__name__, mutant)
        elif change == "o6-corrects":
            mutant = create_model(
                "ObligationChangeDecision",
                __base__=governance.ObligationChangeDecision,
                corrects=(Determined[OwnerDecisionId], ...),
            )
            killer()
            patch.setattr(governance, "ObligationChangeDecision", mutant)
        elif change == "ambiguity":
            killer = outcome_killer
            annotation = authorization.SuspendedDisposition.model_fields[
                "established_by_event"
            ].annotation
            fields = {"established_by_event": (annotation | AuthorityAmbiguityId, ...)}
            mutant = create_model(
                "SuspendedDisposition", __base__=authorization.SuspendedDisposition, **fields
            )
            killer()
            patch.setattr(authorization, "SuspendedDisposition", mutant)
        else:
            killer = vocabulary_killer
            from gpauto.vocabulary import StageOutcomeDisposition

            values = {value.name: value.value for value in StageOutcomeDisposition}
            mutation_kind, value = change.split(":")
            if mutation_kind == "drop-outcome":
                del values[value]
            else:
                values[value] = "REFUSED" if value == "ACCEPTED" else "ACCEPTED"
            killer()
            patch.setattr(vocabulary_evidence, "StageOutcomeDisposition", StrEnum("Mutant", values))
        with pytest.raises((AssertionError, pytest.fail.Exception)):
            killer()
