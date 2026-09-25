"""`GP-AUTO-ST-03`: the `IV11-*` value sets — exactly their frozen members, and inert.

Design basis: AP-11 ST-03 store-realization amendment §5.1 (`IV11-1`…`IV11-15`), §5.2,
§4 (`SRB11-2`…`SRB11-4`), §11.1 (Tests, Negative tests, Discovery-review scope), §15
(`AP11-I65`…`AP11-I68`).

Each value set is checked against the **frozen amendment row itself**, digest-verified:
the expected members are listed here, and every one of them must be named by the row's
own text — so a member added here without a frozen name, or a frozen name dropped here,
fails. Then the set is shown closed at both layers: the model refuses a non-member, and
the store's schema refuses one written through any connection.
"""

from __future__ import annotations

import ast
import sqlite3
from enum import StrEnum
from pathlib import Path

import pytest
from pydantic import BaseModel

import traceability
from gpauto import (
    coordination_identity,
    coordination_records,
    coordination_vocabulary,
    store_schema,
)
from gpauto import vocabulary as st01_vocabulary
from gpauto.coordination_records import (
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
)
from gpauto.coordination_vocabulary import (
    AuditEntryClass,
    ClosureVerdict,
    ConformanceDeterminationClass,
    DeclaredItemClass,
    DiscoveryVerdict,
    M1Edge,
    M1Position,
    M2Edge,
    M2Position,
    M3Edge,
    M3Position,
    M4Edge,
    Machine,
    ObligationDisposition,
    Quiescence,
    StructuralConformanceResult,
    TerminatedDisposition,
    TimeoutDisposition,
)
from gpauto.vocabulary import AuthorizationDisposition
from st03_world import populated_store, raw

GPAUTO_STAGE = "GP-AUTO-ST-03"

FROZEN: dict[str, tuple[tuple[type[StrEnum], ...], dict[str, str]]] = {
    "IV11-1": ((M1Position,), {m.value: f"`{m.value}`" for m in M1Position}),
    "IV11-2": ((M2Position,), {m.value: f"`{m.value.replace('_', ' ', 1)}`" for m in M2Position}),
    "IV11-3": ((M3Position,), {m.value: f"`{m.value}`" for m in M3Position}),
    "IV11-4": (
        (M1Edge, M2Edge, M3Edge, M4Edge),
        {
            **{e: "M1 `A1`…`A4`" for e in ("A1", "A2", "A3", "A4")},
            **{e: "M2 `B1`…`B5`, `B6a`, `B6b`, `B7`…`B13`, `B15`" for e in M2Edge},
            **{e: "M3 `C1`…`C6`" for e in M3Edge},
            **{e: "M4 `G1`…`G6`" for e in M4Edge},
        },
    ),
    "IV11-5": ((ClosureVerdict,), {"CLOSED": "`CLOSED`", "NOT_CLOSED": "`NOT_CLOSED`"}),
    "IV11-6": (
        (DiscoveryVerdict,),
        {"FINDINGS_REPORTED": "*findings reported*", "NO_FINDINGS": "*no findings*"},
    ),
    "IV11-7": (
        (ObligationDisposition,),
        {"ADDRESSED": "*addressed*", "NOT_ADDRESSED": "*not addressed*"},
    ),
    "IV11-8": (
        (DeclaredItemClass,),
        {
            "DISCOVERY_VERDICT": "discovery verdict (`CA-7`)",
            "FINDING_ITEM": "finding item (`CA-8`)",
            "OBLIGATION_DISPOSITION_ITEM": "per-obligation disposition item (`CA-10`)",
            "MEMBER_CLOSURE_RESULT": "per-member closure result (`CA-12`)",
            "DISPUTE_ITEM": "dispute item (`CA-13`)",
            "POST_FREEZE_CANDIDATE_ITEM": "post-freeze-candidate item (`CA-14`)",
            "WORKER_REFUSAL_OR_EXPANSION_REQUEST": "declared worker refusal / expansion request",
        },
    ),
    "IV11-9": (
        (TerminatedDisposition,),
        {
            "ORDINARY_EXIT": "ordinary exit",
            "NON_ZERO_EXIT": "non-zero exit",
            "SIGNALLED_OR_KILLED": "signalled/killed",
            "EXTERNALLY_LOST": "externally lost",
        },
    ),
    "IV11-10": (
        (TimeoutDisposition,),
        {"TIMEOUT": "the timeout **termination-disposition class**"},
    ),
    "IV11-11": ((Quiescence,), {m.value: f"`{m.value}`" for m in Quiescence}),
    "IV11-12": (
        (ConformanceDeterminationClass,),
        {
            "STRUCTURAL_CONFORMANCE": "structural conformance (`CP-3`)",
            "ENVELOPE_CONFORMANCE": "envelope conformance of the activation's own effects",
            "RESIDUE": "residue",
            "ADOPTION": "adoption (`CP-5`)",
        },
    ),
    "IV11-13": (
        (StructuralConformanceResult,),
        {
            "CONFORMANT": "conformant;",
            "NONCONFORMANT": "nonconformant;",
            "INDETERMINATE": "indeterminate, which is a nonconformance",
        },
    ),
    "IV11-14": ((Machine,), {m.value: f"`{m.value}`" for m in Machine}),
    "IV11-15": (
        (AuditEntryClass,),
        {
            "REPORTED": "a record **reported**",
            "REPLAY": "a **replay** of an occurrence",
            "DELIVERY": "a **delivery** of an occurrence",
        },
    ),
}


@pytest.mark.traces(
    "IV11-1", "IV11-2", "IV11-3", "IV11-4", "IV11-5", "IV11-6", "IV11-7", "IV11-8",
    "IV11-9", "IV11-10", "IV11-11", "IV11-12", "IV11-13", "IV11-14", "IV11-15",
    "ST03-T6", "ST03-D6",
)  # fmt: skip
def test_each_value_set_is_exactly_its_frozen_members() -> None:
    """`AC11A-2`: every value set has exactly the members its frozen row names — each
    expected member's name is found in the digest-verified row, and the enumeration has
    no member beyond them. `B14` is named by the row as non-existent, and is not one."""
    rows = traceability.st03_amendment_elements()
    for element, (enums, names) in FROZEN.items():
        row = rows[element]
        members = {member.value for enum in enums for member in enum}
        assert members == set(names), element
        for value, phrase in names.items():
            assert phrase in row, (element, value, phrase)
    assert "`B14` does not exist" in rows["IV11-4"]
    assert "B14" not in {member.value for member in M2Edge}


@pytest.mark.traces("IV11-9", "IV11-5", "ST03-T6")
def test_the_structured_value_sets_keep_their_frozen_distinctions() -> None:
    """`IV11-9`: *termination indeterminate* carries no disposition class, so it can never
    read as terminated; `IV11-5`: `NOT_CLOSED` carries the `CL-8` reason, `CLOSED` none."""
    assert set(coordination_vocabulary.TerminationIndeterminate.model_fields) == set()
    assert set(coordination_vocabulary.Terminated.model_fields) == {"disposition"}
    assert set(coordination_vocabulary.ClosedVerdict.model_fields) == {"verdict"}
    assert set(coordination_vocabulary.NotClosedVerdict.model_fields) == {
        "verdict",
        "indeterminacy_reason",
    }


REFUSAL_SITES: dict[str, tuple[str, str]] = {
    "IV11-1": ("rc34_m1_position_entry", "state"),
    "IV11-2": ("rc34_m2_position_entry", "state"),
    "IV11-3": ("rc34_m3_position_entry", "state"),
    "IV11-4": ("rc34_m2_position_entry", "edge"),
    "IV11-5": ("rc28_closure_assessment", "verdict__ClosedVerdict__verdict"),
    "IV11-6": (
        "rc37_outcome_ingestion_record__items",
        "element__DiscoveryVerdictItem__verdict",
    ),
    "IV11-7": (
        "rc37_outcome_ingestion_record__items",
        "element__ObligationDispositionItem__disposition",
    ),
    "IV11-8": (
        "rc37_outcome_ingestion_record__items",
        "element__DiscoveryVerdictItem__item_class",
    ),
    "IV11-9": (
        "rc38_execution_observation",
        "observation__TerminationObservation__termination__Terminated__disposition",
    ),
    "IV11-10": ("rc38_execution_observation", "observation__TimeoutObservation__disposition"),
    "IV11-11": ("rc38_execution_observation", "observation__QuiescenceObservation__quiescence"),
    "IV11-12": (
        "rc39_conformance_determination",
        "determination__StructuralConformanceDetermination__determination_class",
    ),
    "IV11-13": (
        "rc39_conformance_determination",
        "determination__StructuralConformanceDetermination__result",
    ),
    "IV11-15": ("rc40_audit_entry", "entry_class"),
}


@pytest.mark.traces("ST03-T6")
def test_each_stored_value_set_refuses_any_other_value_through_any_connection() -> None:
    """Closure holds in the file, not only in the model: a row copied from a stored one
    with a single value replaced by a non-member — `B14` included, and a member of the
    right vocabulary pinned to the wrong variant — is refused by the schema's `CHECK`."""
    bad = {"IV11-4": "B14", "IV11-8": "FINDING_ITEM"}
    with populated_store() as (store, _):
        connection = raw(store)
        try:
            for element, (table, column) in REFUSAL_SITES.items():
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE {column} IS NOT NULL LIMIT 1"
                ).fetchall()
                assert rows, (element, table, column)
                names = [str(r[1]) for r in connection.execute(f"PRAGMA table_info({table})")]
                for value in (bad.get(element, "NOT_A_MEMBER"), "not_a_member"):
                    values = [
                        value if name == column else v
                        for name, v in zip(names, rows[0], strict=True)
                    ]
                    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
                        connection.execute(
                            f"INSERT INTO {table} ({', '.join(names)}) "
                            f"VALUES ({', '.join('?' for _ in names)})",
                            values,
                        )
        finally:
            connection.close()


@pytest.mark.traces("IV11-14", "ST03-T6")
def test_the_machine_vocabulary_labels_the_four_position_record_families() -> None:
    """`IV11-14`: each `RC-34` family is one machine's, its subject typed by that machine
    (AP-04 §2), so an entry's machine is fixed by its record class and its table."""
    families: dict[type[BaseModel], str] = {
        M1PositionEntry: "M1",
        M2PositionEntry: "M2",
        M3PositionEntry: "M3",
        M4PositionEntry: "M4",
    }
    catalogue = store_schema.build_catalogue()
    for entry, machine in families.items():
        assert getattr(entry, "MACHINE") is Machine(machine)  # noqa: B009 - a ClassVar
        assert catalogue.by_record[entry].name == f"rc34_{machine.lower()}_position_entry"
    assert M4PositionEntry.model_fields["state"].annotation is AuthorizationDisposition


# --- inert, and encoded once -----------------------------------------------------------------


def _module_tree(module: object) -> ast.Module:
    path = getattr(module, "__file__", None)
    assert path is not None
    return ast.parse(Path(path).read_text(encoding="utf-8"))


@pytest.mark.traces("AP11-I66", "ST03-N7")
def test_the_vocabularies_and_record_shapes_are_inert() -> None:
    """`SRB11-3`, `AP11-I66`: the vocabulary, identity and record modules declare classes
    and nothing else — no function, no method, no lambda, and no mapping or table
    constant that could carry a from→to relation, an admissibility table or a default."""
    for module in (coordination_vocabulary, coordination_identity, coordination_records):
        tree = _module_tree(module)
        for node in ast.walk(tree):
            assert not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda), (
                module.__name__,
                getattr(node, "name", "lambda"),
            )
            assert not isinstance(node, ast.Dict | ast.DictComp), module.__name__
            if isinstance(node, ast.Call):
                assert _is_type_construction(node), (module.__name__, ast.dump(node)[:80])


def _is_type_construction(node: ast.Call) -> bool:
    """`Field(min_length=1)` inside an annotation is the only call these modules make."""
    return isinstance(node.func, ast.Name) and node.func.id == "Field"


@pytest.mark.traces("AP11-I67", "ST03-N7")
def test_no_transition_guard_or_evaluator_exists_over_any_value() -> None:
    """`AP11-I67`, `SRB11-3`: ST-03 names edges and states and never relates them. The
    store's modules reference no vocabulary member in code, and the only member names in
    its SQL are the three edges whose result bindings `RO7A-5` fixes — a structural
    fact about the record, not an edge's endpoint, guard or coupling."""
    members = {
        m.value
        for enum in (M1Edge, M2Edge, M3Edge, M4Edge, M1Position, M2Position, M3Position)
        for m in enum
    }
    for module in (store_schema, coordination_records):
        tree = _module_tree(module)
        referenced = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id
            in {"M1Edge", "M2Edge", "M3Edge", "M4Edge", "M1Position", "M2Position", "M3Position"}
        }
        allowed = (
            {"B6a", "B15", "S6_REMEDIATION_ACTIVE"} if module is coordination_records else set()
        )
        assert referenced <= allowed, (module.__name__, referenced)
    literals: set[str] = set()
    for node in ast.walk(_module_tree(store_schema)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            literals.update(member for member in members if f"'{member}'" in node.value)
    assert literals == {"A2", "A3", "A4"}


@pytest.mark.traces("AP11-I65", "ST03-N7")
def test_no_concept_is_encoded_twice() -> None:
    """`SRB11-4`, `AP11-I65`: no ST-03 enumeration repeats, contains or is contained in an
    ST-01 or ST-02 one, and the M4 state is ST-01's `AuthorizationDisposition`, imported.
    The ST-01 resolution *outcome* and `IV11-1`'s M1 *positions* are two frozen concepts
    and share no member (§5.2 note)."""
    ours = [
        v
        for v in vars(coordination_vocabulary).values()
        if isinstance(v, type)
        and issubclass(v, StrEnum)
        and v.__module__ == coordination_vocabulary.__name__
    ]
    theirs = [
        v
        for v in vars(st01_vocabulary).values()
        if isinstance(v, type) and issubclass(v, StrEnum) and v is not StrEnum
    ]
    assert len(ours) == 18
    for enum in ours:
        values = {m.value for m in enum}
        for other in theirs:
            other_values = {m.value for m in other}
            assert not (values <= other_values or other_values <= values), (enum, other)
    assert "AuthorizationDisposition" not in vars(coordination_vocabulary)
    outcome = {m.value for m in st01_vocabulary.RootResolutionOutcome}
    assert outcome.isdisjoint({m.value for m in M1Position})


@pytest.mark.traces("AP11-I68", "ST03-A2")
def test_the_schema_is_generated_from_the_one_encoding_and_carries_no_second_list() -> None:
    """`AP11-I68`, `SRB11-6`: every closed-set `CHECK` in the schema is generated from the
    enumeration it closes, so a later change to a vocabulary is a schema change — a new
    version under `SRB11-13`, caught by the pinned schema digest — never a silent drift
    between two lists."""
    source = Path(store_schema.__file__ or "").read_text(encoding="utf-8")
    for enum in (
        M1Position,
        M2Position,
        M3Position,
        Quiescence,
        TerminatedDisposition,
        DeclaredItemClass,
    ):
        listed = ", ".join(f"'{m.value}'" for m in enum)
        assert listed not in source, enum
    statements = "\n".join(store_schema.schema_statements(store_schema.build_catalogue()))
    for enum in (M1Position, M2Position, M3Position, Quiescence, TerminatedDisposition):
        assert ", ".join(f"'{m.value}'" for m in enum) in statements, enum
