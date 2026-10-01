"""Design basis: ST-08 plan §15–17; PA-03-B conditional evidence and NV11-16 handoff."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

import decode_gate
import st07_world as x
import st08_world as w
import traceability as t
from gate_scope import REPOSITORY_ROOT
from gpauto import attribution as a
from gpauto.coordination_records import (
    ActivationEffectRecord,
    ConformanceDetermination,
    EnvelopeConformanceDetermination,
    EnvelopeViolationRecord,
    ResidueDetermination,
)
from gpauto.repository import UnaccountedMutation
from gpauto.store import CoordinationStore
from gpauto.store_schema import SCHEMA_VERSION, build_catalogue, schema_statements
from test_ga06_structural import PROVIDER_SDK_MODULES
from test_ga17_st03_store import PINNED_SCHEMA_DIGEST

GPAUTO_STAGE = "GP-AUTO-ST-08"
NEW = (
    "src/gpauto/attribution.py",
    "tests_gpauto/st08_world.py",
    "tests_gpauto/test_ga39_st08_brackets_and_attribution.py",
    "tests_gpauto/test_ga40_st08_defeat_and_classification.py",
    "tests_gpauto/test_ga41_st08_stratification_and_facts.py",
    "tests_gpauto/test_ga42_st08_restart_and_mutation.py",
    "tests_gpauto/test_ga43_st08_gates_and_traceability.py",
)
MODIFIED = (
    "tests_gpauto/mutation.py",
    "tests_gpauto/traceability.py",
    "tests_gpauto/test_ga06_structural.py",
    "tests_gpauto/test_ga14_st02_gates.py",
    "tests_gpauto/test_ga38_st07_gates_and_traceability.py",
)
SCOPE = NEW + MODIFIED
SOURCE = REPOSITORY_ROOT / NEW[0]
ALLOWED_IMPORTS = {
    "__future__",
    "dataclasses",
    "enum",
    "typing",
    "collections.abc",
    "gpauto",
    "gpauto.absence",
    "gpauto.coordination_identity",
    "gpauto.coordination_records",
    "gpauto.coordination_vocabulary",
    "gpauto.identity",
    "gpauto.minting",
    "gpauto.repository",
    "gpauto.store",
    "gpauto.vocabulary",
}
ALLOWED_OBSERVATION = {
    "observe",
    "bound_referents",
    "boundary_facts",
    "Observation",
    "Determinate",
    "Indeterminate",
    "Reader",
    "FILESYSTEM",
    "Referents",
    "ObservationCause",
}
FORBIDDEN_ATTRIBUTES = {"provider", "session", "author", "committer", "message"}


def surface_findings(path: Path) -> list[str]:
    tree = ast.parse(path.read_text("utf-8"))
    found: list[str] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            found.extend(alias.name for alias in n.names if alias.name not in ALLOWED_IMPORTS)
        if isinstance(n, ast.ImportFrom):
            if n.module not in ALLOWED_IMPORTS:
                found.append(str(n.module))
            if n.module == "gpauto":
                allowed = {
                    "authority",
                    "observation",
                    "derivations",
                    "state_machine",
                    "state_machine_model",
                }
                found.extend(alias.name for alias in n.names if alias.name not in allowed)
        if isinstance(n, ast.Attribute):
            if n.attr in FORBIDDEN_ATTRIBUTES:
                found.append(n.attr)
            if (
                isinstance(n.value, ast.Name)
                and n.value.id == "observation"
                and n.attr not in ALLOWED_OBSERVATION
            ):
                found.append(n.attr)
        if isinstance(n, ast.Name) and n.id in {"open", "eval", "exec", "__import__"}:
            found.append(n.id)
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if n.value in FORBIDDEN_ATTRIBUTES | {"git"}:
                found.append(n.value)
    return found


def provider_findings() -> tuple[tuple[str, ...], list[str]]:
    findings: list[str] = []
    for relative in SCOPE:
        for n in ast.walk(ast.parse((REPOSITORY_ROOT / relative).read_text("utf-8"))):
            modules = (
                [alias.name for alias in n.names]
                if isinstance(n, ast.Import)
                else [n.module or ""]
                if isinstance(n, ast.ImportFrom)
                else []
            )
            findings.extend(
                relative + ":" + name
                for name in modules
                if name.split(".")[0] in PROVIDER_SDK_MODULES
            )
    return SCOPE, findings


@contextmanager
def nonconformant(suffix: str) -> Iterator[None]:
    """Scope proof uses the one authorized production path, restored in finally."""
    original = SOURCE.read_bytes()
    try:
        SOURCE.write_bytes(original + suffix.encode())
        yield
    finally:
        SOURCE.write_bytes(original)


@pytest.mark.traces("ST08-G1", "ST08-B1", "AT9-3", "AT9-5", "AT9-9", "DC9-15")
def test_observation_import_actor_and_claim_surfaces_are_bounded() -> None:
    assert surface_findings(SOURCE) == []
    for suffix in (
        "\nimport os\n",
        "\nopen('x')\n",
        "\nx.provider\n",
        "\nobservation.fix_entry_boundary\n",
        "\nx = 'git'\n",
        "\nfrom gpauto import ingestion\n",
    ):
        with nonconformant(suffix):
            assert surface_findings(SOURCE), suffix
    tree = ast.parse(SOURCE.read_text("utf-8"))
    claims = [
        n.value.lower()
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    assert not [
        s
        for s in claims
        if any(word in s for word in ("prevent", "detect all", "confine", "complete guarantee"))
    ]
    # Fact inputs are records only; these functions have no store or reader parameter.
    for name in ("violation_facts", "completion_facts", "halt_cause_facts"):
        function = next(
            n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name
        )
        assert [arg.arg for arg in function.args.args][0] == "records"
        assert not any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in {"observe", "enumerate", "create_unit"}
            for n in ast.walk(function)
        )


@pytest.mark.traces("ST08-G1", "ST08-N4", "PA9-1")
def test_producer_values_have_only_the_authorized_basis() -> None:
    tree = ast.parse(SOURCE.read_text("utf-8"))
    values = [
        ast.unparse(n.value)
        for n in ast.walk(tree)
        if isinstance(n, ast.keyword) and n.arg == "producing_activation"
    ]
    assert values == [
        "Present[WorkerActivationId](value=activation)",
        "NotObserved()",
    ] or values == ["NotObserved()", "Present[WorkerActivationId](value=activation)"]
    assert not [
        n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == "affected_envelopes"
    ]
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "sorted"
        ):
            end = node.end_lineno or node.lineno
            lines = SOURCE.read_text("utf-8").splitlines()
            assert "inert presentation order" in "\n".join(lines[node.lineno - 1 : end + 1])
    with nonconformant("\nx = record.affected_envelopes\n"):
        changed = ast.parse(SOURCE.read_text("utf-8"))
        assert any(
            isinstance(n, ast.Attribute) and n.attr == "affected_envelopes"
            for n in ast.walk(changed)
        )


@pytest.mark.traces("ST08-G1")
def test_decode_import_and_provider_gates_cover_the_declared_scope() -> None:
    inspected, errors = decode_gate.offenders()
    assert Path(NEW[0]) in inspected and not errors
    paths, errors2 = provider_findings()
    assert paths == SCOPE and len(set(paths)) == 12 and not errors2
    with nonconformant("\nimport json\n"):
        assert decode_gate.offenders()[1]
    with nonconformant("\nimport openai\n"):
        assert provider_findings()[1]
    with nonconformant("\nx = EnvelopeViolationRecord.model_validate({})\n"):
        assert decode_gate.offenders()[1]


@pytest.mark.traces("ST08-G1")
def test_schema_identity_and_ddl_are_unchanged() -> None:
    assert SCHEMA_VERSION == "gpauto.coordination-store/4"
    assert (
        hashlib.sha256("\n;\n".join(schema_statements(build_catalogue())).encode()).hexdigest()
        == PINNED_SCHEMA_DIGEST
    )


@pytest.mark.traces("ST08-G1", "ST08-D1", "AT9-0", "OB9-15", "DC9-15", "PA9-3")
def test_st08_writes_only_effects_residue_and_the_two_determinations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = CoordinationStore.create_unit
    units = []

    def bounded(self: CoordinationStore, records: Any) -> None:
        unit = tuple(records)
        units.append(unit)
        assert all(
            isinstance(r, (ActivationEffectRecord, UnaccountedMutation, ConformanceDetermination))
            for r in unit
        )
        determinations = [r for r in unit if isinstance(r, ConformanceDetermination)]
        if determinations:
            assert len(determinations) == 2
            assert {type(r.determination) for r in determinations} == {
                EnvelopeConformanceDetermination,
                ResidueDetermination,
            }
            assert unit[-2:] == tuple(determinations)
        else:
            assert len(unit) == 1 and isinstance(unit[0], UnaccountedMutation)
        original(self, unit)

    for kind in ("lawful", "outside", "reviewer", "index", "history", "late", "closed"):
        from gpauto.vocabulary import Role

        with w.world() as s:
            subject, opening = w.begin(
                s, Role.DISCOVERY_REVIEWER if kind == "reviewer" else Role.IMPLEMENTER
            )
            s.repo.write("src/new", b"actual effect")
            if kind == "outside":
                s.repo.write("outside", b"outside")
            if kind == "index":
                s.repo.git("add", "src/new")
            if kind == "history":
                s.repo.git("commit", "--allow-empty", "-qm", "external")
            s.quiesce(subject)
            if kind in {"late", "closed"}:
                s.close(subject, adopted=kind == "late")
            closing = a.take_closing_bracket(s.store, subject.identity)
            assert isinstance(opening, a.Bracket) and isinstance(closing, a.Bracket)
            before = x.snapshot(s.repo.path)
            with monkeypatch.context() as patch:
                patch.setattr(CoordinationStore, "create_unit", bounded)
                result = a.assess_activation(s.store, subject.identity, opening, closing)
                assert isinstance(result, a.Assessed)
                if result.classification.defeats:
                    assert not result.effects and len(result.mutations) == len(
                        result.classification.differences
                    )
                else:
                    assert result.effects
                if kind == "closed":
                    assert isinstance(
                        a.record_non_completed_residue(s.store, subject.identity), a.Recorded
                    )
            assert x.snapshot(s.repo.path) == before
    assert units
    # The gate itself rejects both forbidden kinds, including any terminal-edge attempt.
    from gpauto.coordination_records import M3PositionEntry
    from st03_world import world

    fixtures = world().records()
    for record_kind in (EnvelopeViolationRecord, M3PositionEntry):
        record = next(r for r in fixtures if isinstance(r, record_kind))
        with w.world() as s, pytest.raises(AssertionError):
            bounded(s.store, (record,))


@pytest.mark.traces("AP03-I28", "AP04-I35", "AP04-I22", "ST08-G1")
def test_conditional_elements_retain_their_structural_clauses() -> None:
    """Support stays support. Positive branch not witnessed on repository observation."""
    from gpauto.authorization import AuthorityAmbiguity, CandidateExclusion
    from gpauto.governance import EnvelopeViolation, Refusal
    from test_ga05_negative import (
        test_the_case_marker_is_neither_optional_nor_inferable,
        test_the_not_prevented_marker_must_be_stated,
    )
    from test_ga06_structural import (
        test_no_governance_record_carries_a_recommendation_or_severity_field,
    )
    from test_ga25_st05_model import test_terminal_positions_have_no_lawful_outgoing_edge

    test_the_case_marker_is_neither_optional_nor_inferable()
    test_the_not_prevented_marker_must_be_stated()
    test_terminal_positions_have_no_lawful_outgoing_edge()
    test_no_governance_record_carries_a_recommendation_or_severity_field()
    types = (
        Refusal,
        EnvelopeViolation,
        UnaccountedMutation,
        AuthorityAmbiguity,
        CandidateExclusion,
    )
    assert len(set(types)) == 5
    assert all(
        not issubclass(left, right) for left in types for right in types if left is not right
    )
    # A reviewer has no write authority; its role cannot supply or exempt a producer.
    from gpauto.vocabulary import Role, WriteMode

    with w.world() as s:
        envelope = s.envelope(Role.DISCOVERY_REVIEWER)
        assert envelope.envelope.bounds.write_mode == WriteMode.READ_ONLY
        from gpauto.absence import NotApplicable

        assert isinstance(envelope.envelope.bounds.write_boundary, NotApplicable)
    # Earlier role-shape support: carrying E-12 is malformed, not broader authority.
    import st06_world
    from gpauto import authority
    from test_ga29_st06_eligibility import CLAUSE_CASES, RA07, S

    changes = next(
        changes for name, _, changes in CLAUSE_CASES if name == "d: reviewer carrying E-12"
    )
    invalid = st06_world.record(S, "st08-reviewer-with-write-boundary", **changes)
    assert authority.ra_failures(invalid) == {RA07}


@pytest.mark.traces("ST08-A1")
def test_st08_inventory_and_conditional_evidence_are_result_driven(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elements = t.st08_elements()
    assert len(elements) == 40
    assert all("Accepted 01-A" in elements[e] for e in ("AT9-1", "AT9-1b"))
    assert "Accepted 03-B" in elements["AT9-1b"] and "Accepted 04-A" in elements["AT9-1b"]
    assert len(t.inventory()) == 606
    assert not t.unknown_elements() and not t.untraced_tests()
    evidence = t.declared_evidence()
    assert not t.pa03_missing_declarations(evidence)
    # Reuse the parsed input fixtures while varying results; production reporting remains uncached.
    inventory = t.inventory()
    support = t.declared_support()
    stages = {
        REPOSITORY_ROOT / n.split("::")[0]: t.module_stage(REPOSITORY_ROOT / n.split("::")[0])
        for nodes in evidence.values()
        for n in nodes
    }
    monkeypatch.setattr(t, "inventory", lambda: inventory)
    monkeypatch.setattr(t, "declared_support", lambda: support)
    monkeypatch.setattr(t, "module_stage", lambda path: stages[path])
    # Synthetic result maps test the reporter only; final discharge uses real JUnit.
    results = {node: True for nodes in evidence.values() for node in nodes}
    rows = {r.element: r for r in t.matrix(results)}
    assert sum(r.disposition == t.DISCHARGED for r in rows.values()) == 581
    assert sum(r.disposition == t.UNDISCHARGED for r in rows.values()) == 25
    assert not [r for r in rows.values() if r.disposition == "not applicable"]
    assert {e for e, r in rows.items() if r.disposition == t.UNDISCHARGED} == set(t.OWED_BY)
    assert t.OWED_BY["OB9-16"][0] == t.OWED_BY["DC9-9"][0] == "GP-AUTO-ST-16"
    assert "Accepted 01-A" in rows["OB9-9a"].note
    for element, stage in t.OWED_AT_ST07_ACCEPTANCE.items():
        if stage != GPAUTO_STAGE:
            assert t.OWED_BY[element][0] == stage
            assert rows[element].disposition == t.UNDISCHARGED
    for element, required in t.PA03_REQUIRED.items():
        assert rows[element].implementing == rows[element].local_verifying == GPAUTO_STAGE
        assert "positive branch not witnessed" in rows[element].note
        for node in required:
            for value in (None, False):
                missing = dict(results)
                if value is None:
                    missing.pop(node)
                else:
                    missing[node] = value
                assert (
                    next(r for r in t.matrix(missing) if r.element == element).disposition
                    == t.UNDISCHARGED
                )
            declarations = {e: list(nodes) for e, nodes in evidence.items()}
            declarations[element].remove(node)
            with monkeypatch.context() as patch:
                patch.setattr(
                    t, "declared_evidence", lambda declarations=declarations: declarations
                )
                assert (
                    next(r for r in t.matrix(results) if r.element == element).disposition
                    == t.UNDISCHARGED
                )
    assert all(r.disposition == t.UNDISCHARGED for r in t.matrix(None))


@pytest.mark.traces("ST08-A1")
def test_omitted_negative_decorators_leave_the_conditional_element_undischarged() -> None:
    path = REPOSITORY_ROOT / "tests_gpauto/test_ga40_st08_defeat_and_classification.py"
    original = path.read_bytes()
    all_declared = t.declared_evidence()
    results = {n: True for nodes in all_declared.values() for n in nodes}
    try:
        for element in t.PA03_REQUIRED:
            path.write_bytes(original.replace(('"' + element + '"').encode(), b'"ST08-A1"'))
            assert element in t.pa03_missing_declarations(t.declared_evidence())
            row = next(r for r in t.matrix(results) if r.element == element)
            assert row.disposition == t.UNDISCHARGED
            assert row.implementing == GPAUTO_STAGE
    finally:
        path.write_bytes(original)


@pytest.mark.traces("ST08-G1")
def test_tool_gates_reject_a_nonconformant_authorized_production_file() -> None:
    import subprocess
    import sys

    with nonconformant('\nimport decimal\nST08_INVALID: int = "wrong type"\n'):
        ruff = subprocess.run(
            [str(REPOSITORY_ROOT / ".venv/bin/ruff"), "check", str(SOURCE)],
            capture_output=True,
            text=True,
            check=False,
        )
        mypy = subprocess.run(
            [sys.executable, "-m", "mypy", "--strict", str(SOURCE)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert ruff.returncode and "F401" in ruff.stdout and "decimal" in ruff.stdout
        assert mypy.returncode and "assignment" in mypy.stdout
    assert surface_findings(SOURCE) == []
