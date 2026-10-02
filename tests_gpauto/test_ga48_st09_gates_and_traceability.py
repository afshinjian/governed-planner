"""Design basis: ST-09 plan §5, §14, §17; gate scope and unchanged schema /4."""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

import decode_gate
import traceability as t
from gate_scope import REPOSITORY_ROOT, gpauto_source_files
from gpauto.review import (
    ClosureAssessment,
    Finding,
    FrozenFindingSet,
    PostFreezeCandidate,
    RemediationObligation,
)
from gpauto.store_schema import SCHEMA_VERSION, build_catalogue, schema_statements
from test_ga06_structural import PROVIDER_SDK_MODULES

GPAUTO_STAGE = "GP-AUTO-ST-09"
NEW = (
    "src/gpauto/finding_lifecycle.py",
    "tests_gpauto/st09_world.py",
    "tests_gpauto/test_ga44_st09_freeze.py",
    "tests_gpauto/test_ga45_st09_obligations_closure_and_candidates.py",
    "tests_gpauto/test_ga46_st09_cycle_and_budget.py",
    "tests_gpauto/test_ga47_st09_restart_and_mutation.py",
    "tests_gpauto/test_ga48_st09_gates_and_traceability.py",
)
MODIFIED = (
    "tests_gpauto/mutation.py",
    "tests_gpauto/traceability.py",
    "tests_gpauto/test_ga06_structural.py",
    "tests_gpauto/test_ga08_traceability.py",
    "tests_gpauto/test_ga14_st02_gates.py",
    "tests_gpauto/test_ga28_st05_gates_and_traceability.py",
    "tests_gpauto/test_ga33_st06_gates_and_traceability.py",
    "tests_gpauto/test_ga43_st08_gates_and_traceability.py",
)
SCOPE = NEW + MODIFIED
SOURCE = REPOSITORY_ROOT / NEW[0]
EARLIER_MODULES = {
    "absence",
    "activation",
    "authorization",
    "bounds",
    "envelope",
    "evidence",
    "governance",
    "identity",
    "repository",
    "review",
    "schema",
    "scope_frame",
    "vocabulary",
    "codec",
    "content_identity",
    "equivalence",
    "preimage",
    "coordination_identity",
    "coordination_records",
    "coordination_vocabulary",
    "minting",
    "store",
    "store_schema",
    "derivations",
    "state_machine",
    "state_machine_model",
}
FORBIDDEN_FIELDS = {
    "provider",
    "session",
    "worker_authored_channel",
    "severity",
    "rank",
    "priority",
    "merit",
    "recommendation",
    "resolution",
    "timestamp",
    "author",
    "committer",
    "message",
}


def surface_findings(path: Path) -> list[str]:
    found: list[str] = []
    allowed = {
        "__future__",
        "collections.abc",
        "dataclasses",
        "enum",
        "typing",
        "pydantic",
        "gpauto",
    } | {"gpauto." + m for m in EARLIER_MODULES}
    for n in ast.walk(ast.parse(path.read_text())):
        if isinstance(n, ast.Import):
            found.extend(a.name for a in n.names if a.name not in allowed)
        if isinstance(n, ast.ImportFrom):
            if n.module not in allowed:
                found.append(str(n.module))
            if n.module == "gpauto":
                found.extend(a.name for a in n.names if a.name not in EARLIER_MODULES)
        if isinstance(n, ast.Attribute) and n.attr in FORBIDDEN_FIELDS | {
            "model_validate",
            "model_validate_json",
            "unlink",
            "write_bytes",
            "write_text",
        }:
            found.append(n.attr)
        if isinstance(n, ast.Name) and n.id in {"open", "eval", "exec", "__import__"}:
            found.append(n.id)
    return found


def provider_findings() -> tuple[tuple[str, ...], list[str]]:
    found: list[str] = []
    for relative in SCOPE:
        for n in ast.walk(ast.parse((REPOSITORY_ROOT / relative).read_text())):
            modules = (
                [a.name for a in n.names]
                if isinstance(n, ast.Import)
                else [n.module or ""]
                if isinstance(n, ast.ImportFrom)
                else []
            )
            found.extend(
                relative + ":" + name
                for name in modules
                if name.split(".")[0] in PROVIDER_SDK_MODULES
            )
    return SCOPE, found


@contextmanager
def nonconformant(suffix: str) -> Iterator[None]:
    original = SOURCE.read_bytes()
    try:
        SOURCE.write_bytes(original + suffix.encode())
        yield
    finally:
        SOURCE.write_bytes(original)


@pytest.mark.traces("ST09-G1", "CY-14", "OP-5", "OP-6", "CL-4", "BC-5", "ST09-B1")
@pytest.mark.supports(
    "AP05-I31",
    "AP05-I32",
    "AP05-I33",
    "BC-8",
    "EV-4",
    "AP03-I13",
    "AP03-I14",
    "ST06C-I02",
    "ST06C-I03",
)
def test_imports_and_record_inputs_respect_the_stage_boundary() -> None:
    assert surface_findings(SOURCE) == []
    forbidden = {
        "authority",
        "observation",
        "attribution",
        "st06_world",
        "st07_world",
        "st08_world",
    }
    for relative in NEW:
        for n in ast.walk(ast.parse((REPOSITORY_ROOT / relative).read_text())):
            if isinstance(n, ast.Import):
                assert not {a.name.split(".")[-1] for a in n.names} & forbidden
            if isinstance(n, ast.ImportFrom):
                assert (n.module or "").split(".")[-1] not in forbidden
                if n.module == "gpauto":
                    assert not {a.name for a in n.names} & forbidden
    for suffix in (
        "\nfrom gpauto import authority\n",
        "\nimport json\n",
        "\nx = record.worker_authored_channel\n",
        "\nopen('x')\n",
        "\nx = record.session\n",
    ):
        with nonconformant(suffix):
            assert surface_findings(SOURCE), suffix
    tree = ast.parse(SOURCE.read_text())
    # No input-package/envelope derivation or session operation exists here.
    assert not {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    } & {
        "AuthorityEnvelope",
        "AuthorityEnvelopeRecord",
        "InputPackage",
        "InputPackageRecord",
        "WorkerActivationRecord",
    }


@pytest.mark.traces("ST09-G1")
def test_provider_decode_and_tool_gates_inspect_the_authorized_scope() -> None:
    inspected = {p.as_posix() for p in gpauto_source_files()}
    assert set(SCOPE) <= inspected and len(SCOPE) == 15 and len(NEW) == 7
    assert provider_findings() == (SCOPE, [])
    paths, failures = decode_gate.offenders()
    assert Path(NEW[0]) in paths and not failures
    with nonconformant("\nimport json\nST09_INVALID: int = 'wrong type'\n"):
        assert decode_gate.offenders()[1]
        ruff = subprocess.run(
            [str(REPOSITORY_ROOT / ".venv/bin/ruff"), "check", str(SOURCE)],
            capture_output=True,
            text=True,
            check=False,
        )
        mypy = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "--strict",
                "--cache-dir=/tmp/st09-gate-mypy",
                str(SOURCE),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert ruff.returncode and "F401" in ruff.stdout
        assert mypy.returncode and "assignment" in mypy.stdout
    with nonconformant("\nimport anthropic\n"):
        assert provider_findings()[1]
    assert surface_findings(SOURCE) == [] and not decode_gate.offenders()[1]


@pytest.mark.traces(
    "ST09-G1",
    "ST09-B1",
    "FI-6",
    "OB-7",
    "SC-1",
    "PF-6",
    "PF-9",
    "OD-7",
    "OD-8",
    "CY-16",
    "CY-23",
    "CY-24",
    "AP05-I14",
    "AP05-I28",
    "AP05-I40",
    "AP05-I41",
    "AP05-I42",
    "OP-2",
)
def test_no_derived_or_semantic_state_is_added_to_the_schema() -> None:
    assert SCHEMA_VERSION == "gpauto.coordination-store/4"
    ddl = "\n;\n".join(schema_statements(build_catalogue())).encode()
    assert (
        hashlib.sha256(ddl).hexdigest()
        == "a1084fa4f3a895d550667eec5098dff4bc08b02786e08f6ecea828e89fcce320"
    )
    forbidden = {
        "status",
        "scope",
        "force",
        "cycle_bound",
        "b15_used",
        "budget",
        "exhaustion",
        "rank",
        "priority",
        "severity",
        "merit",
        "recommendation",
    }
    for kind in (
        Finding,
        FrozenFindingSet,
        RemediationObligation,
        ClosureAssessment,
        PostFreezeCandidate,
    ):
        assert not set(kind.model_fields) & forbidden
    tree = ast.parse(SOURCE.read_text())
    assert not [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.bases and n.name != "LifecycleCause"
    ]
    assert surface_findings(SOURCE) == []
    assert {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}.isdisjoint(
        FORBIDDEN_FIELDS
    )
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            assert not any(
                word in n.value.lower()
                for word in ("detect all", "complete guarantee", "confine", "prevent")
            )


@pytest.mark.traces(
    "FZ-7",
    "FZ-9",
    "FZ-11",
    "NF-1",
    "NF-4",
    "NF-5",
    "NF-6",
    "RM-13",
    "RM-14",
    "SC-8",
    "CY-1",
    "CY-5",
    "CY-8",
    "CY-22",
    "OP-P1",
    "OP-P2",
    "OP-P4",
    "OP-P5",
    "OP-P6",
    "BC-3",
    "BC-9",
    "BC-13",
    "BC-14",
    "AP05-I02",
    "AP05-I25",
    "AP05-I37",
)
@pytest.mark.supports("FZ-14", "OB-11", "OB-12", "RM-1", "NF-2", "AP05-I26", "AP05-I36")
def test_only_the_four_authorized_create_units_exist() -> None:
    tree = ast.parse(SOURCE.read_text())
    writes = {}
    constructors: dict[str, set[str]] = {}
    for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
        for n in ast.walk(fn):
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "store"
            ):
                assert n.func.attr in {"enumerate", "create_unit"}
                if n.func.attr == "create_unit":
                    writes[fn.name] = ast.unparse(n.args[0])
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id
                in {
                    "Finding",
                    "FindingRecord",
                    "FrozenFindingSet",
                    "RemediationObligation",
                    "CycleOccurrence",
                    "M2PositionEntry",
                    "ClosureAssessmentRecord",
                    "PostFreezeCandidateRecord",
                }
            ):
                constructors.setdefault(n.func.id, set()).add(fn.name)
    assert writes == {
        "freeze": "(frozen, *findings, *obligations, entry)",
        "_establish": "(occurrence, entry)",
        "record_closure_assessments": "assessments",
        "record_post_freeze_candidates": "candidates",
    }
    assert constructors == {
        "Finding": {"freeze"},
        "FindingRecord": {"freeze"},
        "FrozenFindingSet": {"freeze"},
        "RemediationObligation": {"freeze"},
        "CycleOccurrence": {"_establish"},
        "M2PositionEntry": {"freeze", "_establish"},
        "ClosureAssessmentRecord": {"record_closure_assessments"},
        "PostFreezeCandidateRecord": {"record_post_freeze_candidates"},
    }
    assert not [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.ExceptHandler)
        and (n.type is None or ast.unparse(n.type) != "WriteRefused")
    ]
    # Frozen state and suffix entry are the only targets; no suffix-to-prefix transition.
    states = [
        ast.unparse(n.value)
        for n in ast.walk(tree)
        if isinstance(n, ast.keyword) and n.arg == "state"
    ]
    assert sorted(states) == [
        "M2Position.S5_FINDING_SET_FROZEN",
        "M2Position.S6_REMEDIATION_ACTIVE",
    ]
    assert not [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Name)
        and n.id in {"OwnerDecision", "Refusal", "StageOutcome", "AuthorityEnvelope"}
    ]


@pytest.mark.traces("ST09-A1", "ST09-G1")
def test_current_trace_ownership_preserves_the_closed_st08_snapshot() -> None:
    evidence, support = t.declared_evidence(), t.declared_support()
    new = set(t.st09_elements()) | set(t.ST09_CONTRACT_OBLIGATIONS)
    assert len(t.st09_elements()) == 240 and len(t.ST09_CONTRACT_OBLIGATIONS) == 31
    assert len(new) == 271 and len(t.inventory()) == 877
    old09 = {e for e, stage in t.OWED_AT_ST08_ACCEPTANCE.items() if stage == GPAUTO_STAGE}
    assert old09 == {
        "AP03-I24",
        "AP03-I36",
        "AP04-I30",
        "AP04-I31",
        "AP04-I45",
        "AP04-I47",
        "AP04-I49",
        "AP04-I50",
    }
    assert len(t.OWED_AT_ST08_ACCEPTANCE) == 25
    assert t.STAGES_RUN[-1] == GPAUTO_STAGE
    assert len(new & set(t.OWED_BY)) == 29 and len(t.OWED_BY) == 46
    for element in t.OWED_BY:
        assert element not in evidence
        if element in new:
            assert support.get(element)
    for element in (new - set(t.OWED_BY)) | old09:
        assert any(
            t.module_stage(REPOSITORY_ROOT / n.split("::")[0]) == GPAUTO_STAGE
            for n in evidence.get(element, ())
        ), element
    st08 = set(t.st08_elements()) | set(t.ST08_CONTRACT_OBLIGATIONS)
    for element in st08:
        assert not any(
            t.module_stage(REPOSITORY_ROOT / n.split("::")[0]) == GPAUTO_STAGE
            for n in evidence.get(element, ())
        )
    for element, stage in t.OWED_AT_ST08_ACCEPTANCE.items():
        if element not in old09:
            assert t.OWED_BY[element][0] == stage
    assert not t.unknown_elements() and not t.untraced_tests()
    assert "ST09-OWNER-DECISION-01 = (a)" in t.st09_elements()["FZ-6"]
    assert "ST09-OWNER-DECISION-01 = (a)" in t.st09_elements()["DO-12"]
