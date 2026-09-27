"""`GP-AUTO-ST-05`: its static gates, its pinned operations, its boundaries, its rows.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §13 (`EV11-6`), §14 (`SD11-12a`(ii),
`SD11-12b`, `SD11-16`), §15 (`SG11-11`, `SG11-11a`), §16 (`GP-AUTO-ST-05` Static gates: *"As
ST-04"*, Non-goals: *"No authority evaluation (ST-06), no observation (ST-07), no execution,
no routing (ST-16)"*); CLAUDE.md amendment part 3.

Gates: each GP-AUTO gate enumerates every ST-05 module and passes over it. Operations:
ST-05's functions are pinned by name, in its one operation module; its model module has
none. Boundaries: no provider surface, no later-stage evaluation, no import beyond ST-01 …
ST-04. Traceability: ST-05's rows come from the frozen AP-04 and its accepted amendment,
digest-verified; each is discharged by ST-05's own evidence or owed by a named later stage;
`AP03-I12` is discharged here; nothing owed to ST-06 or later is discharged.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import decode_gate
import traceability
from gate_scope import REPOSITORY_ROOT, configured_paths
from test_ga06_structural import PROMPT_WORDS, PROVIDER_SDK_MODULES
from test_ga07_gate_scope import run_mypy, run_ruff
from traceability import DISCHARGED, OWED_BY, UNDISCHARGED

GPAUTO_STAGE = "GP-AUTO-ST-05"

ST05_PRODUCTION = (Path("src/gpauto/state_machine_model.py"), Path("src/gpauto/state_machine.py"))
ST05_TESTS = (
    Path("tests_gpauto/test_ga25_st05_model.py"),
    Path("tests_gpauto/test_ga26_st05_matrix_and_coupling.py"),
    Path("tests_gpauto/test_ga27_st05_restart_and_mutation.py"),
    Path("tests_gpauto/test_ga28_st05_gates_and_traceability.py"),
)

ST05_OPERATIONS = [
    "__init__", "_admitted", "_completed_bound", "_cycle_bound_facts", "_envelope_facts",
    "_halt_facts", "_m1", "_m2", "_m3", "_m4", "_occurrence_bound", "_running_bound",
    "_stratified", "_truth", "_unmet", "act_violations", "admissible_edges",
    "conformance_matrix", "coupling_violations", "derived_guard_facts", "edge_rule",
    "evaluate", "evaluate_act", "fact_value", "guard_conditions", "occupancy",
    "recorded_positions", "recorded_restoration",
]  # fmt: skip
"""Every function ST-05 declares. `__init__` is `_Undetermined`'s, the internal signal."""

FORBIDDEN_OPERATION_WORDS = (
    "rank", "prefer", "select", "choose", "pick", "latest", "newest", "merge", "reconcile",
    "winner", "best", "revive", "reset", "reopen", "reuse", "retry", "update", "delete",
    "replace", "remove", "migrate", "repair", "rekey", "reparent", "write", "save", "persist",
    "store", "cache", "commit", "snapshot", "sort", "order", "resolve", "match", "compare",
    "package", "mirror", "route", "dispatch", "observe", "derive_envelope", "exclu",
    "candidate", "constitut",
)  # fmt: skip

ALLOWED_GPAUTO_IMPORTS = {
    "absence", "derivations", "state_machine_model", "coordination_identity",
    "coordination_records", "coordination_vocabulary", "identity", "vocabulary",
}  # fmt: skip
"""ST-01 … ST-04 modules and ST-05's own model — nothing later exists, and nothing that
evaluates authority (`authorization`'s records, `equivalence`) is read (`SD11-16`).
`absence` is ST-01's inert present/absent vocabulary, read for `E-14`'s role-conditional
reference (`OP-8`) and a halt's recorded cycle occurrence (`HB-1`)."""


# --- gates -------------------------------------------------------------------------------------


@pytest.mark.traces("ST05-G1")
def test_ruff_inspects_every_st05_module_and_passes() -> None:
    listed = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--no-cache", "--show-files"]
        + [str(p) for p in configured_paths()],
        capture_output=True,
        text=True,
        cwd=REPOSITORY_ROOT,
        check=True,
    )
    inspected = {
        Path(line).resolve().relative_to(REPOSITORY_ROOT)
        for line in listed.stdout.splitlines()
        if line.strip()
    }
    assert set(ST05_PRODUCTION + ST05_TESTS) <= inspected
    result = run_ruff(configured_paths())
    assert result.returncode == 0, result.stdout


@pytest.mark.traces("ST05-G1")
def test_mypy_strict_type_checks_every_st05_module(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    result = run_mypy(configured_paths(), tmp_path / "cache", report_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    reported = {
        line.split()[-1]
        for line in (report_dir / "linecount.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().endswith("total")
    }
    expected = {f"gpauto.{p.stem}" for p in ST05_PRODUCTION} | {p.stem for p in ST05_TESTS}
    assert expected <= reported, sorted(expected - reported)


@pytest.mark.traces("ST05-G1")
def test_the_decode_gate_inspects_every_st05_module_and_finds_nothing() -> None:
    inspected, findings = decode_gate.offenders()
    assert set(ST05_PRODUCTION + ST05_TESTS) <= set(inspected)
    assert findings == ()


# --- operations and boundaries -----------------------------------------------------------------


@pytest.mark.traces("ST05-G1", "ST05-D2", "AP04-I06", "AP04-I28")
def test_st05_declares_exactly_its_operations_and_none_chooses_or_writes() -> None:
    """ST-05's functions are pinned by name, all in `state_machine.py`; the model module
    declares none. None ranks, prefers, chooses, orders, merges, writes, caches, routes,
    dispatches, observes, resolves authority or derives an envelope; no lambda exists; and
    no position or class names a decision package (`AP04-I28`)."""
    tree = ast.parse((REPOSITORY_ROOT / ST05_PRODUCTION[1]).read_text("utf-8"))
    names = [
        n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    assert sorted(names) == sorted(ST05_OPERATIONS)
    for name in names:
        assert not [w for w in FORBIDDEN_OPERATION_WORDS if w in name.lower()], name
    model_tree = ast.parse((REPOSITORY_ROOT / ST05_PRODUCTION[0]).read_text("utf-8"))
    for source_tree in (tree, model_tree):
        assert not [n for n in ast.walk(source_tree) if isinstance(n, ast.Lambda)]
        classes = [n.name for n in ast.walk(source_tree) if isinstance(n, ast.ClassDef)]
        assert not [c for c in classes if "package" in c.lower() or "mirror" in c.lower()]
    assert not [
        n for n in ast.walk(model_tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    ]


@pytest.mark.supports("AP04-I03")
@pytest.mark.traces("ST05-B1", "ST05-G1")
def test_st05_evaluates_no_later_stage_authority_and_imports_nothing_later() -> None:
    """The ST-06 boundary: no `RA-00`…`RA-09` attribute, `AuthorizationRecord`, candidate,
    exclusion, ambiguity record, equivalence comparison or envelope derivation is named;
    the imports are ST-01 … ST-04 modules and ST-05's own model. Facts from ST-06, ST-07,
    ST-08, ST-09, ST-10, ST-12 and ST-14 are only named as suppliers, never computed."""
    for relative in ST05_PRODUCTION:
        tree = ast.parse((REPOSITORY_ROOT / relative).read_text("utf-8"))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
            alias.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for alias in n.names
        }
        for forbidden in (
            "AuthorizationRecord", "RaAttribute", "AuthorityBearingContent", "CandidateExclusion",
            "CandidateExclusionRecord", "AuthorityAmbiguity", "compare_records", "equivalence",
            "AuthorityEnvelope", "derive_envelope", "CoordinationStore",
        ):  # fmt: skip
            assert forbidden not in names, (relative, forbidden)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("gpauto"):
                if node.module == "gpauto":
                    imported |= {alias.name for alias in node.names}
                else:
                    imported.add((node.module or "").split(".", 1)[1])
        assert imported <= ALLOWED_GPAUTO_IMPORTS, (relative, imported - ALLOWED_GPAUTO_IMPORTS)


@pytest.mark.traces("ST05-G1", "ST05-A1")
def test_the_st05_code_carries_no_provider_surface() -> None:
    """`SG11-11`, `SG11-11a`, amendment part 3: no provider SDK import in any ST-05 module,
    production or test; no prompt or provider identifier in production; no network,
    subprocess or browser client in production."""
    for relative in ST05_PRODUCTION + ST05_TESTS:
        tree = ast.parse((REPOSITORY_ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            else:
                continue
            for module in modules:
                assert module.split(".")[0] not in PROVIDER_SDK_MODULES, (relative, module)
                if relative in ST05_PRODUCTION:
                    root = module.split(".")[0]
                    assert root not in {"socket", "http", "urllib", "requests", "subprocess"}
    for relative in ST05_PRODUCTION:
        tree = ast.parse((REPOSITORY_ROOT / relative).read_text(encoding="utf-8"))
        identifiers = [
            node.id if isinstance(node, ast.Name) else node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Name | ast.Attribute)
        ]
        assert not [i for i in identifiers if any(w in i.lower() for w in PROMPT_WORDS)]


# --- traceability ------------------------------------------------------------------------------


def _rows() -> dict[str, traceability.Row]:
    results = {
        node_id: True
        for node_ids in traceability.declared_evidence().values()
        for node_id in node_ids
    }
    return {row.element: row for row in traceability.matrix(results)}


@pytest.mark.traces("ST05-A1", "ST05-C1")
def test_the_st05_rows_are_parsed_from_the_frozen_artifacts() -> None:
    """`TR11-4`, `TR11-8`: each artifact's identity is checked first, then every ST-05 row
    is found in it — no transcribed inventory."""
    for path, digest, lines, size in (
        (traceability.AP04_PATH, traceability.AP04_SHA256, 1110, 189358),
        (traceability.AP04_CYCLE_PATH, traceability.AP04_CYCLE_SHA256, 664, 142207),
    ):
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, path.name
        assert (raw.count(b"\n"), len(raw)) == (lines, size), path.name
    rows = traceability.st05_elements()
    assert list(rows) == [*traceability.ST05_AP04_ELEMENTS, *traceability.ST05_CYCLE_ELEMENTS]
    assert len(rows) == 117
    assert "B14" not in rows


@pytest.mark.traces("ST05-A1", "ST05-A2")
def test_every_st05_row_is_discharged_here_or_owed_by_a_named_later_stage() -> None:
    """Every frozen ST-05 row and every ST-05 contract row is discharged with ST-05 as
    implementing and local-verifying stage, except the AP-04 invariants whose remaining
    clause is a later stage's act — each recorded in `OWED_BY` with its reason, owed by a
    stage that has not run, never `N/A` and never discharged here."""
    rows = _rows()
    owed_here = {e for e in traceability.st05_elements() if e in OWED_BY}
    assert owed_here == {
        "AP04-I03", "AP04-I12", "AP04-I22", "AP04-I25", "AP04-I30", "AP04-I31", "AP04-I32",
        "AP04-I35", "AP04-I36", "AP04-I45", "AP04-I47", "AP04-I48", "AP04-I49", "AP04-I50",
    }  # fmt: skip
    for element in [*traceability.st05_elements(), *traceability.ST05_CONTRACT_OBLIGATIONS]:
        row = rows[element]
        if element in owed_here:
            assert row.disposition == UNDISCHARGED, element
            assert row.implementing not in traceability.STAGES_RUN, element
        else:
            assert row.disposition == DISCHARGED, element
            assert row.implementing == row.local_verifying == GPAUTO_STAGE, element


@pytest.mark.traces("ST05-A1")
def test_ap03_i12_is_discharged_here_and_nothing_owed_later_is_pulled_forward() -> None:
    """`AP03-I12`, owed by ST-05 since ST-01, is discharged by ST-05's evidence and is no
    longer owed. Every other row owed at ST-04's acceptance is still undischarged and owed
    by the same stage — ST-06, ST-07, ST-08, ST-09, ST-17 — and no ST-05 test declares
    discharging evidence for any of them."""
    rows = _rows()
    assert rows["AP03-I12"].disposition == DISCHARGED
    assert rows["AP03-I12"].implementing == GPAUTO_STAGE
    assert "AP03-I12" not in OWED_BY
    evidence = traceability.declared_evidence()
    for element, stage in traceability.OWED_AT_ST04_ACCEPTANCE.items():
        if element == "AP03-I12":
            continue
        assert rows[element].disposition == UNDISCHARGED, element
        assert OWED_BY[element][0] == stage, element
        assert not [n for n in evidence.get(element, []) if "st05" in n], element
    assert traceability.STAGES_RUN[-1] == GPAUTO_STAGE
