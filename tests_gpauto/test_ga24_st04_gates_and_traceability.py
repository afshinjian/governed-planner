"""`GP-AUTO-ST-04`: its static gates, its pinned operations, and its traceability rows.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §13 (`EV11-6`), §14 (`SD11-12a`(ii),
`SD11-12b`), §15 (`SG11-11`, `SG11-11a`), §16 (`GP-AUTO-ST-04` Static gates: *"As
ST-03"*); AP-11 ST-04 derivation-ownership amendment §1–§3 (`DO11-1`…`DO11-8`,
`AP11-I74`).

Gates: each GP-AUTO gate enumerates every ST-04 module it inspected and passes over them.
Operations: ST-04's functions are pinned by name, in its one operation module, and none
selects, orders, prefers, writes, caches, evaluates authority or transitions anything.
Traceability: ST-04's rows come from the frozen AP-07 and the accepted ST-04 amendment,
digest-verified; each is discharged by ST-04's own evidence; `DV-4`, `DV-9`, `DV-10` and
`DV-11` are **not** ST-04 rows; and the nineteen rows owed to later stages stay owed.
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

GPAUTO_STAGE = "GP-AUTO-ST-04"

ST04_PRODUCTION = (Path("src/gpauto/derivations.py"),)
ST04_TESTS = (
    Path("tests_gpauto/st04_world.py"),
    Path("tests_gpauto/test_ga21_st04_derivations.py"),
    Path("tests_gpauto/test_ga22_st04_restart_and_absence.py"),
    Path("tests_gpauto/test_ga23_st04_mutation.py"),
    Path("tests_gpauto/test_ga24_st04_gates_and_traceability.py"),
)

ST04_OPERATIONS = [
    "__init__", "_authorized_effects", "_closing_activation", "_closure_scope", "_completed",
    "_cycle_bound", "_m1_chain", "_m2_chain", "_m3_chain", "_m4_chain", "_obligation_force",
    "_of", "_one", "_read_pass", "_still_suspending", "_stratum", "_walk",
    "derive_closure_scope", "derive_closure_scope_series", "derive_cycle_bound",
    "derive_liveness", "derive_m1_position", "derive_m2_position", "derive_m3_position",
    "derive_m4_position", "derive_obligation_force", "derive_outstanding_halts",
    "derive_prior_authorized_state", "derive_recorded_eligibility",
    "read_authoritative_records",
]  # fmt: skip
"""Every function ST-04 declares. `__init__` is `_Indeterminacy`'s, the internal signal."""

FORBIDDEN_OPERATION_WORDS = (
    "rank", "prefer", "select", "choose", "pick", "latest", "newest", "merge", "reconcile",
    "winner", "best", "revive", "reset", "reopen", "update", "delete", "replace", "remove",
    "migrate", "upgrade", "repair", "rekey", "reparent", "transition", "guard", "evaluate",
    "advance", "write", "save", "persist", "store", "cache", "commit", "snapshot", "sort",
    "order", "resolve", "match", "compare", "package", "mirror",
)  # fmt: skip

LATER_STAGE_OBLIGATIONS = 19
"""The rows owed to later stages at ST-04's entry: fifteen AP-03 invariants, three
`PB-2` placement clauses and `EQ-6`. ST-04 discharges none of them."""


# --- gates: SD11-12b carried forward to the ST-04 modules ---------------------------------


@pytest.mark.traces("ST04-G1")
def test_ruff_inspects_every_st04_module_and_passes() -> None:
    """`ruff` over the configured GP-AUTO scope lists every ST-04 file and finds nothing."""
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
    assert set(ST04_PRODUCTION + ST04_TESTS) <= inspected
    result = run_ruff(configured_paths())
    assert result.returncode == 0, result.stdout


@pytest.mark.traces("ST04-G1")
def test_mypy_strict_type_checks_every_st04_module(tmp_path: Path) -> None:
    """`mypy --strict` actually type-checks each ST-04 module, and passes."""
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    result = run_mypy(configured_paths(), tmp_path / "cache", report_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    reported = {
        line.split()[-1]
        for line in (report_dir / "linecount.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().endswith("total")
    }
    expected = {f"gpauto.{p.stem}" for p in ST04_PRODUCTION} | {p.stem for p in ST04_TESTS}
    assert expected <= reported, sorted(expected - reported)


@pytest.mark.traces("ST04-G1")
def test_the_decode_gate_inspects_every_st04_module_and_finds_nothing() -> None:
    """`DC-1`, `DC-2`: no ST-04 module imports `json` or calls `model_validate`; the
    derivations read decoded records through the store and decode nothing themselves."""
    inspected, findings = decode_gate.offenders()
    assert set(ST04_PRODUCTION + ST04_TESTS) <= set(inspected)
    assert findings == ()


@pytest.mark.traces("ST04-G1", "DO11-1", "DV-14")
def test_st04_declares_exactly_its_operations_and_none_decides_or_writes() -> None:
    """ST-04's functions are pinned by name, in its one operation module. None ranks,
    prefers, selects, orders, merges, writes, caches, snapshots, resolves authority,
    compares content, transitions or evaluates a guard; no lambda exists."""
    path = REPOSITORY_ROOT / "src" / "gpauto" / "derivations.py"
    tree = ast.parse(path.read_text("utf-8"))
    names = [
        n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    assert sorted(names) == sorted(ST04_OPERATIONS)
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.Lambda)]
    for name in names:
        assert not [w for w in FORBIDDEN_OPERATION_WORDS if w in name.lower()], name


@pytest.mark.traces("ST04-G1", "ST04-A1")
def test_the_st04_code_carries_no_provider_surface() -> None:
    """`SG11-11`, `SG11-11a`, amendment part 3: ST-04 is provider-free on every surface —
    no provider SDK import in its production or test modules, and no prompt or provider
    identifier in its production module."""
    for relative in ST04_PRODUCTION + ST04_TESTS:
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
    tree = ast.parse((REPOSITORY_ROOT / ST04_PRODUCTION[0]).read_text(encoding="utf-8"))
    identifiers = [
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
    ]
    assert not [i for i in identifiers if any(w in i.lower() for w in PROMPT_WORDS)]


# --- traceability ----------------------------------------------------------------------------


def _rows() -> dict[str, traceability.Row]:
    results = {
        node_id: True
        for node_ids in traceability.declared_evidence().values()
        for node_id in node_ids
    }
    return {row.element: row for row in traceability.matrix(results)}


@pytest.mark.traces("ST04-A1", "AP11-I74")
def test_the_st04_rows_are_parsed_from_the_frozen_artifacts() -> None:
    """`TR11-4`, `TR11-8`: generated from the artifacts, each identity checked first, and
    each row found verbatim in its source — no transcribed inventory."""
    for path, digest, lines, size in (
        (traceability.AP07_PATH, traceability.AP07_SHA256, 1127, 245910),
        (traceability.AP11_ST04_PATH, traceability.AP11_ST04_SHA256, 74, 17480),
    ):
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, path.name
        assert (raw.count(b"\n"), len(raw)) == (lines, size), path.name
    derivations = traceability.ap07_derivation_elements()
    assert list(derivations) == [
        "DV-1", "DV-2", "DV-3", "DV-5", "DV-6", "DV-7", "DV-8", "DV-12", "DV-13", "DV-14",
    ]  # fmt: skip
    amendment = traceability.st04_amendment_elements()
    assert list(amendment) == [*(f"DO11-{n}" for n in range(1, 9)), "AP11-I74"]
    ap07 = traceability.AP07_PATH.read_text(encoding="utf-8")
    ap11 = traceability.AP11_ST04_PATH.read_text(encoding="utf-8")
    for element in derivations:
        assert f"| {element} |" in ap07
    for element in amendment:
        assert element in ap11


@pytest.mark.traces("ST04-A1", "AP11-I74", "DO11-4", "DO11-6")
def test_rows_st04_does_not_implement_are_not_st04_rows() -> None:
    """`AP11-I74`: one implementing stage per derivation and per `DV-4` portion. `DV-4` as
    a whole (ST-04 and ST-06 portions), `DV-9`, `DV-10` (ST-15) and `DV-11` (ST-02) are
    not in the inventory as rows ST-04 could dispose; ST-04's share of each is its
    `DO11-*` row."""
    inventory = traceability.inventory()
    for element in ("DV-4", "DV-9", "DV-10", "DV-11"):
        assert element not in inventory, element
    assert traceability.unknown_elements() == []


@pytest.mark.traces("ST04-A1", "DO11-1", "DO11-5")
def test_every_st04_row_is_discharged_by_st04_evidence() -> None:
    """ST-04's `DV-*` rows, its amendment rows and its contract rows are each discharged
    with ST-04 as implementing and local-verifying stage — `DV-3` and `DV-5` included,
    which were enabled by the committed corrections and are discharged only here."""
    rows = _rows()
    elements = [
        *traceability.ap07_derivation_elements(),
        *traceability.st04_amendment_elements(),
        *traceability.ST04_CONTRACT_OBLIGATIONS,
    ]
    for element in elements:
        assert rows[element].disposition == DISCHARGED, element
        assert rows[element].implementing == rows[element].local_verifying == GPAUTO_STAGE, element
    for element in ("DV-3", "DV-5"):
        assert rows[element].implementing == GPAUTO_STAGE


@pytest.mark.traces("ST04-A1")
def test_no_later_stage_obligation_is_discharged_or_reassigned_here() -> None:
    """`EV11-6`, `SG11-9`: the nineteen rows owed to later stages are still undischarged,
    each still owed by the stage recorded for it; none is owed by ST-04; and nothing
    beyond them is undischarged."""
    rows = _rows()
    undischarged = {e for e, row in rows.items() if row.disposition == UNDISCHARGED}
    assert undischarged == set(OWED_BY)
    assert len(undischarged) == LATER_STAGE_OBLIGATIONS
    for element, (stage, _) in OWED_BY.items():
        assert rows[element].implementing == stage, element
        assert stage != GPAUTO_STAGE and stage not in traceability.STAGES_RUN, element
    assert traceability.STAGES_RUN[-1] == GPAUTO_STAGE
