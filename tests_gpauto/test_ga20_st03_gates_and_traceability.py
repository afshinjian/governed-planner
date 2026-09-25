"""`GP-AUTO-ST-03`: its static gates, its pinned operations, and its traceability rows.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §13 (`EV11-6`), §14 (`SD11-12a`(ii),
`SD11-12b`), §16 (`GP-AUTO-ST-03` Static gates: *"As ST-02, plus: decision layer imports
no engine"*); ST-03 store-realization amendment §11.1, §12 (`SRB11-31`…`SRB11-36`), §15
(`AP11-I64`, `AP11-I71`); follow-on amendment §4 (`AP11-I73`).

Gates: each GP-AUTO gate enumerates every ST-03 module it inspected and passes over them
(`SD11-12b`, carried forward from ST-01 and ST-02). Operations: ST-03's functions are
pinned by name, in its three operation modules only, and none selects, orders, updates or
deletes. Traceability: ST-03's rows come from the frozen artifacts, digest-verified; every
`RC-10` … `RC-41` row is realized by exactly one stage, ST-03; every row ST-03 owed from
ST-02 is discharged here; and the placement boundaries no stage has instantiated are
owed by ST-17, never `N/A`.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

import decode_gate
import traceability
from gate_scope import REPOSITORY_ROOT, configured_paths
from test_ga07_gate_scope import run_mypy, run_ruff
from traceability import DISCHARGED, INTEGRATIVE_STAGE, OWED_BY, UNDISCHARGED

GPAUTO_STAGE = "GP-AUTO-ST-03"

ST03_PRODUCTION = (
    Path("src/gpauto/coordination_vocabulary.py"),
    Path("src/gpauto/coordination_identity.py"),
    Path("src/gpauto/coordination_records.py"),
    Path("src/gpauto/minting.py"),
    Path("src/gpauto/store_schema.py"),
    Path("src/gpauto/store.py"),
)
ST03_TESTS = (
    Path("tests_gpauto/st03_ingest.py"),
    Path("tests_gpauto/st03_world.py"),
    Path("tests_gpauto/test_ga16_st03_vocabulary.py"),
    Path("tests_gpauto/test_ga17_st03_store.py"),
    Path("tests_gpauto/test_ga18_st03_root_resolution.py"),
    Path("tests_gpauto/test_ga19_st03_mutation.py"),
    Path("tests_gpauto/test_ga20_st03_gates_and_traceability.py"),
)

ST03_OPERATIONS: dict[str, list[str]] = {
    "minting.py": ["mint_value"],
    "store_schema.py": [
        "__init__", "_align", "_chain", "_column_ddl", "_decode_scalar", "_find", "_flatten",
        "_join", "_json_layout", "_literal", "_m1_checks", "_node", "_own_keys",
        "_partial_unique_ddl", "_presence", "_production_origin", "_references",
        "_same_subject", "_scalar_value", "_stray_children", "_substitute", "_superkeys",
        "_tables_under", "_trigger_ddl", "_unflatten", "_union_members", "_unwrap",
        "build_catalogue", "build_layout", "catalogue_specs", "child_key", "column", "flatten",
        "groups", "is_child", "key_groups", "key_node", "key_values", "schema_statements",
        "sql_value", "table_columns", "table_ddl", "table_references", "unflatten",
        "variant_tag", "writable_layouts",
    ],
    "store.py": [
        "__enter__", "__exit__", "__init__", "_apply_pragmas", "_connect", "_decode",
        "_decode_json", "_execute", "_insert", "_insert_row", "_layout", "_production",
        "_query", "_schema_rows", "_transaction", "close", "create", "create_store",
        "create_unit", "effective_pragmas", "enumerate", "expected_schema", "open_store",
        "path", "read", "schema_incompatibility",
    ],
}  # fmt: skip
"""Every function ST-03 declares, by module. Its other modules declare none (`test_ga16`)."""

FORBIDDEN_OPERATION_WORDS = (
    "rank", "prefer", "select", "choose", "pick", "latest", "newest", "merge", "reconcile",
    "winner", "best", "revive", "reset", "reopen", "update", "delete", "replace", "remove",
    "migrate", "upgrade", "repair", "rekey", "reparent", "transition", "guard", "evaluate",
    "advance",
)  # fmt: skip


# --- gates: SD11-12b carried forward to every ST-03 module ------------------------------


@pytest.mark.traces("ST03-G1")
def test_ruff_inspects_every_st03_module_and_passes() -> None:
    """`ruff` over the configured GP-AUTO scope lists every ST-03 file and finds nothing."""
    import subprocess
    import sys

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
    assert set(ST03_PRODUCTION + ST03_TESTS) <= inspected
    result = run_ruff(configured_paths())
    assert result.returncode == 0, result.stdout


@pytest.mark.traces("ST03-G1")
def test_mypy_strict_type_checks_every_st03_module(tmp_path: Path) -> None:
    """`mypy --strict` actually type-checks each ST-03 module, and passes."""
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    result = run_mypy(configured_paths(), tmp_path / "cache", report_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    reported = {
        line.split()[-1]
        for line in (report_dir / "linecount.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().endswith("total")
    }
    expected = {f"gpauto.{p.stem}" for p in ST03_PRODUCTION} | {p.stem for p in ST03_TESTS}
    assert expected <= reported, sorted(expected - reported)


@pytest.mark.traces("ST03-G1")
def test_the_decode_gate_inspects_every_st03_module_and_finds_nothing() -> None:
    """`DC-1`, `DC-2`: the store decodes JSON only through the ST-02 codec — its only JSON
    record, `RC-12`, is read by `codec.decode_authorization_record` — and no ST-03 module
    imports `json` or calls `model_validate`."""
    inspected, findings = decode_gate.offenders()
    assert set(ST03_PRODUCTION + ST03_TESTS) <= set(inspected)
    assert findings == ()


@pytest.mark.traces("ST03-G1", "AP11-I67", "ST03-N7")
def test_st03_declares_exactly_its_operations_and_none_decides_or_mutates() -> None:
    """ST-03's functions are pinned by name, in its three operation modules only. None is
    an ordering, preference, selection, merge, update, delete, replace, migration, repair,
    re-key, re-parent, transition, guard or evaluation (`AP11-I67`, `SRB11-3`, `WP-4`)."""
    declared: dict[str, list[str]] = {}
    for module, functions in ST03_OPERATIONS.items():
        tree = ast.parse((REPOSITORY_ROOT / "src" / "gpauto" / module).read_text("utf-8"))
        names = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        assert not [node for node in ast.walk(tree) if isinstance(node, ast.Lambda)], module
        declared[module] = sorted(names)
        assert declared[module] == sorted(functions), module
        for name in names:
            assert not [w for w in FORBIDDEN_OPERATION_WORDS if w in name.lower()], name


# --- traceability ---------------------------------------------------------------------------


def _rows() -> dict[str, traceability.Row]:
    results = {
        node_id: True
        for node_ids in traceability.declared_evidence().values()
        for node_id in node_ids
    }
    return {row.element: row for row in traceability.matrix(results)}


@pytest.mark.traces("ST03-A1", "AP11-I64")
def test_the_st03_rows_are_parsed_from_the_frozen_artifacts() -> None:
    """`TR11-4`, `TR11-8`: generated from the artifacts, each digest checked first, and
    each row's statement found verbatim in its source — no transcribed inventory."""
    for path, digest, lines, size in (
        (traceability.AP07_PATH, traceability.AP07_SHA256, 1127, 245910),
        (traceability.AP11_ST03_PATH, traceability.AP11_ST03_SHA256, 451, 61690),
        (traceability.AP11_ST03_FOLLOWON_PATH, traceability.AP11_ST03_FOLLOWON_SHA256, 153, 18457),
        (traceability.AP10_PATH, traceability.AP10_SHA256, 741, 139777),
    ):
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, path.name
        assert (raw.count(b"\n"), len(raw)) == (lines, size), path.name
    records = traceability.ap07_record_elements()
    assert list(records) == [f"RC-{n}" for n in range(10, 42)]
    amendment = traceability.st03_amendment_elements()
    assert list(amendment) == [
        *(f"IV11-{n}" for n in range(1, 16)),
        *(f"AP11-I{n}" for n in range(64, 72)),
    ]
    assert list(traceability.st03_followon_elements()) == ["AP11-I73"]
    assert list(traceability.placement_elements()) == list(traceability.PLACEMENT_ELEMENTS)
    source = traceability.AP10_PATH.read_text(encoding="utf-8")
    for clause in traceability.placement_elements().values():
        assert clause in source


@pytest.mark.traces("AP11-I64", "ST03-A1")
def test_every_record_class_row_is_realized_by_exactly_one_stage_st03() -> None:
    """`AP11-I64`, `SRB11-31`, `SRB11-36`: every `RC-10` … `RC-41` row is discharged, with
    ST-03 as its implementing and local-verifying stage and ST-18 only as the integrative
    re-verifier — never mapped to ST-18 alone (`TR11-4b`)."""
    rows = _rows()
    for number in range(10, 42):
        row = rows[f"RC-{number}"]
        assert row.disposition == DISCHARGED, row.element
        assert row.implementing == row.local_verifying == GPAUTO_STAGE, row.element
        assert row.integrative == INTEGRATIVE_STAGE, row.element


@pytest.mark.traces("ST03-A1")
def test_every_row_owed_to_st03_is_discharged_here_and_no_later_row_is_pulled_forward() -> None:
    """`SRB11-34`: the rows ST-03 owed — `RC-21`, `ID-3`, `ID-4`, `ID-5`, `ID-7`, `ID-8`,
    `ID-14`, `EQ-7`, `EQ-9`, `AP03-I10`, `AP03-I19`, `AP03-I27`, `AP03-I35` — are discharged
    by ST-03's own evidence; `EQ-6` stays owed by ST-06; and no row owed by a later stage
    is recorded as discharged here."""
    rows = _rows()
    owed_here = (
        "RC-21", "ID-3", "ID-4", "ID-5", "ID-7", "ID-8", "ID-14", "EQ-7", "EQ-9",
        "AP03-I10", "AP03-I19", "AP03-I27", "AP03-I35",
    )  # fmt: skip
    for element in owed_here:
        assert rows[element].disposition == DISCHARGED, element
        assert rows[element].implementing == GPAUTO_STAGE, element
        assert element not in OWED_BY, element
    assert rows["EQ-6"].disposition == UNDISCHARGED
    assert OWED_BY["EQ-6"][0] == "GP-AUTO-ST-06"
    for element, (stage, _) in OWED_BY.items():
        assert rows[element].disposition == UNDISCHARGED, element
        assert stage not in traceability.STAGES_RUN, element


@pytest.mark.traces("AP11-I71", "ST03-P1")
def test_unplaced_boundaries_are_owed_by_st17_and_never_not_applicable() -> None:
    """`AP11-I71`, `SRB11-29`, `SRB11-35`: `PB-2`(i) and (iv) are discharged here by
    location; (ii), (iii) and (v) are recorded **undischarged, owed by ST-17** — never
    `N/A`, and never checked against a location invented here."""
    rows = _rows()
    for element in ("PB-2(i)", "PB-2(iv)"):
        assert rows[element].disposition == DISCHARGED, element
        assert rows[element].implementing == GPAUTO_STAGE, element
    for element in ("PB-2(ii)", "PB-2(iii)", "PB-2(v)"):
        assert rows[element].disposition == UNDISCHARGED, element
        assert rows[element].implementing == "GP-AUTO-ST-17", element
        assert element not in traceability.declared_evidence(), element
    assert all(row.disposition != traceability.NOT_APPLICABLE for row in rows.values())


@pytest.mark.traces("ST03-A1")
def test_every_st03_contract_and_frozen_row_carries_discharging_evidence() -> None:
    """ST-03's own contract rows, its `IV11-*` rows and its new invariants all discharge
    here; `AP11-I72` is not a matrix row (see `traceability.ST03_AMENDMENT_ELEMENTS`)."""
    rows = _rows()
    elements = [
        *traceability.ST03_CONTRACT_OBLIGATIONS,
        *traceability.st03_amendment_elements(),
        *traceability.st03_followon_elements(),
    ]
    for element in elements:
        assert rows[element].disposition == DISCHARGED, element
        assert rows[element].implementing == GPAUTO_STAGE, element
    assert "AP11-I72" not in rows
