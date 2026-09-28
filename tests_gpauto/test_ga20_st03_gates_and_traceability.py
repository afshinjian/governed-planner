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
import functools
import hashlib
import re
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
@pytest.mark.traces("SC03-V14", "SP6-V14")
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
@pytest.mark.traces("SC03-V14", "SP6-V14")
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
@pytest.mark.traces("SC03-V14", "SP6-V14")
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


@pytest.mark.traces("SC03-V14", "ST03-A1", "SP6-V14")
def test_correction_sources_prerequisites_and_traceability_are_pinned() -> None:
    """Accepted identities remain untouched; correction rows come from those sources."""
    elements = traceability.correction_elements()
    assert set(elements) == {
        *(f"SC01-V{n}" for n in range(1, 18)),
        *(f"SC03-V{n}" for n in range(1, 15)),
        *(f"SP6-V{n}" for n in range(1, 18)),
    }
    evidence = traceability.declared_evidence()
    assert set(elements) <= set(evidence)
    for name, lines, size, digest in (
        (
            "AP-02-AMENDMENT-V01-accept-partial-stage-outcome.md",
            51,
            4621,
            "0b920707e5b01a88b0cd10cab0fdf918f2c4e61a82a08c699fef933164affc7f",
        ),
        (
            "AP-04-AMENDMENT-S10-accept-partial-stage-outcome.md",
            55,
            4830,
            "26fc19097227d6bba5b161a4331834d289e2fb708de433d13e538bf816022ede",
        ),
        (
            "AP-09-AMENDMENT-SA9-1-stage-outcome-decision-kind.md",
            94,
            14468,
            "64dad3a83a064f55eedded1108aa09812abb08f1778102c65f44400048de037b",
        ),
        (
            "AP-03-AMENDMENT-stage-outcome-decision-and-accept-partial.md",
            71,
            11244,
            "3df51f702c7baa56cc180a93d7e3b56b98673ca26b54c055f94e5b51aab057c3",
        ),
        (
            "AP-05-AP-07-AMENDMENT-O6-obligation-change-content.md",
            71,
            12250,
            "f0558ae4f0e850fabcf6ab96af92d0c8d06bcf038f250a274f155087c6583282",
        ),
    ):
        raw = (Path("/root/.claude/plans") / name).read_bytes()
        assert (raw.count(b"\n"), len(raw), hashlib.sha256(raw).hexdigest()) == (
            lines,
            size,
            digest,
        )


# --- ST06PC-1 `SP6-V14`: discharged only by the complete executed regression ---------------

GPSPK_NODE = "tests_gpauto/test_ga20_st03_gates_and_traceability.py::test_the_gpspk_suite_passes"
GIT_DIFF_CHECK_NODE = (
    "tests_gpauto/test_ga20_st03_gates_and_traceability.py::test_git_diff_check_passes"
)
ST03_GATE_NODES = tuple(
    f"tests_gpauto/test_ga20_st03_gates_and_traceability.py::{name}"
    for name in (
        "test_ruff_inspects_every_st03_module_and_passes",
        "test_mypy_strict_type_checks_every_st03_module",
        "test_the_decode_gate_inspects_every_st03_module_and_finds_nothing",
        "test_correction_sources_prerequisites_and_traceability_are_pinned",
    )
)
TRACEABILITY_CONSISTENCY_NODE = (
    "tests_gpauto/test_ga08_traceability.py::test_the_generator_reports_a_self_consistent_matrix"
)


@pytest.mark.traces("SP6-V14")
def test_the_gpspk_suite_passes() -> None:
    """`SP6-V14`: the GP-SPK suite runs in full and passes, all 707 tests, as an executed
    GP-AUTO node. It runs as a subprocess and imports no spike module."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"],
        capture_output=True,
        text=True,
        cwd=REPOSITORY_ROOT,
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    summary = result.stdout.strip().splitlines()[-1]
    assert re.fullmatch(r"=* ?707 passed in [0-9.]+s( \([0-9:]+\))? ?=*", summary), summary


@pytest.mark.traces("SP6-V14")
def test_git_diff_check_passes() -> None:
    """`SP6-V14`: `git diff --check` finds no whitespace error in the working tree."""
    import subprocess

    result = subprocess.run(
        ["git", "diff", "--check"], capture_output=True, text=True, cwd=REPOSITORY_ROOT
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _sp6_v14(results: dict[str, bool] | None) -> traceability.Row:
    return {row.element: row for row in traceability.matrix(results)}["SP6-V14"]


def _junit(tmp_path: Path, outcomes: dict[str, str]) -> Path:
    """A JUnit report with one `testcase` per node id: `passed`, `failure` or `skipped`."""
    cases = []
    for node_id, outcome in outcomes.items():
        module, name = node_id.split("::")
        classname = module.removesuffix(".py").replace("/", ".")
        body = "" if outcome == "passed" else f"<{outcome}/>"
        cases.append(f'<testcase classname="{classname}" name="{name}">{body}</testcase>')
    report = tmp_path / "junit.xml"
    report.write_text("<testsuite>" + "".join(cases) + "</testsuite>", encoding="utf-8")
    return report


@pytest.mark.traces("SP6-V14")
def test_sp6_v14_is_discharged_only_by_the_complete_executed_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`SP6-V14`, `TR11-9`: the four ST-03 gate tests alone never discharge it. Its evidence
    is the whole GP-AUTO corpus — ST-04/ST-05 regression and mutation, the correction's
    mutation and gate tests, ruff, mypy, the decode gate, traceability consistency, and
    the executed GP-SPK and `git diff --check` nodes — so a partial, failing or skipped
    run leaves it undischarged. The untraced-test gate still reads the raw markers."""
    # The corpus does not change during the test, so its pure readers are memoized here.
    for reader in ("declared_evidence", "declared_support", "module_stage", "inventory"):
        monkeypatch.setattr(traceability, reader, functools.cache(getattr(traceability, reader)))
    corpus = traceability.corpus_tests()
    designated = set(traceability.declared_evidence()["SP6-V14"])
    required_groups = {
        "GP-SPK": [GPSPK_NODE],
        "git diff --check": [GIT_DIFF_CHECK_NODE],
        "traceability": [TRACEABILITY_CONSISTENCY_NODE],
        **{gate.split("::")[1]: [gate] for gate in ST03_GATE_NODES},
        **{
            module: [node for node in corpus if node.startswith(f"tests_gpauto/{module}_")]
            for module in (
                "test_ga11", "test_ga13", "test_ga19",  # correction mutation and gates
                "test_ga21", "test_ga22", "test_ga23", "test_ga24",  # ST-04, mutation ga23
                "test_ga25", "test_ga26", "test_ga27", "test_ga28",  # ST-05, mutation ga27
            )
        },
    }  # fmt: skip
    assert set(corpus) <= designated
    for group, nodes in required_groups.items():
        assert nodes, group
        assert set(nodes) <= set(corpus), group

    everything = dict.fromkeys(corpus, True)
    assert _sp6_v14(None).disposition == UNDISCHARGED
    assert _sp6_v14(dict.fromkeys(ST03_GATE_NODES, True)).disposition == UNDISCHARGED
    assert _sp6_v14(everything).disposition == DISCHARGED
    for group, nodes in required_groups.items():
        missing = {n: v for n, v in everything.items() if n not in nodes}
        assert _sp6_v14(missing).disposition == UNDISCHARGED, group
        failed = {**everything, **dict.fromkeys(nodes, False)}
        assert _sp6_v14(failed).disposition == UNDISCHARGED, group

    passed = dict.fromkeys(corpus, "passed")
    report = traceability.executed_results(_junit(tmp_path, passed))
    assert _sp6_v14(report).disposition == DISCHARGED
    for outcome in ("skipped", "failure"):
        report = traceability.executed_results(
            _junit(tmp_path, {**passed, corpus[0]: outcome, GPSPK_NODE: outcome})
        )
        assert _sp6_v14(report).disposition == UNDISCHARGED, outcome
    partial = {n: o for n, o in passed.items() if "test_ga20_" in n}
    report = traceability.executed_results(_junit(tmp_path, partial))
    assert _sp6_v14(report).disposition == UNDISCHARGED

    # The widening is evidence only: an unmarked test is still reported untraced.
    victim = "tests_gpauto/test_ga04_entities.py::" + next(
        n.split("::")[1] for n in corpus if n.startswith("tests_gpauto/test_ga04_")
    )
    monkeypatch.undo()
    raw = traceability._declared

    def without_victim(marker: str) -> dict[str, list[str]]:
        return {k: [n for n in v if n != victim] for k, v in raw(marker).items()}

    monkeypatch.setattr(traceability, "_declared", without_victim)
    assert traceability.untraced_tests() == [victim]
    assert victim in traceability.declared_evidence()["SP6-V14"]
