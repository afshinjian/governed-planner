"""`GP-AUTO-ST-06`: its static gates, its pinned operations, its boundaries, its rows.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §7 (`NV11-1`, `NV11-15`), §13 (`EV11-6`), §14
(`SD11-12a`(ii), `SD11-12b`, `SD11-16`), §15 (`SG11-11`, `SG11-11a`), §16 (`GP-AUTO-ST-06`
Static gates: *"As ST-05"*; Non-goals: *"No observation, no dispatch, no gate mechanics"*;
Discovery-review scope: *"including the absence of any selection operation"*); CLAUDE.md
amendment part 3.

Gates: each GP-AUTO gate enumerates the ST-06 module and tests and passes over them.
Operations: ST-06's functions are pinned by name, in its one module. Boundaries: no
selection operation, no write beyond its own units, no import beyond ST-01 … ST-05 and the
`canonical` primitive, no provider surface, no decision read as authority. Traceability:
ST-06's rows come from the frozen artifacts, digest-verified; each is discharged by ST-06's
own evidence or owed by a named later stage, and nothing owed elsewhere moved.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import decode_gate
import st06_world as w
import traceability
from gate_scope import REPOSITORY_ROOT, configured_paths
from gpauto import authority
from gpauto.absence import Present
from gpauto.coordination_records import RootResolutionRecord
from gpauto.coordination_vocabulary import M1Edge, M2Position
from gpauto.governance import AuthorizingDecision, OwnerDecision
from gpauto.identity import OwnerAuthorizationId, OwnerDecisionId
from gpauto.store import CoordinationStore
from gpauto.vocabulary import OwnerDecisionKind, Role
from st03_ingest import ingest
from st03_world import fresh_store
from test_ga06_structural import PROMPT_WORDS, PROVIDER_SDK_MODULES
from test_ga07_gate_scope import run_mypy, run_ruff
from traceability import DISCHARGED, OWED_BY, UNDISCHARGED

GPAUTO_STAGE = "GP-AUTO-ST-06"

ST06_PRODUCTION = (Path("src/gpauto/authority.py"),)
ST06_TESTS = (
    Path("tests_gpauto/st06_world.py"),
    Path("tests_gpauto/test_ga29_st06_eligibility.py"),
    Path("tests_gpauto/test_ga30_st06_resolution.py"),
    Path("tests_gpauto/test_ga31_st06_envelope.py"),
    Path("tests_gpauto/test_ga32_st06_restart_and_mutation.py"),
    Path("tests_gpauto/test_ga33_st06_gates_and_traceability.py"),
)

ST06_OPERATIONS = [
    "_attempt_anchor", "_canonical", "_canonical_key", "_carried_scopes", "_completing_unit",
    "_conditional_order", "_derivable", "_disagreeing_classes", "_exclusion_chain",
    "_exclusions", "_frozen_set_reference", "_indeterminate", "_missing_exclusions",
    "_multiplicity", "_multiplicity_of", "_own", "_priors_hold", "_ra_checks", "_read_pass",
    "_replayed", "_ten_dimension_order", "_truth", "_unreadable_of", "_unreadable_record_ids",
    "authority_ambiguity", "binding_match", "canonical_content", "canonical_member",
    "ceiling_clauses", "complete_resolution", "derive_envelope", "designation_within_read",
    "envelope_applicability", "envelope_facts", "envelope_inputs", "envelope_role_shape",
    "equivalent_or_narrower", "evaluate_resolution", "failing_attribute", "holds",
    "identity_consistency", "member_shape", "members_cover_worker_roles", "members_distinct",
    "missing_authority_refusal", "open_resolution", "ra_failures", "read_authority_records",
    "record_envelope", "remediator_within_implementer", "resolution_facts", "resolved_root",
    "reviewer_shape", "root_facts", "scope_frame_matches", "side_effects_declarable",
    "within_ceiling", "writer_shape",
]  # fmt: skip
"""Every function ST-06 declares. `holds` is `CeilingClauses`'."""

FORBIDDEN_OPERATION_WORDS = (
    "rank", "prefer", "choose", "pick", "latest", "newest", "merge", "reconcile", "winner",
    "best", "revive", "reset", "reopen", "reuse", "retry", "update", "delete", "replace",
    "remove", "migrate", "repair", "rekey", "reparent", "cache", "snapshot", "sort", "union",
    "intersect", "dispatch", "observe", "route", "package", "mirror",
)  # fmt: skip

ORDERINGS = {
    ("failing_attribute", "min"): "the lowest RA index among one record's attributes (S6G3-3)",
    ("_exclusions", "sorted"): "canonical JCS order of one resolution's exclusions (S6G3-6)",
    ("_canonical", "sorted"): "canonical JCS order of one dimension's tokens (EQ-3)",
    ("open_resolution", "sorted"): "canonical JCS order of the recorded candidate set",
    ("authority_ambiguity", "sorted"): "canonical JCS order of the competing identities",
    ("record_envelope", "sorted"): "the names in a refused call's error message",
}
"""Every ordering call in `authority.py` and what it orders. None orders candidates to
choose one: each is inert presentation, or one record's attributes (`AP04-I06`, `M1-4`)."""

ALLOWED_GPAUTO_IMPORTS = {
    "absence", "authorization", "bounds", "coordination_identity", "coordination_records",
    "coordination_vocabulary", "derivations", "envelope", "equivalence", "governance",
    "identity", "minting", "review", "scope_frame", "state_machine", "state_machine_model",
    "store", "vocabulary",
}  # fmt: skip
"""ST-01 … ST-05 modules, and nothing later: none exists, and ST-06 observes, dispatches,
attributes and routes nothing (AP-11 §16 ST-06 Non-goals)."""

WRITTEN_BY_ST06 = {
    "RootResolutionRecord", "M1PositionEntry", "CandidateExclusionRecord", "RefusalRecord",
    "AuthorityAmbiguity", "AuthorityEnvelopeRecord", "M3PositionEntry",
}  # fmt: skip
"""The start authorization's writes: `RC-14` with its `A1` entry, `RC-15`, the completing
M1 entry with `RC-30` or `RC-16`, and `RC-18` with its `C1` entry — nothing else."""


def _tree() -> ast.Module:
    return ast.parse((REPOSITORY_ROOT / ST06_PRODUCTION[0]).read_text(encoding="utf-8"))


def _function_of(tree: ast.Module, node: ast.AST) -> str:
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    line = getattr(node, "lineno", 0)
    inner = [f for f in functions if f.lineno <= line <= (f.end_lineno or 0)]
    return max(inner, key=lambda f: f.lineno).name


# --- gates -------------------------------------------------------------------------------------


@pytest.mark.traces("ST06-G1")
def test_ruff_inspects_every_st06_module_and_passes() -> None:
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
    assert set(ST06_PRODUCTION + ST06_TESTS) <= inspected
    result = run_ruff(configured_paths())
    assert result.returncode == 0, result.stdout


@pytest.mark.traces("ST06-G1")
def test_mypy_strict_type_checks_every_st06_module(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    result = run_mypy(configured_paths(), tmp_path / "cache", report_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    reported = {
        line.split()[-1]
        for line in (report_dir / "linecount.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().endswith("total")
    }
    expected = {f"gpauto.{p.stem}" for p in ST06_PRODUCTION} | {p.stem for p in ST06_TESTS}
    assert expected <= reported, sorted(expected - reported)


@pytest.mark.traces("ST06-G1")
def test_the_decode_gate_inspects_every_st06_module_and_finds_nothing() -> None:
    inspected, findings = decode_gate.offenders()
    assert set(ST06_PRODUCTION + ST06_TESTS) <= set(inspected)
    assert findings == ()


# --- operations and boundaries -----------------------------------------------------------------


@pytest.mark.traces("ST06-G1", "ST06-N3", "ST06-D2")
def test_st06_declares_exactly_its_operations_and_none_ranks_merges_or_routes() -> None:
    """ST-06's functions are pinned by name, all in `authority.py`; none ranks, prefers,
    merges, reconciles, revives, caches, dispatches, observes or routes; no lambda exists."""
    tree = _tree()
    names = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    assert sorted(names) == sorted(ST06_OPERATIONS)
    for name in names:
        assert not [word for word in FORBIDDEN_OPERATION_WORDS if word in name.lower()], name
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Lambda)]
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)]


@pytest.mark.traces("ST06-N3", "M1-4", "ST06-A1")
def test_no_selection_ranking_ordering_or_merge_operation_exists() -> None:
    """`AP04-I06`, `NV11-1`, `M1-4`: every ordering call in the module is one of the inert
    orderings named in `ORDERINGS`, keyed only by the `RA` enumeration or canonical bytes;
    no list is sorted in place; and no `max`, `reversed` or `__lt__` exists. The resolved
    root is produced only by unpacking a set of exactly one identity."""
    tree = _tree()
    found: dict[tuple[str, str], int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("sorted", "min", "max", "reversed"):
                key = (_function_of(tree, node), node.func.id)
                found[key] = found.get(key, 0) + 1
                for keyword in node.keywords:
                    assert ast.unparse(keyword.value) in ("RA_ORDER.index", "_canonical_key")
        if isinstance(node, ast.Attribute):
            assert node.attr not in ("sort", "__lt__", "__le__", "__gt__", "__ge__")
    assert set(found) == set(ORDERINGS), set(found) ^ set(ORDERINGS)
    unpacked = [
        ast.unparse(n.value)
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and ast.unparse(n.targets[0]) in ("only,", "(only,)")
    ]
    assert unpacked and all("eligible" in u for u in unpacked), unpacked


@pytest.mark.traces("ST06-G1", "AP03-I01")
def test_st06_writes_only_its_own_record_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Across every act — `A1`, the exclusions, `A2`, `A3`, `A4`, `C1` — every record written
    is of a class the start authorization names; no `RC-12`, `RC-13`, `RC-17`, `RC-26`,
    `RC-35`, M2 or M4 record is ever written by ST-06, and nothing is written but through
    `create_unit`."""
    written: set[str] = set()
    original = CoordinationStore.create_unit

    def recording(self: CoordinationStore, records: Any) -> None:
        unit = tuple(records)
        written.update(type(r).__name__ for r in unit)
        original(self, unit)

    with fresh_store() as store:
        s = w.scope()
        w.supply(store, s, [w.record(s, "record-a"), w.record(s, "record-z", "other")])
        opened = authority.open_resolution(store, s.project, s.stage)
        assert isinstance(opened, authority.Opened)
        monkeypatch.setattr(CoordinationStore, "create_unit", recording)
        authority.complete_resolution(store, opened.resolution)
    with fresh_store() as store:
        s = w.scope()
        w.supply(store, s, [w.record(s, "record-z", "x", authorized_roles=())])
        authority.open_resolution(store, s.project, s.stage)
        records = authority.read_authority_records(store)
        (occurrence,) = [
            r for r in records.derivable.records if isinstance(r, RootResolutionRecord)
        ]
        authority.complete_resolution(store, occurrence.identity)
    monkeypatch.setattr(CoordinationStore, "create_unit", original)
    with fresh_store() as store:
        s = w.scope()
        w.supply(store, s, [w.record(s, "record-a")])
        monkeypatch.setattr(CoordinationStore, "create_unit", recording)
        done = w.resolve(store, s)
        assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A2
        monkeypatch.setattr(CoordinationStore, "create_unit", original)
        epoch = w.epoch(store, s, w.root_id())
        monkeypatch.setattr(CoordinationStore, "create_unit", recording)
        found = epoch.derive(Role.IMPLEMENTER, M2Position.S3_IMPLEMENTATION_ACTIVE)
        assert isinstance(found, authority.EnvelopeRecorded)
    assert written == WRITTEN_BY_ST06, written ^ WRITTEN_BY_ST06
    tree = _tree()
    writes = {
        n.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr in ("create", "create_unit", "_execute")
    }
    assert writes == {"create_unit"}


@pytest.mark.traces("ST06-N7", "ST06-G1")
def test_no_decision_or_acceptance_is_ever_read_as_authority() -> None:
    """`NV11-15`, `AP03-I01`: an OWNER decision is never an authorization. A decision that
    says it produced an instance makes no record of that instance eligible — the
    candidates are the `RC-12` records alone, judged on their own content — and the module
    names no decision, outcome or acceptance at all; the one decision-borne fact it
    consumes, liveness, is ST-04's derivation."""
    s = w.scope()
    with fresh_store() as store:
        w.supply(store, s, [w.record(s, "record-a", owner_human_label_present=False)])
        ingest(
            store.path,
            [
                OwnerDecision(
                    identity=OwnerDecisionId(value="authorize-root"),
                    stage=s.stage,
                    act=AuthorizingDecision(
                        kind=OwnerDecisionKind.STAGE_ENTRY_AUTHORIZATION,
                        corrects=w.ABSENT,
                        produced_authorization=Present[OwnerAuthorizationId](value=w.root_id()),
                    ),
                )
            ],
        )
        done = w.resolve(store, s)
        assert isinstance(done, authority.Resolved) and done.entry.edge == M1Edge.A3
        (occurrence,) = [
            r for r in store.enumerate(RootResolutionRecord) if isinstance(r, RootResolutionRecord)
        ]
        assert [c.value for c in occurrence.candidates] == ["record-a"]
    names = {n.id for n in ast.walk(_tree()) if isinstance(n, ast.Name)}
    names |= {a.name for n in ast.walk(_tree()) if isinstance(n, ast.ImportFrom) for a in n.names}
    for forbidden in (
        "OwnerDecision", "StageOutcome", "StageOutcomeDecision", "AuthorizingDecision",
        "OwnerAuthorization",
    ):  # fmt: skip
        assert forbidden not in names, forbidden


@pytest.mark.traces("ST06-G1")
def test_st06_imports_nothing_later_and_only_the_authorized_spike_primitive() -> None:
    """The imports are ST-01 … ST-05 modules and `SD11-16`'s `canonical` primitive; no
    engine (`EB-6`), no JSON (`DC-1`), no observation, attribution or dispatch module."""
    imported: set[str] = set()
    spike: set[tuple[str, str]] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "gpauto":
                imported |= {alias.name for alias in node.names}
            elif module.startswith("gpauto."):
                imported.add(module.split(".", 1)[1])
            elif module.startswith("gplanner"):
                spike |= {(module, alias.name) for alias in node.names}
        if isinstance(node, ast.Import):
            assert not [a for a in node.names if a.name in ("json", "dbos", "sqlite3")]
    assert imported <= ALLOWED_GPAUTO_IMPORTS, imported - ALLOWED_GPAUTO_IMPORTS
    assert spike == {("gplanner.canonical", "canonical_bytes")}


@pytest.mark.traces("ST06-G1", "ST06-A1")
def test_the_st06_code_carries_no_provider_surface() -> None:
    """`SG11-11`, `SG11-11a`, amendment part 3: no provider SDK import in any ST-06 module,
    production or test; no prompt or provider identifier in production; no network,
    subprocess or browser client in production."""
    for relative in ST06_PRODUCTION + ST06_TESTS:
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
                if relative in ST06_PRODUCTION:
                    root = module.split(".")[0]
                    assert root not in {"socket", "http", "urllib", "requests", "subprocess"}
    tree = _tree()
    identifiers = [
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
    ]
    assert not [i for i in identifiers if any(word in i.lower() for word in PROMPT_WORDS)]


# --- traceability ------------------------------------------------------------------------------


def _rows() -> dict[str, traceability.Row]:
    results = {
        node_id: True
        for node_ids in traceability.declared_evidence().values()
        for node_id in node_ids
    }
    return {row.element: row for row in traceability.matrix(results)}


OWED_TO_ST06 = (
    "AP03-I01", "AP03-I02", "AP03-I06", "AP03-I07", "AP03-I13", "AP03-I14", "AP03-I15",
    "AP03-I18", "AP03-I30", "EQ-6", "AP04-I03", "AP04-I12", "AP04-I49",
)  # fmt: skip
"""The thirteen rows the committed inventory assigned to ST-06."""


@pytest.mark.traces("ST06-A1")
def test_the_st06_rows_are_parsed_from_the_frozen_artifacts() -> None:
    """`TR11-4`, `TR11-8`: each artifact's identity is checked first, then every ST-06 row is
    found in it — no transcribed inventory."""
    for path, digest, lines, size in (
        (traceability.AP04_PATH, traceability.AP04_SHA256, 1110, 189358),
        (
            traceability.ST06_CLARIFICATION_PATH,
            traceability.ST06_CLARIFICATION_SHA256,
            321,
            53738,
        ),
    ):
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, path.name
        assert (raw.count(b"\n"), len(raw)) == (lines, size), path.name
    rows = traceability.st06_elements()
    assert list(rows) == [
        *traceability.ST06_AP03_ELEMENTS,
        *traceability.ST06_AP04_ELEMENTS,
        *traceability.ST06_CLARIFICATION_ELEMENTS,
    ]
    assert len(rows) == 23 and all(statement.strip() for statement in rows.values())


@pytest.mark.traces("ST06-A1")
def test_every_st06_row_is_discharged_here_or_owed_by_a_named_later_stage() -> None:
    """Every row owed to ST-06, every frozen ST-06 row and every ST-06 contract row is
    discharged with ST-06 as implementing and local-verifying stage — except `AP04-I49`,
    whose adoption clause ST-09 owes, and `EV-5`, whose activation ST-12 owes: each stays
    undischarged, owed by a stage that has not run, with ST-06's support recorded."""
    rows = _rows()
    owed_later = {"AP04-I49": "GP-AUTO-ST-09", "EV-5": "GP-AUTO-ST-12"}
    elements = [
        *OWED_TO_ST06,
        *traceability.st06_elements(),
        *traceability.ST06_CONTRACT_OBLIGATIONS,
    ]
    for element in elements:
        row = rows[element]
        if element in owed_later:
            assert row.disposition == UNDISCHARGED, element
            assert OWED_BY[element][0] == owed_later[element], element
            assert row.implementing not in traceability.STAGES_RUN, element
            assert traceability.declared_support()[element], element
            assert element not in traceability.declared_evidence(), element
        else:
            assert row.disposition == DISCHARGED, element
            assert row.implementing == row.local_verifying == GPAUTO_STAGE, element
            assert element not in OWED_BY, element


@pytest.mark.traces("ST06-A1")
def test_nothing_owed_to_another_stage_is_discharged_or_reassigned_here() -> None:
    """`EV11-6`: every row owed at ST-05's acceptance to a stage other than ST-06 is still
    undischarged and owed by that same stage — or, once that stage has run, discharged by
    exactly it; no ST-06 test declares discharging evidence for it; and ST-06 has run. The
    set owed at ST-06's acceptance is the historical `OWED_AT_ST06_ACCEPTANCE` record, and
    is checked the same way (the ST-05 → `test_ga24` precedent)."""
    rows = _rows()
    evidence = traceability.declared_evidence()
    for owed_then in (
        traceability.OWED_AT_ST05_ACCEPTANCE,
        traceability.OWED_AT_ST06_ACCEPTANCE,
    ):
        for element, stage in owed_then.items():
            if stage == GPAUTO_STAGE:
                continue
            assert not [n for n in evidence.get(element, []) if "st06" in n], element
            if stage in traceability.STAGES_RUN:
                assert rows[element].disposition == DISCHARGED, element
                assert rows[element].implementing == stage, element
            else:
                assert rows[element].disposition == UNDISCHARGED, element
                assert OWED_BY[element][0] == stage, element
    assert GPAUTO_STAGE in traceability.STAGES_RUN
    assert traceability.unknown_elements() == []
    assert traceability.untraced_tests() == []
