"""The matrix is generated from frozen sources and bound to executed results.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §13 (`EV11-1`, `EV11-5`, `EV11-6`), §16
(`GP-AUTO-ST-01` acceptance — traceability rows for the AP-03 invariants this stage
discharges).

`TR11-4` lists what a generated matrix must assert: every in-scope element appears
exactly once; every element has a disposition; every non-`N/A` element names at least
one evidence class and the stage roles of `TR11-4a`; and no evidence class names a
non-existent element. Those are here, together with `TR11-7`'s reverse direction,
`TR11-9`'s closed vocabulary, and the two properties that make the matrix worth
reading at all: its inventory comes from the **frozen artifact**, and `discharged`
requires a result, not a declaration.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

import traceability
from gate_scope import REPOSITORY_ROOT
from traceability import (
    DISCHARGED,
    INTEGRATIVE_STAGE,
    NOT_APPLICABLE,
    OWED_BY,
    ST01_CONTRACT_OBLIGATIONS,
    UNDISCHARGED,
    FrozenSourceError,
)

ALL_PASSED = "all-designated-evidence-passed"


def synthetic_results(outcome: bool = True) -> dict[str, bool]:
    """Every declared node id, with the given outcome — a stand-in for a real run."""
    results: dict[str, bool] = {}
    for node_ids in traceability.declared_evidence().values():
        for node_id in node_ids:
            results[node_id] = outcome
    return results


# --- A. The inventory comes from the frozen artifact ----------------------------


@pytest.mark.traces("ST01-A6")
def test_the_ap03_inventory_is_parsed_from_the_frozen_artifact() -> None:
    """`TR11-4`, `TR11-8`: generated from the artifacts, never hand-maintained.

    The artifact is the source. A transcribed list would be a second normative
    inventory, and two inventories of one frozen thing can disagree — at which point
    the matrix is evidence about itself rather than about the artifact.
    """
    inventory = traceability.ap03_invariants()
    assert len(inventory) == 36
    assert list(inventory) == [f"AP03-I{index:02d}" for index in range(1, 37)]
    assert all(statement.strip() for statement in inventory.values())

    # The statements are AP-03's own words, not a paraphrase written here.
    source = traceability.frozen_artifact_text("ap03_path", "ap03_sha256")
    for element, statement in inventory.items():
        assert statement in source, element


@pytest.mark.traces("ST01-A6")
def test_the_frozen_source_digest_is_verified_before_it_is_used() -> None:
    """An artifact whose digest does not match is not the frozen artifact.

    There is no fallback inventory to fall back to: the generator fails instead, which
    is what keeps *"generated from the frozen artifact"* a true statement rather than a
    hopeful one.
    """
    configured = traceability._traceability_configuration()
    path = Path(configured["ap03_path"])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == configured["ap03_sha256"]

    with pytest.raises(FrozenSourceError):
        traceability.frozen_artifact_text("ap03_path", "ap11_sha256")


@pytest.mark.traces("ST01-A6")
def test_the_stage_contract_ids_carry_no_ap03_content() -> None:
    """The ST01 labels are not a second normative inventory.

    They name this stage's own contract rows so `TR11-7`'s reverse direction has an
    answer for tests that verify the contract rather than an invariant. None of them
    restates an AP-03 invariant, and none disposes one.
    """
    assert not set(ST01_CONTRACT_OBLIGATIONS) & set(traceability.ap03_invariants())
    assert all(key.startswith("ST01-") for key in ST01_CONTRACT_OBLIGATIONS)
    assert not any(key in OWED_BY for key in ST01_CONTRACT_OBLIGATIONS)


# --- B. `discharged` requires an executed passing result ------------------------


@pytest.mark.traces("ST01-A6")
def test_a_declaration_without_a_result_is_not_a_discharge() -> None:
    """`TR11-9`: discharged means the evidence *"was actually run, and passed"*.

    With no executed results supplied, every element is `undischarged` — including
    every element whose tests carry a `traces` marker. A marker is a declaration about
    what a test is for, never a report that it ran.
    """
    rows = traceability.matrix(None)
    assert rows
    assert all(row.disposition == UNDISCHARGED for row in rows)
    assert any("declared evidence did not pass" in row.detail for row in rows)


@pytest.mark.traces("ST01-A6")
def test_a_failing_result_is_not_a_discharge() -> None:
    """*"unrun, failed, indeterminate, evidence-missing and blocked"* are all one thing."""
    rows = traceability.matrix(synthetic_results(outcome=False))
    assert all(row.disposition == UNDISCHARGED for row in rows)


@pytest.mark.traces("ST01-A6")
def test_a_passing_result_discharges_only_the_elements_that_declared_it() -> None:
    """The binding is per element, not aggregate (`EV11-3`)."""
    rows = {row.element: row for row in traceability.matrix(synthetic_results())}
    declared = set(traceability.declared_evidence())

    for element, row in rows.items():
        if element in declared:
            assert row.disposition == DISCHARGED, element
            assert row.detail, element
        else:
            assert row.disposition == UNDISCHARGED, element


@pytest.mark.traces("ST01-A6")
def test_one_failing_parametrization_withholds_the_discharge() -> None:
    """A suite where one case failed has not shown the element enforced."""
    results = synthetic_results()
    target = sorted(traceability.declared_evidence())[0]
    node_id = traceability.declared_evidence()[target][0]
    results[node_id] = False

    row = next(row for row in traceability.matrix(results) if row.element == target)
    assert row.disposition == UNDISCHARGED
    assert node_id in row.detail


@pytest.mark.traces("ST01-A6")
def test_the_results_reader_folds_parametrizations_and_reads_outcomes(tmp_path: Path) -> None:
    """The executed-result reader is itself checked, since everything rests on it."""
    report = tmp_path / "results.xml"
    report.write_text(
        '<testsuites><testsuite name="pytest">'
        '<testcase classname="tests_gpauto.test_x" name="test_a[one]"/>'
        '<testcase classname="tests_gpauto.test_x" name="test_a[two]"/>'
        '<testcase classname="tests_gpauto.test_x" name="test_b[one]"/>'
        '<testcase classname="tests_gpauto.test_x" name="test_b[two]">'
        '<failure message="boom"/></testcase>'
        '<testcase classname="tests_gpauto.test_x" name="test_c"><skipped/></testcase>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    outcomes = traceability.executed_results(report)
    assert outcomes["tests_gpauto/test_x.py::test_a"] is True
    assert outcomes["tests_gpauto/test_x.py::test_b"] is False
    assert outcomes["tests_gpauto/test_x.py::test_c"] is False


# --- C. Stage roles -------------------------------------------------------------


@pytest.mark.traces("ST01-A6")
def test_every_row_records_the_three_stage_roles_separately() -> None:
    """`TR11-4a`: implementing, local-verifying and integrative, recorded separately.

    Recording them separately is what makes *"is this enforced, where, and when"*
    answerable without reading the corpus. `TR11-4b` is respected: no element is mapped
    to the integrative stage alone.
    """
    for row in traceability.matrix(synthetic_results()):
        assert row.implementing.startswith("GP-AUTO-ST-"), row.element
        assert row.local_verifying == row.implementing, row.element
        assert row.integrative == INTEGRATIVE_STAGE, row.element
        assert row.implementing != INTEGRATIVE_STAGE, row.element


@pytest.mark.traces("ST01-A6")
def test_a_discharged_row_names_this_stage_and_an_undischarged_row_names_a_later_one() -> None:
    """The implementing stage is where the enforcement first exists (`TR11-4a`(i)).

    From `GP-AUTO-ST-02` on, *"this stage"* is the stage whose test modules carry the
    element's passing evidence — derived from the corpus, never declared per row — and
    it is always a stage that has run. An owed row names a stage that has not.
    """
    evidence = traceability.declared_evidence()
    for row in traceability.matrix(synthetic_results()):
        if row.disposition == DISCHARGED:
            assert row.implementing == traceability.evidence_stage(evidence[row.element])
            assert row.implementing in traceability.STAGES_RUN, row.element
        elif row.element in OWED_BY:
            assert row.implementing == OWED_BY[row.element][0], row.element
            assert row.implementing not in traceability.STAGES_RUN, row.element


# --- D. Deferred clauses --------------------------------------------------------


DEFERRED_CLAUSE_ELEMENTS = {
    # AP03-I19 was owed to GP-AUTO-ST-03 here; ST-03 has run and discharged it with its
    # own evidence, so it is no longer a deferred-clause element (test_ga17).
    "AP03-I24": "GP-AUTO-ST-09",
}
"""Invariants whose structural clauses hold here and whose remaining clause does not.

Reporting these as discharged would be the error `TR11-9` names: representation
counted as enforcement. Each is `undischarged`, owed by the stage that implements the
operation its remaining clause needs, with its verified structure recorded as support
so nothing is hidden in either direction.
"""


@pytest.mark.traces("ST01-A6")
@pytest.mark.parametrize(("element", "owed_stage"), sorted(DEFERRED_CLAUSE_ELEMENTS.items()))
def test_an_invariant_with_a_deferred_clause_is_not_reported_discharged(
    element: str, owed_stage: str
) -> None:
    """Representation present, behaviour owed elsewhere — so: `undischarged`."""
    row = next(row for row in traceability.matrix(synthetic_results()) if row.element == element)
    assert row.disposition == UNDISCHARGED
    assert row.implementing == owed_stage
    assert element in OWED_BY
    assert "structure verified here:" in row.detail


@pytest.mark.traces("ST01-A6")
def test_no_element_with_a_deferred_clause_carries_a_discharging_marker() -> None:
    """The disposition is derived, so the corpus must not claim otherwise.

    A `traces` marker on one of these would make the matrix report it discharged the
    moment its test passed — which is the defect, not a formatting detail.
    """
    declared = set(traceability.declared_evidence())
    assert not (declared & set(DEFERRED_CLAUSE_ELEMENTS))


# --- E. Disposition semantics and the four TR11-4 assertions --------------------


@pytest.mark.traces("ST01-A6")
def test_every_in_scope_element_appears_exactly_once_with_one_disposition() -> None:
    """`TR11-4`, assertions one and two."""
    rows = traceability.matrix(synthetic_results())
    elements = [row.element for row in rows]
    inventory = traceability.inventory()
    assert len(elements) == len(set(elements)) == len(inventory)
    assert set(elements) == set(inventory)
    assert all(row.disposition in {DISCHARGED, UNDISCHARGED, NOT_APPLICABLE} for row in rows)


@pytest.mark.traces("ST01-A6")
def test_the_disposition_vocabulary_is_closed_and_nothing_is_marked_not_applicable() -> None:
    """`TR11-9`: three dispositions, and `N/A` is not a way round a deferral.

    Every AP-03 invariant carries an implementation obligation somewhere in GP-AUTO, so
    `N/A` here would be the re-disposition `TR11-9` calls a defect in the plan's
    execution rather than a closure.
    """
    rows = traceability.matrix(synthetic_results())
    dispositions = {row.disposition for row in rows}
    assert dispositions <= {DISCHARGED, UNDISCHARGED}
    assert NOT_APPLICABLE not in dispositions


@pytest.mark.traces("ST01-A6")
def test_every_discharged_row_names_evidence_that_exists_in_the_corpus() -> None:
    """`TR11-4`, assertion three: evidence, not an assertion of evidence."""
    existing: set[str] = set()
    for path in sorted(traceability.TEST_TREE.glob("test_*.py")):
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        module = ast.parse(path.read_text(encoding="utf-8"))
        for node in module.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                existing.add(f"{relative}::{node.name}")

    for row in traceability.matrix(synthetic_results()):
        if row.disposition != DISCHARGED:
            continue
        node_ids = row.detail.split("; ")
        assert node_ids
        for node_id in node_ids:
            assert node_id in existing, f"{row.element} -> {node_id}"


@pytest.mark.traces("ST01-A6")
def test_no_evidence_names_an_element_outside_the_inventory() -> None:
    """`TR11-4`, assertion four."""
    assert traceability.unknown_elements() == []


@pytest.mark.traces("ST01-A6")
def test_every_test_traces_to_an_element() -> None:
    """`TR11-7`, the reverse direction.

    *"A test tracing to no element is either verifying an invented requirement or
    verifying an implementation detail, and must say which."* Every test here names an
    AP-03 invariant or one of this stage's own contract obligations.
    """
    assert traceability.untraced_tests() == []


@pytest.mark.traces("ST01-A6")
def test_every_undischarged_element_records_its_first_executable_stage() -> None:
    """`EV11-6`: owed, never absent and never waived."""
    for row in traceability.matrix(synthetic_results()):
        if row.disposition != UNDISCHARGED:
            continue
        assert row.element in OWED_BY, row.element
        assert row.implementing.startswith("GP-AUTO-ST-"), row.element
        assert row.implementing != "<UNRECORDED>", row.element
        assert row.note.strip(), row.element


@pytest.mark.traces("ST01-A6")
def test_no_owed_by_entry_is_stale() -> None:
    """An owed-by for a discharged element means declared and derived disagree."""
    discharged = {
        row.element for row in traceability.matrix(synthetic_results())
        if row.disposition == DISCHARGED
    }
    assert not (discharged & set(OWED_BY)), sorted(discharged & set(OWED_BY))


@pytest.mark.traces("ST01-A6")
def test_supporting_evidence_is_never_counted_as_a_discharge() -> None:
    """`TR11-9`: `undischarged` is never aggregated into or presented as a pass.

    Several elements have real structural verification here and still stand
    `undischarged`, because a clause of each belongs to a later stage. The matrix
    reports both facts without letting the first soften the second.
    """
    supported = set(traceability.declared_support())
    assert supported
    evidence = traceability.declared_evidence()
    rows = {row.element: row for row in traceability.matrix(synthetic_results())}
    for element in supported - set(evidence):
        assert rows[element].disposition == UNDISCHARGED, element
        assert "structure verified here:" in rows[element].detail, element
    # An element a stage supported and a later stage then discharged is discharged by
    # the later stage's **traces** evidence alone; the support is never among it.
    for element in supported & set(evidence):
        assert rows[element].disposition == DISCHARGED, element
        support = set(traceability.declared_support()[element])
        assert not support & set(rows[element].detail.split("; ")), element


@pytest.mark.traces("ST01-A6")
def test_this_stages_own_contract_obligations_all_carry_discharging_evidence() -> None:
    """Its AP-03 rows may be owed later; its own contract rows may not be.

    Checked against a passing result set, because a declaration alone would not show
    it either way.
    """
    rows = {row.element: row for row in traceability.matrix(synthetic_results())}
    undischarged = [
        element
        for element in ST01_CONTRACT_OBLIGATIONS
        if rows[element].disposition == UNDISCHARGED
    ]
    assert undischarged == []


@pytest.mark.traces("ST01-A6")
def test_the_generator_reports_a_self_consistent_matrix() -> None:
    """`EV11-7`: regenerable from the recorded inputs.

    The generator's exit status reports **consistency** — inventory parsed, no unknown
    element, no untraced test, every undischarged element owed somewhere — and never
    the dispositions themselves, which are a finding to read rather than a gate to pass.
    """
    assert traceability.main([]) == 0
