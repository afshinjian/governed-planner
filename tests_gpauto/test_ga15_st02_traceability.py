"""`GP-AUTO-ST-02`'s traceability rows: frozen sources, executed evidence, three roles.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §13 (`EV11-5`, `EV11-6`), §16
(`GP-AUTO-ST-02` frozen inputs, negative tests and acceptance); AP-07 §5, §23, §23.1.

ST-01's matrix tests (`test_ga08`) keep running over the whole matrix. This module adds
what is specific to ST-02's rows: they come from the **frozen AP-07 and AP-11
artifacts**, digest-verified, with no transcribed fallback; the selection of rows is
the one AP-11's own `GP-AUTO-ST-02` row names; `AP03-I04`, owed by ST-02 at ST-01's
acceptance, is now discharged by ST-02's evidence; and every ST-02 row that is not
discharged names the later stage that owes it, never ST-02 and never nothing.
"""

from __future__ import annotations

import hashlib
import re

import pytest

import traceability
from traceability import (
    DISCHARGED,
    INTEGRATIVE_STAGE,
    OWED_BY,
    ST02_CONTRACT_OBLIGATIONS,
    UNDISCHARGED,
    FrozenSourceError,
)

GPAUTO_STAGE = "GP-AUTO-ST-02"

EXPECTED_AP07 = (
    [f"ID-{n}" for n in range(1, 15)]
    + [f"EQ-{n}" for n in range(0, 11)]
    + [f"DC-{n}" for n in range(1, 6)]
    + ["VM-11"]
)


def synthetic_results(outcome: bool = True) -> dict[str, bool]:
    """Every declared node id, with the given outcome — a stand-in for a real run."""
    return {
        node_id: outcome
        for node_ids in traceability.declared_evidence().values()
        for node_id in node_ids
    }


def _rows() -> dict[str, traceability.Row]:
    return {row.element: row for row in traceability.matrix(synthetic_results())}


@pytest.mark.traces("ST02-A2", "ST02-A3")
def test_the_ap07_rows_are_parsed_from_the_frozen_artifact() -> None:
    """`TR11-4`, `TR11-8`: generated from the artifact, verbatim, digest checked first."""
    raw = traceability.AP07_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == traceability.AP07_SHA256
    assert len(raw) == 245910
    assert raw.count(b"\n") == 1127

    elements = traceability.ap07_elements()
    assert sorted(elements) == sorted(EXPECTED_AP07)
    source = raw.decode("utf-8")
    for element, statement in elements.items():
        assert statement in source, element


@pytest.mark.traces("ST02-A2")
def test_a_frozen_source_with_the_wrong_digest_is_refused() -> None:
    """No fallback inventory: an artifact that is not the frozen one is refused."""
    with pytest.raises(FrozenSourceError):
        traceability.verified_text(traceability.AP07_PATH, "0" * 64)


@pytest.mark.traces("ST02-A2")
def test_the_row_selection_is_the_one_ap11s_st02_contract_names() -> None:
    """The families in the inventory are read off AP-11's own `GP-AUTO-ST-02` row.

    Frozen inputs: AP-07 §5 (`ID-*`, `EQ-*`), §23.1 (`DC-1`…`DC-5`), `SD11-1`,
    `SD11-2`, `SD11-4`; negative tests: `VM-11`; discovery-review scope: `SD11-15`.
    """
    ap11 = traceability.frozen_artifact_text("ap11_path", "ap11_sha256")
    block = ap11.split("### `GP-AUTO-ST-02`", 1)[1].split("### `GP-AUTO-ST-03`", 1)[0]
    inputs = next(line for line in block.splitlines() if line.startswith("| Frozen inputs"))
    for family in ("`ID-*`", "`EQ-*`", "`DC-1`…`DC-5`", "`SD11-1`", "`SD11-2`", "`SD11-4`"):
        assert family in inputs, family
    negatives = next(line for line in block.splitlines() if line.startswith("| Negative tests"))
    assert "`VM-11`" in negatives
    review = next(line for line in block.splitlines() if line.startswith("| Discovery-review"))
    assert "`SD11-15`" in review

    assert set(traceability.ap11_elements()) == set(traceability.ST02_AP11_ELEMENTS)
    families = {re.sub(r"-\d+$", "", element) for element in traceability.ap07_elements()}
    assert families == {"ID", "EQ", "DC", "VM"}


@pytest.mark.traces("ST02-A2")
def test_ap03_i04_is_now_discharged_by_st02_evidence() -> None:
    """Owed by ST-02 at ST-01's acceptance, and discharged here — nowhere else."""
    row = _rows()["AP03-I04"]
    assert row.disposition == DISCHARGED
    assert row.implementing == row.local_verifying == GPAUTO_STAGE
    assert row.integrative == INTEGRATIVE_STAGE
    assert "AP03-I04" not in OWED_BY


@pytest.mark.traces("ST02-A2")
def test_every_st02_row_is_discharged_here_or_owed_by_a_later_stage() -> None:
    """`TR11-9`, `EV11-6`: `discharged`, or `undischarged` owed by a named later stage.

    Nothing is dispositioned `N/A`, and no ST-02 row is owed by ST-02 itself or by an
    earlier stage — an ST-02 obligation left undischarged *by* ST-02 would be a failing
    disposition of this stage, not an owed one.
    """
    rows = _rows()
    st02_rows = [*traceability.ap07_elements(), *traceability.ap11_elements()]
    for element in st02_rows:
        row = rows[element]
        if row.disposition == DISCHARGED:
            assert row.implementing == GPAUTO_STAGE, element
        else:
            assert row.disposition == UNDISCHARGED, element
            assert element in OWED_BY, element
            assert row.implementing not in traceability.STAGES_RUN, element
            assert row.implementing != INTEGRATIVE_STAGE, element


@pytest.mark.traces("ST02-A2")
def test_st02s_own_contract_rows_all_carry_discharging_evidence() -> None:
    """Its frozen rows may be owed later; its own contract rows may not be."""
    rows = _rows()
    assert all(key.startswith("ST02-") for key in ST02_CONTRACT_OBLIGATIONS)
    assert not set(ST02_CONTRACT_OBLIGATIONS) & set(OWED_BY)
    for element in ST02_CONTRACT_OBLIGATIONS:
        assert rows[element].disposition == DISCHARGED, element
        assert rows[element].implementing == GPAUTO_STAGE, element


@pytest.mark.traces("ST02-A2")
def test_every_owed_st02_row_records_what_holds_here_as_support() -> None:
    """An owed row does not hide what ST-02 did verify: the support is recorded."""
    rows = _rows()
    for element in ("ID-3", "ID-5", "ID-7", "ID-14", "EQ-6", "EQ-7"):
        assert rows[element].disposition == UNDISCHARGED, element
        assert "structure verified here:" in rows[element].detail, element
