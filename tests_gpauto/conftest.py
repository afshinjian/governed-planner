"""GP-AUTO test-suite bootstrap.

Design basis: AP-11 §14 (`SD11-10`, `SD11-12a`(ii)), §15 (`SG11-4`), §16
(`GP-AUTO-ST-01`).

This tree is **separate from and additive to** the spike's `tests/`. `SD11-10` places
GP-SPK-001's test modules outside reach: they are that stage's closed evidence, and
the spike's own `pytest` invocation — `testpaths = ["tests"]` — collects exactly what
it collected before, because nothing was added under it. GP-AUTO's suite is its own
invocation over this directory (`SD11-12a`(ii)).

This module imports only the standard library and pytest, following the spike
conftest's discipline: conftest is imported at collection time, so a dependency on a
package module would turn a missing import into a collection error rather than a test
failure.
"""

from __future__ import annotations

import pytest

GPAUTO_PACKAGE = "gpauto"


def pytest_configure(config: pytest.Config) -> None:
    """Register the traceability marker.

    `TR11-4` requires the element → evidence mapping to be **generated from the test
    corpus rather than hand-maintained**, because a hand-maintained matrix drifts and
    then lies. The markers are where a test declares which frozen elements it is
    evidence for; `traceability.py` reads the declarations back out of the corpus.

    Two markers, because `TR11-9` closes the disposition vocabulary and `EV11-6`
    forbids rounding anything into a discharge. `traces` is discharging evidence.
    `supports` is the honest middle: the element's structural half exists here and is
    tested, while its behavioural enforcement is owed by a later stage — so the row
    stays **`undischarged`**, a failing disposition, and says what already holds
    rather than pretending either more or less.
    """
    config.addinivalue_line(
        "markers",
        "traces(*element_ids): frozen normative elements this test discharges (TR11-4).",
    )
    config.addinivalue_line(
        "markers",
        "supports(*element_ids): elements this test bears on but does not discharge here — "
        "the structure exists and is verified, while the element's behavioural enforcement "
        "is owed by a later stage (EV11-6). Never counted as a discharge (TR11-9).",
    )
