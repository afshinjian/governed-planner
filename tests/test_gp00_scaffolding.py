"""GP-00 — the scaffolding itself.

Design basis: design/GP-SPK-001-governance-kernel.md §4.

Not one of the eleven spike requirements. It exists so the ST-1 gate
(`pytest --collect-only`) asserts something real: that the src-layout editable
install actually works and the harness fixture resolves. Without it the gate would
collect zero tests and exit 5, which proves nothing either way.
"""

from __future__ import annotations

import gplanner
from conftest import Harness


def test_the_package_is_installed_and_importable() -> None:
    assert gplanner.__version__ == "0.1.0"


def test_the_harness_derives_every_path_from_one_root(h: Harness) -> None:
    assert h.governance_db.parent == h.root
    assert h.system_db.parent == h.root
    assert h.ready_dir.is_dir()


def test_the_two_databases_are_distinct_files(h: Harness) -> None:
    """Ours and DBOS's are never the same store (design §12)."""
    assert h.governance_db != h.system_db
