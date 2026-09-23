"""The GP-AUTO gates' configured scope, and the fixture harness that proves it.

Design basis: AP-11 §14 (`SD11-12`, `SD11-12a`, `SD11-12b`), §15 (`SG11-4`), §16
(`GP-AUTO-ST-01` static gates), §2 (`VP11-5`, `VP11-11`).

`SD11-12a` distinguishes three gate classes and forbids conflating them. The spike's
own `ruff`, `mypy --strict`, `pytest` and decode-gate invocations are class *(i)*:
their configured scope is the spike package and its tests, they keep running
unchanged, and they are **not** any GP-AUTO stage's evidence. What this module
configures is class *(ii)* — invocations whose configured scope is the GP-AUTO
package and its tests.

`SD11-12b` is why the scope is read from configuration rather than written into a
test: a gate that reports success while inspecting no GP-AUTO file is a
**verification defect, not coverage**, so each gate must *enumerate the GP-AUTO paths
it inspected* and must be shown to *fail on a deliberately non-conformant GP-AUTO
fixture*. Both halves need the same path list, and the list lives in
`pyproject.toml` under `[tool.gpauto.gates]`.

**Why the fixture is written into the real package directory.** The weaker
construction — a fixture in a directory the gate excludes — proves only that the
*rule* would fire somewhere, not that this gate's *configured scope* contains this
stage's code. Writing the fixture where the stage's own modules live and re-running
the identical command is the only demonstration that answers `SD11-12b`. The fixture
is removed in a `finally`, and `test_ga07` asserts afterwards that none remains, so
it is never stage delta.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

FIXTURE_PREFIX = "_st01_gate_scope_fixture_"
"""Every fixture file this harness writes starts with it, so a stray one is findable."""


def gate_configuration() -> dict[str, object]:
    """`[tool.gpauto.gates]` from `pyproject.toml` — the configured GP-AUTO scope."""
    manifest = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    gates = manifest["tool"]["gpauto"]["gates"]
    assert isinstance(gates, dict)
    return gates


def configured_paths() -> tuple[Path, ...]:
    """The GP-AUTO paths every GP-AUTO gate is configured to inspect."""
    declared = gate_configuration()["paths"]
    assert isinstance(declared, list)
    return tuple(REPOSITORY_ROOT / str(entry) for entry in declared)


def configured_package_path() -> Path:
    """The GP-AUTO package directory — where a production fixture must land."""
    return REPOSITORY_ROOT / str(gate_configuration()["package_path"])


def gpauto_source_files() -> tuple[Path, ...]:
    """Every `.py` file inside the configured GP-AUTO scope, sorted and repo-relative."""
    found: list[Path] = []
    for root in configured_paths():
        found.extend(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)
    return tuple(sorted(path.relative_to(REPOSITORY_ROOT) for path in found))


@contextmanager
def non_conformant_fixture(name: str, source: str) -> Iterator[Path]:
    """Place a deliberately non-conformant module inside the GP-AUTO package.

    Removed in a `finally`, so an assertion failure inside the block still cleans up
    and the fixture never becomes stage delta (`SG11-8`).
    """
    path = configured_package_path() / f"{FIXTURE_PREFIX}{name}.py"
    path.write_text(source, encoding="utf-8")
    try:
        yield path.relative_to(REPOSITORY_ROOT)
    finally:
        path.unlink(missing_ok=True)


def stray_fixtures() -> tuple[Path, ...]:
    """Any fixture file left behind anywhere in the configured scope."""
    found: list[Path] = []
    for root in configured_paths():
        found.extend(root.rglob(f"{FIXTURE_PREFIX}*"))
    return tuple(sorted(path.relative_to(REPOSITORY_ROOT) for path in found))
