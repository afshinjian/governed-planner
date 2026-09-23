"""`SD11-12b`: each GP-AUTO gate enumerates what it inspected and fails on a fixture.

Design basis: AP-11 §14 (`SD11-12a`, `SD11-12b`), §15 (`SG11-4`), §16
(`GP-AUTO-ST-01` static gates, tests and acceptance), §2 (`VP11-5`, `VP11-11`).

*"A stage-local gate that cannot fail on the stage's own code is not a gate."* Three
gates are named by this stage's contract — `ruff`, `mypy --strict`, and the GP-AUTO
decode/import gate — and each is checked twice here:

1. **Scope enumeration.** The gate reports the GP-AUTO paths it inspected, and that
   list is compared against the files actually present in the configured scope. A
   gate that passed while inspecting nothing would fail this comparison, which is the
   verification defect `SD11-12b` names.
2. **Fixture failure.** A deliberately non-conformant GP-AUTO module is written into
   the package directory, the **identical** gate command is re-run, and the gate is
   required to fail and to name that file. The fixture is removed in a `finally`, and
   the last test in this module asserts none remains.

The spike's own gates are class `SD11-12a`(i): they keep running unchanged over the
spike and are not this stage's evidence. Nothing here invokes them, alters them or
reads their results.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import decode_gate
from gate_scope import (
    REPOSITORY_ROOT,
    configured_package_path,
    configured_paths,
    gpauto_source_files,
    non_conformant_fixture,
    stray_fixtures,
)

RUFF_VIOLATION = '''
"""A deliberately non-conformant GP-AUTO module — `ruff` fixture.

Design basis: AP-11 §14 (`SD11-12b`).
"""

from __future__ import annotations

import os


UNUSED_IMPORT_IS_AN_F401_VIOLATION = 1
'''

MYPY_VIOLATION = '''
"""A deliberately non-conformant GP-AUTO module — `mypy --strict` fixture.

Design basis: AP-11 §14 (`SD11-12b`).
"""

from __future__ import annotations

from typing import Any


def untyped_and_any_returning(argument):  # noqa: ANN001, ANN201
    """An untyped signature returning `Any` — exactly what `SD11-12b` names."""
    value: Any = argument
    return value
'''

DECODE_VIOLATION_ALIASED_IMPORT = '''
"""A deliberately non-conformant GP-AUTO module — decode gate fixture.

Design basis: AP-11 §14 (`SD11-12b`); `DC-1`, `DC-2`.
"""

from __future__ import annotations

import json as j

DECODED = j
'''

DECODE_VIOLATION_FROM_IMPORT = '''
"""A deliberately non-conformant GP-AUTO module — decode gate fixture.

Design basis: AP-11 §14 (`SD11-12b`); `DC-1`, `DC-2`.
"""

from __future__ import annotations

from json import loads

DECODER = loads
'''

DECODE_VIOLATION_MODEL_VALIDATE = '''
"""A deliberately non-conformant GP-AUTO module — decode gate fixture.

Design basis: AP-11 §14 (`SD11-12b`); `DC-1`, `DC-2`.
"""

from __future__ import annotations

from gpauto.scope_frame import Project


def _decode(payload: dict[str, object]) -> Project:
    return Project.model_validate(payload)
'''


def run_ruff(paths: tuple[Path, ...]) -> subprocess.CompletedProcess[str]:
    """The GP-AUTO `ruff` gate, exactly as configured (`SD11-12a`(ii))."""
    return subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--no-cache", *(str(p) for p in paths)],
        capture_output=True,
        text=True,
        cwd=REPOSITORY_ROOT,
        check=False,
    )


def run_mypy(
    paths: tuple[Path, ...], cache_dir: Path, report_dir: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """The GP-AUTO `mypy --strict` gate, exactly as configured (`SD11-12a`(ii))."""
    command = [
        sys.executable,
        "-m",
        "mypy",
        "--strict",
        "--no-incremental",
        "--cache-dir",
        str(cache_dir),
    ]
    if report_dir is not None:
        command += ["--linecount-report", str(report_dir)]
    command += [str(p) for p in paths]
    return subprocess.run(
        command, capture_output=True, text=True, cwd=REPOSITORY_ROOT, check=False
    )


# --- The configured scope itself -----------------------------------------------


@pytest.mark.traces("ST01-T4", "ST01-A3")
def test_the_configured_gpauto_scope_is_the_gpauto_paths_and_no_spike_path() -> None:
    """Class `SD11-12a`(ii): scoped to the GP-AUTO package and its tests.

    It names no spike path, so no GP-AUTO gate can be satisfied by the spike passing,
    and no spike gate is re-pointed by anything configured here.
    """
    relative = {path.relative_to(REPOSITORY_ROOT).as_posix() for path in configured_paths()}
    assert relative == {"src/gpauto", "tests_gpauto"}
    assert all("gplanner" not in entry for entry in relative)
    assert configured_package_path().relative_to(REPOSITORY_ROOT).as_posix() == "src/gpauto"


@pytest.mark.traces("ST01-T4")
def test_the_configured_scope_actually_contains_this_stages_code() -> None:
    """The precondition for every enumeration below: there is something to inspect."""
    inspected = gpauto_source_files()
    assert len(inspected) > 20
    assert Path("src/gpauto/identity.py") in inspected
    assert Path("tests_gpauto/test_ga07_gate_scope.py") in inspected


# --- Gate 1: ruff ---------------------------------------------------------------


@pytest.mark.traces("ST01-G1", "ST01-T4")
def test_ruff_enumerates_the_gpauto_paths_it_inspects() -> None:
    """Half one of the scope check, for `ruff`."""
    listed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--no-cache",
            "--show-files",
            *(str(p) for p in configured_paths()),
        ],
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
    assert inspected == set(gpauto_source_files())


@pytest.mark.traces("ST01-G1")
def test_ruff_passes_over_the_gpauto_scope() -> None:
    """The gate's actual result for this stage's code."""
    result = run_ruff(configured_paths())
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.traces("ST01-G1", "ST01-T4")
def test_ruff_fails_on_a_non_conformant_gpauto_fixture() -> None:
    """Half two of the scope check: the identical command, a fixture inside the scope."""
    with non_conformant_fixture("ruff", RUFF_VIOLATION) as fixture:
        result = run_ruff(configured_paths())
        assert result.returncode != 0
        assert fixture.name in result.stdout
        assert "F401" in result.stdout


# --- Gate 2: mypy --strict ------------------------------------------------------


@pytest.mark.traces("ST01-G2", "ST01-T4")
def test_mypy_strict_enumerates_the_gpauto_modules_it_type_checks(tmp_path: Path) -> None:
    """Half one of the scope check, for `mypy --strict`.

    `--linecount-report` names every module mypy actually analysed, which is the
    enumeration `SD11-12b` asks for. It is compared against the files in the
    configured scope, so a run that silently analysed none would be visible.
    """
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    result = run_mypy(configured_paths(), tmp_path / "cache", report_dir)
    assert result.returncode == 0, result.stdout + result.stderr

    reported = {
        line.split()[-1]
        for line in (report_dir / "linecount.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().endswith("total")
    }
    # `src/gpauto` is a package, so its files report as `gpauto.<module>`; the test
    # tree carries no `__init__.py`, so its files report as top-level module names.
    expected: set[str] = set()
    for path in gpauto_source_files():
        stem = path.with_suffix("")
        if path.parts[0] == "src":
            expected.add(stem.as_posix().removeprefix("src/").replace("/", "."))
        else:
            expected.add(stem.name)
    expected = {name.removesuffix(".__init__") for name in expected}

    assert "gpauto.identity" in reported
    assert "test_ga07_gate_scope" in reported
    assert expected <= reported, sorted(expected - reported)


@pytest.mark.traces("ST01-G2", "ST01-T4")
def test_mypy_strict_fails_on_an_untyped_any_returning_gpauto_fixture(tmp_path: Path) -> None:
    """Half two: the exact fixture shape `SD11-12b` names for a type gate."""
    with non_conformant_fixture("mypy", MYPY_VIOLATION) as fixture:
        result = run_mypy(configured_paths(), tmp_path / "cache")
        assert result.returncode != 0
        assert fixture.as_posix() in result.stdout
        assert "no-untyped-def" in result.stdout


# --- Gate 3: the GP-AUTO decode / import gate -----------------------------------


@pytest.mark.traces("ST01-G3", "ST01-T4")
def test_the_decode_gate_enumerates_the_gpauto_paths_it_inspects() -> None:
    """Half one of the scope check, for the decode gate."""
    inspected, _ = decode_gate.offenders()
    assert set(inspected) == set(gpauto_source_files())
    assert Path("src/gpauto/scope_frame.py") in set(inspected)


@pytest.mark.traces("ST01-G3")
def test_the_decode_gate_passes_over_the_gpauto_scope() -> None:
    """At `GP-AUTO-ST-01` the expected number of `json` importers is zero, not one.

    There is no codec yet, so there is nothing to exempt and the gate carries no
    exemption at all.
    """
    _, findings = decode_gate.offenders()
    assert findings == ()


@pytest.mark.parametrize(
    ("label", "source", "expected"),
    [
        ("aliased_import", DECODE_VIOLATION_ALIASED_IMPORT, "imports json"),
        ("from_import", DECODE_VIOLATION_FROM_IMPORT, "from json import"),
        ("model_validate", DECODE_VIOLATION_MODEL_VALIDATE, "model_validate"),
    ],
    ids=["import json as j", "from json import loads", "model_validate"],
)
@pytest.mark.traces("ST01-G3", "ST01-T4")
def test_the_decode_gate_fails_on_each_non_conformant_gpauto_fixture(
    label: str, source: str, expected: str
) -> None:
    """Half two, over all three shapes the frozen rule names.

    `import json as j` and `from json import loads` are both caught because the gate
    keys on imports rather than on call shape — which is the whole reason the frozen
    rule is import-keyed.
    """
    with non_conformant_fixture(f"decode_{label}", source) as fixture:
        _, findings = decode_gate.offenders()
        assert any(fixture.as_posix() in finding for finding in findings), findings
        assert any(expected in finding for finding in findings), findings


@pytest.mark.traces("ST01-G3")
def test_the_decode_gate_exits_non_zero_as_a_standalone_invocation() -> None:
    """The gate is its own invocation (`SD11-12a`(ii)), so its exit status must carry."""
    clean = subprocess.run(
        [sys.executable, str(Path(decode_gate.__file__))],
        capture_output=True,
        text=True,
        cwd=REPOSITORY_ROOT,
        check=False,
    )
    assert clean.returncode == 0, clean.stdout + clean.stderr

    with non_conformant_fixture("decode_standalone", DECODE_VIOLATION_FROM_IMPORT):
        dirty = subprocess.run(
            [sys.executable, str(Path(decode_gate.__file__))],
            capture_output=True,
            text=True,
            cwd=REPOSITORY_ROOT,
            check=False,
        )
    assert dirty.returncode == 1
    assert "FINDINGS:" in dirty.stdout


# --- The fixtures leave nothing behind ------------------------------------------


@pytest.mark.traces("ST01-A5")
def test_no_gate_fixture_is_left_in_the_repository() -> None:
    """A fixture that survived the run would be stage delta, which `SG11-8` excludes."""
    assert stray_fixtures() == ()
