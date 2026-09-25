"""`GP-AUTO-ST-02`'s gates and its repository-level acceptance structure.

Design basis: AP-11 §14 (`SD11-1`, `SD11-2`, `SD11-12a`(ii), `SD11-12b`, `SD11-16`,
`SD11-16a`), §15 (`SG11-11`, `SG11-11a`), §16 (`GP-AUTO-ST-02` static gates and
acceptance; **Gate inheritance**); AP-07 §5.2 (`ID-11`), §23.1 (`DC-1`, `DC-2`,
`DC-5`); `CLAUDE.md`.

**Gate inheritance.** ST-02's static gates are *"as ST-01"* — the GP-AUTO-scoped set
of `SD11-12a`(ii) — with their scope **extended to this stage's new modules** and
`SD11-12b`'s scope check carried forward. ST-01's own gate tests (`test_ga07`) keep
running unchanged; the scope list is read from configuration, so the new modules are
already inside it. What this module adds is the demonstration for **this** stage's
code: each gate names the ST-02 modules among the paths it inspected, and a
deliberately non-conformant fixture shaped like the mistake ST-02 could make — a JSON
decoder outside the codec, untyped — is shown to fail each gate it should.

**Acceptance: one canonicalization and one SHA-256 site in the repository.** Checked
structurally over the repository's production source, so the property is of the
repository and not merely of the new modules.
"""

from __future__ import annotations

import ast
import inspect
import subprocess
import sys
from pathlib import Path

import pytest

import decode_gate
from gate_scope import (
    REPOSITORY_ROOT,
    configured_paths,
    gpauto_source_files,
    non_conformant_fixture,
)
from gpauto import codec, content_identity, equivalence
from introspect import imported_modules, source_files
from test_ga07_gate_scope import run_mypy, run_ruff

GPAUTO_STAGE = "GP-AUTO-ST-02"

ST02_PRODUCTION = (
    Path("src/gpauto/preimage.py"),
    Path("src/gpauto/content_identity.py"),
    Path("src/gpauto/codec.py"),
    Path("src/gpauto/equivalence.py"),
)
ST02_TESTS = (
    Path("tests_gpauto/st02_support.py"),
    Path("tests_gpauto/mutation.py"),
    Path("tests_gpauto/test_ga09_primitive_verification.py"),
    Path("tests_gpauto/test_ga10_content_identity.py"),
    Path("tests_gpauto/test_ga11_codec.py"),
    Path("tests_gpauto/test_ga12_equivalence.py"),
    Path("tests_gpauto/test_ga13_mutation.py"),
    Path("tests_gpauto/test_ga14_st02_gates.py"),
    Path("tests_gpauto/test_ga15_st02_traceability.py"),
)

DECODER_OUTSIDE_THE_CODEC = '''
"""A deliberately non-conformant GP-AUTO module — a JSON decoder outside the codec.

Design basis: AP-11 §14 (`SD11-12b`); `DC-1`, `DC-2`.
"""

from __future__ import annotations

from gpauto.scope_frame import Project


def decode_project(payload):  # noqa: ANN001, ANN201
    return Project.model_validate_json(payload)
'''

TYPE_ADAPTER_DECODER = '''
"""A deliberately non-conformant GP-AUTO module — a JSON path that is not the codec's.

Design basis: AP-11 §14 (`SD11-12b`); `DC-1`.
"""

from __future__ import annotations

from pydantic import TypeAdapter

from gpauto.scope_frame import Project

DECODED = TypeAdapter(Project).validate_json(b"{}")
'''


def _json_import_fixture(body: str) -> str:
    """A GP-AUTO-shaped module whose only non-conformance is one `json`-rooted import."""
    return (
        chr(34) * 3
        + "A deliberately non-conformant GP-AUTO module - a `json`-rooted import."
        + chr(10) * 2
        + "Design basis: AP-11 ss14 (`SD11-12b`); `DC-1`, `DC-2`."
        + chr(34) * 3
        + chr(10) * 2
        + "from __future__ import annotations"
        + chr(10) * 2
        + body
        + chr(10)
    )


JSON_ROOTED_IMPORTS: tuple[tuple[str, str, str], ...] = (
    ("plain", "import json", "imports json"),
    ("aliased", "import json as j", "imports json"),
    ("submodule", "import json.decoder", "imports json.decoder"),
    ("submodule_aliased", "import json.decoder as jd", "imports json.decoder"),
    ("from_package", "from json import loads", "from json import"),
    ("from_submodule", "from json.decoder import JSONDecoder", "from json.decoder import"),
    (
        "from_submodule_aliased",
        "from json.decoder import JSONDecoder as JD",
        "from json.decoder import",
    ),
    ("from_encoder", "from json.encoder import JSONEncoder", "from json.encoder import"),
    ("nested_alias", "import json.encoder as encoder_module", "imports json.encoder"),
)
"""Every spelling by which the `json` package could be reached, and what the gate says.

`from json.decoder import JSONDecoder` is the one the gate previously missed: it reaches
the same decoder the frozen rule keeps behind one boundary, while naming a module the
old `== "json"` test did not match.
"""


# --- SD11-12b, half one: each gate enumerates this stage's modules ---------------


@pytest.mark.traces("ST02-G1")
def test_ruff_inspects_every_st02_module() -> None:
    """`ruff --show-files` over the configured scope lists each ST-02 file."""
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
    assert set(ST02_PRODUCTION + ST02_TESTS) <= inspected
    assert run_ruff(configured_paths()).returncode == 0


@pytest.mark.traces("ST02-G2")
def test_mypy_strict_type_checks_every_st02_module(tmp_path: Path) -> None:
    """`--linecount-report` names every module mypy analysed; each ST-02 one is there."""
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    result = run_mypy(configured_paths(), tmp_path / "cache", report_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    reported = {
        line.split()[-1]
        for line in (report_dir / "linecount.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().endswith("total")
    }
    expected = {f"gpauto.{path.stem}" for path in ST02_PRODUCTION} | {
        path.stem for path in ST02_TESTS
    }
    assert expected <= reported, sorted(expected - reported)


@pytest.mark.traces("ST02-G3")
def test_the_decode_gate_inspects_every_st02_module() -> None:
    """The decode/import gate's own enumeration includes the codec it now keys on."""
    inspected, findings = decode_gate.offenders()
    assert set(ST02_PRODUCTION + ST02_TESTS) <= set(inspected)
    assert set(inspected) == set(gpauto_source_files())
    assert findings == ()


# --- SD11-12b, half two: a non-conformant ST-02-shaped fixture fails -------------


@pytest.mark.traces("ST02-G3", "DC-1")
def test_the_decode_gate_fails_on_a_json_decoder_outside_the_codec() -> None:
    """The rule that makes the gate load-bearing, shown to fire inside the package."""
    with non_conformant_fixture("st02_decoder", DECODER_OUTSIDE_THE_CODEC) as fixture:
        _, findings = decode_gate.offenders()
    assert any(
        fixture.as_posix() in finding and "JSON decode outside the codec" in finding
        for finding in findings
    ), findings


@pytest.mark.traces("ST02-G3", "DC-1")
def test_the_decode_gate_fails_on_a_json_path_that_is_not_model_validate_json() -> None:
    """`DC-1`: `model_validate_json` is the only JSON → domain path — so not `validate_json`."""
    with non_conformant_fixture("st02_type_adapter", TYPE_ADAPTER_DECODER) as fixture:
        _, findings = decode_gate.offenders()
    assert any(
        fixture.as_posix() in finding and "validate_json" in finding for finding in findings
    ), findings


@pytest.mark.traces("ST02-G2", "ST02-G1")
def test_mypy_strict_and_ruff_fail_on_the_same_st02_shaped_fixture(tmp_path: Path) -> None:
    """The untyped decoder fails `mypy --strict`; an unused import in it fails `ruff`."""
    with non_conformant_fixture("st02_decoder", DECODER_OUTSIDE_THE_CODEC) as fixture:
        typed = run_mypy(configured_paths(), tmp_path / "cache")
    assert typed.returncode != 0
    assert fixture.as_posix() in typed.stdout
    assert "no-untyped-def" in typed.stdout

    linted_source = DECODER_OUTSIDE_THE_CODEC.replace(
        "from __future__ import annotations\n", "from __future__ import annotations\n\nimport os\n"
    )
    with non_conformant_fixture("st02_lint", linted_source) as fixture:
        linted = run_ruff(configured_paths())
    assert linted.returncode != 0
    assert fixture.name in linted.stdout


# --- Acceptance: one canonicalization, one SHA-256 site ------------------------


def _production_imports() -> dict[Path, set[str]]:
    """`file -> imported top-level modules`, over the repository's production source."""
    found: dict[Path, set[str]] = {}
    for path in sorted((REPOSITORY_ROOT / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                modules.add((node.module or "").split(".")[0])
        found[path.relative_to(REPOSITORY_ROOT)] = modules
    return found


@pytest.mark.traces("ST02-A1", "ID-11", "SD11-1", "SD11-2")
def test_the_repository_has_one_canonicalization_site_and_one_sha256_site() -> None:
    """`ID-11`: JCS in exactly one place; `SD11-2`: `digest.py` the sole SHA-256 site.

    Over every production module in the repository — spike and GP-AUTO alike:

    * exactly one module imports `rfc8785`, and it is `gplanner/canonical.py`;
    * exactly one module imports `hashlib`, and it is `gplanner/digest.py`, which
      calls `sha256` exactly once;
    * **no** production module imports `json`, so no hand-rolled `canonical_json` —
      `json.dumps(sort_keys=True)` or anything like it — can exist beside JCS.

    The test trees are verification apparatus (`VP11-12`): the spike's use `rfc8785`
    and `hashlib` as independent oracles, and GP-AUTO's traceability hashes frozen
    planning *documents* to pin them (`TR11-4`). None of them is on any identity path,
    and GP-AUTO's test tree imports no `rfc8785` at all.
    """
    imports = _production_imports()
    assert {path for path, mods in imports.items() if "rfc8785" in mods} == {
        Path("src/gplanner/canonical.py")
    }
    assert {path for path, mods in imports.items() if "hashlib" in mods} == {
        Path("src/gplanner/digest.py")
    }
    assert {path for path, mods in imports.items() if "json" in mods} == set()

    digest_tree = ast.parse((REPOSITORY_ROOT / "src/gplanner/digest.py").read_text("utf-8"))
    sha256_calls = [
        node
        for node in ast.walk(digest_tree)
        if isinstance(node, ast.Attribute) and node.attr == "sha256"
    ]
    assert len(sha256_calls) == 1

    gpauto_test_modules = {
        module.split(".")[0]
        for path in (REPOSITORY_ROOT / "tests_gpauto").glob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Import | ast.ImportFrom)
        for module in (
            [alias.name for alias in node.names]
            if isinstance(node, ast.Import)
            else [node.module or ""]
        )
    }
    assert "rfc8785" not in gpauto_test_modules


@pytest.mark.traces("ST02-A5", "SD11-16", "SD11-1", "SD11-2")
def test_gpauto_imports_exactly_the_two_authorized_primitives_by_name() -> None:
    """`SD11-16`, `SD11-16a`: `canonical_bytes` and `digest_of_preimage_bytes`, nothing else.

    Imported, not modified, subclassed, wrapped or re-exported: neither name is in any
    GP-AUTO module's public surface other than as the import itself, and no other
    spike module is reached — not the error module, not the payload profile, not the
    spike's own codec. The test tree reaches the same two modules only.
    """
    imported_names: set[tuple[str, str, str]] = set()
    for path in source_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("gplanner"):
                imported_names.update((path.name, node.module or "", a.name) for a in node.names)
    assert imported_names == {
        ("content_identity.py", "gplanner.canonical", "canonical_bytes"),
        ("content_identity.py", "gplanner.digest", "digest_of_preimage_bytes"),
        ("equivalence.py", "gplanner.canonical", "canonical_bytes"),
    }
    assert not [m for _, m in imported_modules() if m == "gplanner" or m == "rfc8785"]

    for module in (content_identity, equivalence):
        public = getattr(module, "__all__", None)
        assert public is None, "no re-export surface is declared"

    test_tree_spike_imports = set()
    for path in (REPOSITORY_ROOT / "tests_gpauto").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("gplanner"):
                test_tree_spike_imports.add(node.module)
    assert test_tree_spike_imports == {"gplanner.canonical", "gplanner.digest"}


ST02_OPERATIONS = {
    "content_identity.py": [
        "_preimage_rehashes_to_identity",
        "_preimage_rehashes_to_identity",
        "artifact_content_identity",
        "artifact_content_preimage",
        "identify_artifact_content",
        "identify_stage_contract",
        "stage_contract_identity",
        "stage_contract_preimage",
    ],
    "codec.py": [
        "decode_artifact_content",
        "decode_authorization_record",
        "decode_stage_contract",
    ],
    "equivalence.py": [
        "_compare_projections",
        "_normal_form",
        "_normalize",
        "_normalize_model",
        "_representable",
        "compare_encoded_records",
        "compare_records",
    ],
}
"""Every function ST-02 declares, by module. Nothing else is declared anywhere."""

SELECTION_WORDS = (
    "rank", "order", "prefer", "select", "choose", "pick", "latest", "newest", "merge",
    "union", "intersect", "reconcile", "resolve", "winner", "best", "max", "min", "sort",
    "revive", "reset", "reopen",
)


@pytest.mark.supports("EQ-7")
@pytest.mark.traces("EQ-10", "ST02-D2")
def test_st02_declares_exactly_its_operations_and_none_selects_or_orders() -> None:
    """AP-03 §4.5 — *the absence is the model* — carried into the first operations.

    ST-02's functions are pinned by name. None is an ordering, ranking, preference,
    merge, union, reconciliation, resolution or selection; no lambda exists; and each
    comparison takes exactly two records and returns an outcome — never one of its
    inputs, and never a key, digest or normal form (`EQ-7`, `EQ-10`).
    """
    import test_ga06_structural as structural

    declared: dict[str, list[str]] = {}
    for path in source_files():
        if path.name in structural.ST03_OPERATION_MODULES:
            continue  # GP-AUTO-ST-03's own operations, pinned by its own gate test
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Lambda):
                declared.setdefault(path.name, []).append("<lambda>")
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                declared.setdefault(path.name, []).append(node.name)
    assert {name: sorted(functions) for name, functions in declared.items()} == ST02_OPERATIONS

    for functions in ST02_OPERATIONS.values():
        for name in functions:
            assert not [word for word in SELECTION_WORDS if word in name.lower()], name

    for function in (equivalence.compare_records, equivalence.compare_encoded_records):
        assert list(inspect.signature(function).parameters) == ["first", "second"]
    for name in ST02_OPERATIONS["codec.py"]:
        assert list(inspect.signature(getattr(codec, name)).parameters) in (
            ["preimage"],
            ["payload"],
        ), name


@pytest.mark.traces("DC-5", "ST02-A5")
def test_the_st02_modules_carry_no_provider_surface() -> None:
    """`DC-5`, `SG11-11`, `SG11-11a`: no LLM call, SDK or prompt, on any surface.

    ST-01's provider gates scan the whole package and test tree and so already cover
    these modules; this names them, so the claim for ST-02's own code is explicit.
    """
    import test_ga06_structural as structural

    for path in ST02_PRODUCTION + ST02_TESTS:
        tree = ast.parse((REPOSITORY_ROOT / path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                roots = {(node.module or "").split(".")[0]}
            else:
                continue
            assert not roots & structural.PROVIDER_SDK_MODULES, path
    structural.test_no_provider_sdk_is_imported_anywhere_in_gp_auto()
    structural.test_no_prompt_or_provider_identifier_appears_in_gp_auto()
    structural.test_the_project_declares_no_provider_sdk_dependency()


# --- GA02-R03: the decode/import gate keys on the import root --------------------


@pytest.mark.traces("ST02-G3", "DC-2")
@pytest.mark.parametrize(
    ("label", "statement", "expected"), JSON_ROOTED_IMPORTS, ids=lambda case: str(case)[:28]
)
def test_the_decode_gate_fails_on_every_json_rooted_import(
    label: str, statement: str, expected: str
) -> None:
    """`DC-2`: the single decode boundary has no side door.

    `json` is a package. A gate matching only the module name would let
    `from json.decoder import JSONDecoder` through — a submodule import that reaches the
    decoder the boundary exists to contain. Each spelling is written into the package
    itself and the identical gate is re-run, so this is the configured scope firing and
    not a rule tested in the abstract (`SD11-12b`).
    """
    with non_conformant_fixture(f"st02_json_{label}", _json_import_fixture(statement)) as fixture:
        _, findings = decode_gate.offenders()
    assert any(
        fixture.as_posix() in finding and expected in finding for finding in findings
    ), (label, findings)


@pytest.mark.traces("ST02-G3", "DC-2")
def test_the_import_root_rule_is_keyed_on_the_package_not_on_a_spelling() -> None:
    """Import-keyed, so a submodule nobody anticipated is covered by the same rule.

    The dot is what makes a name a submodule: `jsonschema` and `myjson` are different
    packages and are not findings, while any depth under `json.` is.
    """
    for rooted in ("json", "json.decoder", "json.encoder", "json.scanner", "json.a.b.c"):
        assert decode_gate.rooted_in_json(rooted), rooted
    for unrelated in ("jsonschema", "jsonschema.validators", "myjson", "ujson", "simplejson", ""):
        assert not decode_gate.rooted_in_json(unrelated), unrelated


@pytest.mark.traces("ST02-G3")
def test_a_relative_import_of_a_local_module_named_json_is_not_the_stdlib_package() -> None:
    """Only absolute imports match: `from .json import x` names a different module.

    The GP-AUTO package contains no such module, so this changes no finding today. It is
    asserted so the rule says what it means rather than matching on a name.
    """
    with non_conformant_fixture(
        "st02_relative_json", _json_import_fixture("from .json import loads")
    ) as fixture:
        _, findings = decode_gate.offenders()
    assert not any(fixture.as_posix() in finding for finding in findings), findings


@pytest.mark.traces("ST02-G3")
def test_the_gate_still_reports_no_finding_over_the_real_package() -> None:
    """The codec needs no exemption: `model_validate_json` takes bytes, so it imports none.

    Nothing in the correction relaxed a rule to make the codec pass — the expected number
    of `json` importers is still zero, in the package and in the test tree alike.
    """
    inspected, findings = decode_gate.offenders()
    assert findings == ()
    assert Path("src/gpauto/codec.py") in set(inspected)
