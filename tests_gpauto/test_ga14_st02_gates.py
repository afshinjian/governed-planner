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
    stray_fixtures,
)
from gpauto import authority, codec, content_identity, equivalence
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


DIGEST_MODULE = Path("src/gplanner/digest.py")
OBSERVATION_MODULE = Path("src/gpauto/observation.py")
AUTHORIZED_HASHLIB_USES = {
    DIGEST_MODULE: [("sha256", "digest_of_preimage_bytes")],
    OBSERVATION_MODULE: [("sha1", "_index_checksum_holds")],
}
"""Every `hashlib` use in production, as `(attribute, enclosing function)`: SHA-256 once, in
`digest.py` (`SD11-2`); SHA-1 once, in `_index_checksum_holds` (`ST07-OWNER-DECISION-02`)."""

PRIVATE_HASH_MODULES = frozenset({"_hashlib", "_sha1", "_sha2", "_sha256", "_md5", "_blake2"})


def _production_sources() -> dict[Path, str]:
    return {
        path.relative_to(REPOSITORY_ROOT): path.read_text(encoding="utf-8")
        for path in sorted((REPOSITORY_ROOT / "src").rglob("*.py"))
    }


def _hashlib_uses(tree: ast.Module) -> list[tuple[str, str | None]]:
    """Every use of `hashlib` in one module, as `(attribute, enclosing function)`, however it
    is bound. `import hashlib` and `import hashlib as h` bind a name, and each use of that
    name is its attribute — or `<bare>` where the name is used other than as `name.attr`
    (`getattr`, an assignment, an argument). `from hashlib import x [as y]` is `from:x`. A
    `.sha256(...)` call on any other receiver is `sha256` too. (An uncalled `.sha256` on
    another receiver is a data field — in-toto's `digest.sha256` — and a module cannot
    reach `hashlib` through one without a `<bare>` re-binding, itself a use.)"""
    functions: dict[ast.AST, str | None] = {}
    pending: list[tuple[ast.AST, str | None]] = [(tree, None)]
    while pending:
        node, function = pending.pop()
        functions[node] = function
        inner = node.name if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) else function
        pending += [(child, inner) for child in ast.iter_child_nodes(node)]
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    bindings = {
        alias.asname or "hashlib"
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name.split(".")[0] == "hashlib"
    }
    uses: list[tuple[str, str | None]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "hashlib":
            uses += [(f"from:{alias.name}", functions[node]) for alias in node.names]
        elif isinstance(node, ast.Name) and node.id in bindings:
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                uses.append((parent.attr, functions[node]))
            else:
                uses.append(("<bare>", functions[node]))
        elif isinstance(node, ast.Attribute) and node.attr == "sha256":
            bound = isinstance(node.value, ast.Name) and node.value.id in bindings
            call = parents.get(node)
            if not bound and isinstance(call, ast.Call) and call.func is node:
                uses.append(("sha256", functions[node]))
    return sorted(uses, key=lambda use: (use[0], use[1] or ""))


def _sha_confinement_findings(sources: dict[Path, str]) -> list[str]:
    """`SD11-2` with `ST07-OWNER-DECISION-02`, over every production module: each module's
    `hashlib` uses are exactly its authorized ones — none, outside `digest.py` and
    `observation.py` — and no module imports a private hash module."""
    findings: list[str] = []
    sha256_sites: dict[Path, int] = {}
    for path, text in sorted(sources.items()):
        tree = ast.parse(text)
        uses = _hashlib_uses(tree)
        authorized = AUTHORIZED_HASHLIB_USES.get(path, [])
        if uses != authorized:
            findings.append(f"{path.as_posix()}: hashlib uses {uses}, authorized {authorized}")
        sites = [u for u in uses if u[0] in ("sha256", "from:sha256", "new", "<bare>")]
        if sites:
            sha256_sites[path] = len(sites)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                private = {n.split(".")[0] for n in names} & PRIVATE_HASH_MODULES
                findings += [f"{path.as_posix()}: imports {m}" for m in sorted(private)]
    if sha256_sites != {DIGEST_MODULE: 1}:
        findings.append(f"possible SHA-256 sites: {sha256_sites}")
    return findings


def _receiver_named_sha256(sources: dict[Path, str]) -> int:
    """The pre-`ST07-IMPL-R02` predicate: `.sha256` whose receiver is named `hashlib`."""
    return sum(
        1
        for text in sources.values()
        for n in ast.walk(ast.parse(text))
        if isinstance(n, ast.Attribute)
        and n.attr == "sha256"
        and isinstance(n.value, ast.Name)
        and n.value.id == "hashlib"
    )


def _sha_probes(sources: dict[Path, str]) -> dict[str, tuple[Path, str]]:
    """Each a single re-bound or added hash use in one live production module."""
    observed, digest = sources[OBSERVATION_MODULE], sources[DIGEST_MODULE]
    plain = "import hashlib\n"
    assert observed.count(plain) == 1 and digest.count(plain) == 1
    checksum = "hashlib.sha1(body, usedforsecurity=False)"
    assert observed.count(checksum) == 1
    second = "import hashlib\nimport hashlib as _h\n"
    return {
        "aliased_sha256_beside_sha1": (
            OBSERVATION_MODULE,
            observed.replace(plain, second) + '\n_EMPTY = _h.sha256(b"").digest()\n',
        ),
        "aliased_sha256_in_place_of_sha1": (
            OBSERVATION_MODULE,
            observed.replace(plain, "import hashlib as hashes\n").replace(
                checksum, "hashes.sha256(body)"
            ),
        ),
        "aliased_second_sha256_in_digest": (
            DIGEST_MODULE,
            digest.replace(plain, second) + '\n_SECOND = _h.sha256(b"").hexdigest()\n',
        ),
        "aliased_module_rebound": (
            OBSERVATION_MODULE,
            observed + "\n_HASHES = hashlib\n_EMPTY = _HASHES.sha256(b'').digest()\n",
        ),
        "aliased_in_another_module": (
            Path("src/gpauto/probe.py"),
            'import hashlib as h\nDIGEST = h.sha256(b"").hexdigest()\n',
        ),
        "from_import_sha256": (
            OBSERVATION_MODULE,
            observed.replace(plain, plain + "from hashlib import sha256 as _s\n"),
        ),
        "named_constructor": (
            OBSERVATION_MODULE,
            observed.replace(checksum, 'hashlib.new("sha256", body)'),
        ),
        "getattr": (
            OBSERVATION_MODULE,
            observed.replace(checksum, 'getattr(hashlib, "sha256")(body)'),
        ),
        "sha1_outside_the_checksum": (
            OBSERVATION_MODULE,
            observed + '\n_EMPTY = hashlib.sha1(b"", usedforsecurity=False).digest()\n',
        ),
        "private_module": (
            OBSERVATION_MODULE,
            observed.replace(plain, plain + "import _sha2\n"),
        ),
    }


@pytest.mark.traces("ST02-A1", "ID-11", "SD11-1", "SD11-2")
def test_the_repository_has_one_canonicalization_site_and_one_sha256_site() -> None:
    """`ID-11`: JCS in exactly one place; `SD11-2`: `digest.py` the sole SHA-256 site.

    Over every production module in the repository — spike and GP-AUTO alike:

    * exactly one module imports `rfc8785`, and it is `gplanner/canonical.py`;
    * exactly one module imports `hashlib` for identity, and it is `gplanner/digest.py`,
      which calls `sha256` exactly once, and no other module makes any `sha256` call;
    * **no** production module imports `json`, so no hand-rolled `canonical_json` —
      `json.dumps(sort_keys=True)` or anything like it — can exist beside JCS.

    The test trees are verification apparatus (`VP11-12`): the spike's use `rfc8785`
    and `hashlib` as independent oracles, and GP-AUTO's traceability hashes frozen
    planning *documents* to pin them (`TR11-4`). None of them is on any identity path,
    and GP-AUTO's test tree imports no `rfc8785` at all.

    **From `GP-AUTO-ST-07` on** (`ST07-OWNER-DECISION-02 = A`, the authorized bounded
    re-expression): the `hashlib` importers are exactly `gplanner/digest.py` and
    `gpauto/observation.py`. `observation.py` uses `hashlib.sha1` and no other `hashlib`
    attribute — only to verify the Git index's trailing checksum, confined by `test_ga38`'s
    gate — so it adds no content, artifact, record or governance identity, and `digest.py`
    remains the sole SHA-256 content-identity site (`SD11-2`).

    **However `hashlib` is bound** (`ST07-IMPL-R02`): a use is found through every name the
    module is imported or re-bound under, through `from hashlib import …`, through
    `hashlib.new` and through `getattr`, and any `.sha256(...)` call counts whatever its
    receiver. Each module's uses must be exactly its authorized ones — `digest.py`: one
    `sha256`, in `digest_of_preimage_bytes`; `observation.py`: one `sha1`, in
    `_index_checksum_holds`; every other module: none. Each is shown to fail on a probe of
    the live source, the aliased SHA-256 call included, and on a fixture in the package.
    """
    imports = _production_imports()
    assert {path for path, mods in imports.items() if "rfc8785" in mods} == {
        Path("src/gplanner/canonical.py")
    }
    assert {path for path, mods in imports.items() if "hashlib" in mods} == {
        Path("src/gplanner/digest.py"),
        Path("src/gpauto/observation.py"),
    }
    assert {path for path, mods in imports.items() if "json" in mods} == set()

    sources = _production_sources()
    assert _sha_confinement_findings(sources) == []

    # The probes (`ST07-IMPL-R02`): each is the live production source with one hash use
    # added or re-bound, and each must be found. The aliased ones are invisible to a check
    # keyed on the receiver's name being `hashlib` — shown, so the probe is a real one.
    for label, (path, text) in _sha_probes(sources).items():
        probed = {**sources, path: text}
        assert probed != sources, label
        assert _sha_confinement_findings(probed), label
        if label.startswith("aliased_"):
            assert _receiver_named_sha256(probed) == _receiver_named_sha256(sources), label
    alias_fixture = (
        '"""Design basis: AP-11 fixture."""\nimport hashlib as h\n'
        'DIGEST = h.sha256(b"").hexdigest()\n'
    )
    with non_conformant_fixture("sha256_alias", alias_fixture) as fixture:
        findings = _sha_confinement_findings(_production_sources())
    assert [f for f in findings if f.startswith(fixture.as_posix())], findings
    assert not stray_fixtures()

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

    From `GP-AUTO-ST-06` on, `authority.py` imports `canonical_bytes` too — `SD11-16`'s own
    primitive, required by the frozen ST-06 clarification S6G3-6 — under the same rule.
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
        ("authority.py", "gplanner.canonical", "canonical_bytes"),
    }
    assert not [m for _, m in imported_modules() if m == "gplanner" or m == "rfc8785"]

    for module in (content_identity, equivalence, authority):
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
        if path.name in structural.ST04_OPERATION_MODULES:
            continue  # GP-AUTO-ST-04's own operations, pinned by its own gate test
        if path.name in structural.ST05_OPERATION_MODULES:
            continue  # GP-AUTO-ST-05's own operations, pinned by its own gate test
        if path.name in structural.ST06_OPERATION_MODULES:
            continue  # GP-AUTO-ST-06's own operations, pinned by its own gate test
        if path.name in structural.ST08_OPERATION_MODULES:
            continue
        if path.name in structural.ST07_OPERATION_MODULES:
            continue  # GP-AUTO-ST-07's own operations, pinned by its own gate test
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
