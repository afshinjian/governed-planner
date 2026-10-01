"""`GP-AUTO-ST-07`: its static gates, its dynamic read-only gate, its boundaries, its rows.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §13 (`EV11-6`), §14 (`SD11-2`, `SD11-12a`(ii),
`SD11-12b`), §15 (`SG11-11`, `SG11-11a`), §16 (`GP-AUTO-ST-07` Static gates: *"As ST-06,
plus: no write-side Git call site exists"* `GV11-1`; Negative tests `AV11-6`); AP-09 `GR9-4`,
`GR9-5`, `GR9-7`, `OB9-8`; OWNER decision `ST07-OWNER-DECISION-02 = A`; CLAUDE.md amendment
part 3; plan §15, §17, §20.

Gates: each GP-AUTO gate enumerates the ST-07 files and passes over them; the observation
surface has no write-side or executing call site (`GV11-1`); SHA-1 is confined to the index
checksum. Each gate is also shown to fail on a non-conformant fixture written into the
package and removed afterwards (`SD11-12b`). Dynamically, an audit hook sees every open the
observation makes — read-only and no-follow — and no write, exec or spawn; a repository
snapshot is byte-, mode- and timestamp-identical afterwards; no hook, filter, `textconv`,
`fsmonitor`, pager or alias runs. Traceability: ST-07's rows come from the frozen artifacts,
digest-verified; each is discharged by ST-07's evidence or owed by a named later stage, and
nothing owed elsewhere moved.
"""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

import decode_gate
import st07_world as x
import traceability
from gate_scope import REPOSITORY_ROOT, configured_paths, non_conformant_fixture, stray_fixtures
from gpauto import observation
from gpauto.coordination_records import EntryStateBoundaryRecord, M2PositionEntry
from gpauto.observation import Determinate, Fixed, NotFixed, Replayed
from gpauto.store import CoordinationStore
from gpauto.store_schema import SCHEMA_VERSION, build_catalogue, schema_statements
from introspect import source_files
from st03_world import fresh_store
from test_ga06_structural import PROMPT_WORDS, PROVIDER_SDK_MODULES
from test_ga07_gate_scope import run_mypy, run_ruff
from test_ga17_st03_store import PINNED_SCHEMA_DIGEST
from traceability import DISCHARGED, OWED_BY, UNDISCHARGED

GPAUTO_STAGE = "GP-AUTO-ST-07"

ST07_PRODUCTION = (Path("src/gpauto/observation.py"),)
ST07_TESTS = (
    Path("tests_gpauto/st07_world.py"),
    Path("tests_gpauto/test_ga34_st07_subjects.py"),
    Path("tests_gpauto/test_ga35_st07_coherence_and_defeat.py"),
    Path("tests_gpauto/test_ga36_st07_entry_boundary.py"),
    Path("tests_gpauto/test_ga37_st07_restart_and_mutation.py"),
    Path("tests_gpauto/test_ga38_st07_gates_and_traceability.py"),
)

ST07_OPERATIONS = [
    "_content", "_decoded", "_entry", "_flags", "_index", "_index_checksum_holds",
    "_index_elements", "_internal", "_item", "_kind", "_line", "_list_dir", "_lstat",
    "_mode_supported", "_object_id", "_offset", "_open", "_packed", "_parent", "_parsed",
    "_read_link", "_read_regular", "_readable", "_recorded", "_ref_name_valid", "_refs",
    "_round", "_settings", "_stable", "_stat", "_step", "_symbolic_branch", "_take", "_truth",
    "_value", "_walk",
    "bound_referents", "boundary_facts", "entry_facts", "fix_entry_boundary", "fixable",
    "list_dir", "list_dir", "lstat", "lstat", "observe", "read_link", "read_link",
    "read_regular", "read_regular", "write_domain_exclusive",
]  # fmt: skip
"""Every function ST-07 declares. The four reader methods appear twice: the `Reader` protocol
and the production `FilesystemReader`."""

FORBIDDEN_OPERATION_WORDS = (
    "move", "replace", "reobserve", "refresh", "update", "delete", "remove", "transfer",
    "edit", "retry", "latest", "newest", "prefer", "splice", "merge", "clean", "normal",
    "stash", "reset", "rebind", "attribut", "classif", "drift", "dispatch", "halt", "adopt",
    "mirror", "package", "route",
)  # fmt: skip
"""Nothing here moves, replaces or re-observes a boundary, retries, picks a latest value,
splices or cleans; and nothing here is ST-08's or later (attribution, classification,
dispatch, halting, adoption)."""

ORDERINGS = {
    ("_list_dir", "sorted"): "a directory's names in raw byte order: the walk's inert order",
    ("_index_elements", "sorted"): "index elements in raw path order (plan §6.3), inert",
    ("observe", "sorted"): "working-tree elements in raw path order (plan §6.3), inert",
    ("_entry", "min"): "arithmetic: the name-length field's 12-bit cap, not an ordering",
}
"""Every ordering call in `observation.py`. None selects among values: each fixes an inert
presentation order that no guard, key or derivation reads (as ST-06 `S6G3-6`)."""

ALLOWED_GPAUTO_IMPORTS = {
    "absence", "authority", "content_identity", "coordination_identity",
    "coordination_records", "coordination_vocabulary", "derivations", "identity", "minting",
    "repository", "scope_frame", "state_machine", "state_machine_model", "store",
}  # fmt: skip
"""ST-01 … ST-06 modules, and nothing later: ST-07 attributes, classifies, dispatches and
halts nothing (AP-11 §16 ST-07 Non-goals)."""

ALLOWED_STDLIB_IMPORTS = {
    "__future__", "dataclasses", "enum", "typing", "hashlib", "os", "stat", "struct",
}  # fmt: skip
"""Plan §15: the observation's whole standard-library surface."""

READ_SIDE_OS = {
    "open", "close", "read", "fstat", "lstat", "readlink", "scandir", "fsencode",
    "stat_result", "O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_DIRECTORY",
}  # fmt: skip
"""`GV11-1`: every `os` attribute the observation surface may name. Nothing that writes,
renames, removes, creates, changes a mode or a time, links, executes or spawns."""

HASH_MODULES = {
    "hashlib", "zlib", "binascii", "hmac", "_hashlib", "_sha1", "_sha2", "_md5", "_blake2",
    "Crypto", "cryptography",
}  # fmt: skip
SHA1_CONSTANTS = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0x5A827999, 0x6ED9EBA1,
    0x8F1BBCDC, 0xCA62C1D6, 0xFFFFFFFF,
}  # fmt: skip
"""SHA-1's initial values, round constants and the 32-bit mask a hand-written SHA-1 needs."""

WRITTEN_BY_ST07 = {"EntryStateBoundaryRecord", "M2PositionEntry"}

FORBIDDEN_AUDIT_EVENTS = (
    "os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.chmod", "os.chown", "os.utime",
    "os.truncate", "os.link", "os.symlink", "os.system", "os.exec", "os.posix_spawn",
    "os.spawn", "os.fork", "os.forkpty", "os.kill", "subprocess.Popen", "shutil.copyfile",
    "shutil.copymode", "shutil.copystat", "shutil.move", "shutil.rmtree", "os.chflags",
    "os.setxattr", "os.removexattr", "os.startfile", "pty.spawn", "ctypes.dlopen",
)  # fmt: skip


def _tree() -> ast.Module:
    return ast.parse((REPOSITORY_ROOT / ST07_PRODUCTION[0]).read_text(encoding="utf-8"))


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _function_of(tree: ast.Module, node: ast.AST) -> str | None:
    line = getattr(node, "lineno", 0)
    inner = [
        f
        for f in ast.walk(tree)
        if isinstance(f, ast.FunctionDef) and f.lineno <= line <= (f.end_lineno or 0)
    ]
    return max(inner, key=lambda f: f.lineno).name if inner else None


# --- gate scope (SD11-12b) -------------------------------------------------------------------


@pytest.mark.traces("ST07-G1")
def test_ruff_inspects_every_st07_module_and_passes() -> None:
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
    assert set(ST07_PRODUCTION + ST07_TESTS) <= inspected
    result = run_ruff(configured_paths())
    assert result.returncode == 0, result.stdout


@pytest.mark.traces("ST07-G1")
def test_mypy_strict_type_checks_every_st07_module(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    result = run_mypy(configured_paths(), tmp_path / "cache", report_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    reported = {
        line.split()[-1]
        for line in (report_dir / "linecount.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().endswith("total")
    }
    expected = {f"gpauto.{p.stem}" for p in ST07_PRODUCTION} | {p.stem for p in ST07_TESTS}
    assert expected <= reported, sorted(expected - reported)


@pytest.mark.traces("ST07-G1")
def test_the_decode_gate_inspects_every_st07_module_and_finds_nothing() -> None:
    inspected, findings = decode_gate.offenders()
    assert set(ST07_PRODUCTION + ST07_TESTS) <= set(inspected)
    assert findings == ()


# --- operations and boundaries -----------------------------------------------------------------


@pytest.mark.traces("ST07-G1", "ST07-N8", "AP03-I08", "RS7-4")
def test_st07_declares_exactly_its_operations_and_none_moves_or_replaces_a_boundary() -> None:
    """ST-07's functions are pinned by name, all in `observation.py`. None re-observes,
    replaces, moves, refreshes, retries, splices or cleans; none is ST-08's or later's; no
    lambda exists; and no function takes a boundary at all, so none can yield another from
    one (`AV11-14`, `RS7-4`, `AP03-I08`)."""
    tree = _tree()
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    assert sorted(f.name for f in functions) == sorted(ST07_OPERATIONS)
    for function in functions:
        name = function.name.lower()
        assert not [w for w in FORBIDDEN_OPERATION_WORDS if w in name], function.name
        for argument in function.args.args:
            annotation = ast.unparse(argument.annotation) if argument.annotation else ""
            assert "EntryStateBoundary" not in annotation, (function.name, annotation)
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Lambda | ast.AsyncFunctionDef)]


@pytest.mark.traces("ST07-G1")
def test_every_ordering_is_inert() -> None:
    """Every `sorted`, `min`, `max` or `reversed` call is one of `ORDERINGS`; nothing sorts in
    place or defines an ordering operator."""
    tree = _tree()
    found = {
        (_function_of(tree, n), n.func.id)
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id in ("sorted", "min", "max", "reversed")
    }
    assert found == set(ORDERINGS), found ^ set(ORDERINGS)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr not in ("sort", "__lt__", "__le__", "__gt__", "__ge__")


def _surface_findings(tree: ast.Module) -> list[str]:
    """`GV11-1` over one module: no import beyond the allowlists, no `os` attribute beyond the
    read side, no builtin `open`, `exec`, `eval` or `__import__`, no `git` executable literal
    and no reflog path."""
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_STDLIB_IMPORTS:
                    findings.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "gpauto":
                bad = {a.name for a in node.names} - ALLOWED_GPAUTO_IMPORTS
                findings += [f"from gpauto import {name}" for name in sorted(bad)]
            elif module.startswith("gpauto."):
                if module.split(".", 1)[1] not in ALLOWED_GPAUTO_IMPORTS:
                    findings.append(f"from {module}")
            elif module not in ALLOWED_STDLIB_IMPORTS:
                findings.append(f"from {module}")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr not in READ_SIDE_OS:
                findings.append(f"os.{node.attr}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("open", "exec", "eval", "__import__", "compile"):
                findings.append(f"{node.func.id}()")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            text = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
            if text in ("git", "git.exe") or "logs/" in text or text == "logs":
                findings.append(f"literal {text!r}")
    return findings


@pytest.mark.traces("ST07-G1", "ST07-N1", "ST07-N2", "GR9-4", "GR9-5")
def test_the_observation_surface_has_no_write_side_or_executing_call_site() -> None:
    """`GV11-1`, observation surface: no subprocess, `os.system`, `os.exec*`, `os.spawn*`,
    `pty`, `multiprocessing` or `shutil`; no write-side `os` call; no builtin `open`; no `git`
    executable literal; no clock or randomness; no reflog read (`OB9-3`). The gate enumerates
    the file it inspected and fails on a non-conformant fixture in the package."""
    assert _surface_findings(_tree()) == []
    for label, source in (
        ("subprocess", "import subprocess\nsubprocess.run(['git', 'status'])\n"),
        ("os_write", "import os\nos.remove('index')\n"),
        ("os_system", "import os\nos.system('git gc')\n"),
        ("builtin_open", "handle = open('index', 'wb')\n"),
        ("clock", "import time\nnow = time.time()\n"),
        ("reflog", "path = b'.git/logs/HEAD'\n"),
        ("later_stage", "from gpauto import attribution\n"),
    ):
        with non_conformant_fixture(f"st07_gv11_{label}", f'"""Fixture."""\n{source}') as path:
            tree = ast.parse((REPOSITORY_ROOT / path).read_text(encoding="utf-8"))
            assert _surface_findings(tree), label
    assert not stray_fixtures()


# --- SHA-1 confinement (ST07-OWNER-DECISION-02) --------------------------------------------------


def _sha1_findings(tree: ast.Module) -> list[str]:
    """`hashlib` imported once, plainly; referenced once, as `hashlib.sha1(...)`, inside
    `_index_checksum_holds`; that function annotated `-> bool` over `(body, trailer)` and
    returning only `<digest> == trailer`; the digest bound to no name; one caller, `_index`;
    and no hand-written hash."""
    findings: list[str] = []
    parents = _parents(tree)
    plain = [
        a for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
        if a.name == "hashlib"
    ]  # fmt: skip
    if len(plain) != 1 or plain[0].asname is not None:
        findings.append("hashlib is not imported exactly once, without an alias")
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in HASH_MODULES:
            findings.append(f"from {node.module} import …")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in HASH_MODULES - {"hashlib"}:
                    findings.append(f"import {alias.name}")
    references = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "hashlib"]
    if len(references) != 1:
        findings.append(f"hashlib referenced {len(references)} times")
    for reference in references:
        attribute = parents.get(reference)
        call = parents.get(attribute) if attribute is not None else None
        if not (
            isinstance(attribute, ast.Attribute)
            and attribute.attr == "sha1"
            and isinstance(call, ast.Call)
            and call.func is attribute
        ):
            findings.append("hashlib used other than as one hashlib.sha1(...) call")
        if _function_of(tree, reference) != "_index_checksum_holds":
            findings.append("hashlib.sha1 outside _index_checksum_holds")
    holds = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_index_checksum_holds"
    ]  # fmt: skip
    if len(holds) != 1:
        return [*findings, "no single _index_checksum_holds"]
    (function,) = holds
    returns = ast.unparse(function.returns) if function.returns else ""
    if returns != "bool":
        findings.append("_index_checksum_holds is not annotated -> bool")
    if [a.arg for a in function.args.args] != ["body", "trailer"]:
        findings.append("_index_checksum_holds is not (body, trailer)")
    statements = [
        s for s in function.body
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
    ]  # fmt: skip
    expected = "hashlib.sha1(body, usedforsecurity=False).digest() == trailer"
    shaped = (
        len(statements) == 1
        and isinstance(statements[0], ast.Return)
        and statements[0].value is not None
        and ast.unparse(statements[0].value) == expected
    )
    if not shaped:
        findings.append("_index_checksum_holds returns other than digest == trailer")
    if [n for n in ast.walk(function) if isinstance(n, ast.Assign | ast.AnnAssign | ast.NamedExpr)]:
        findings.append("the digest flows to a name")
    callers = [
        _function_of(tree, n)
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "_index_checksum_holds"
    ]
    if callers != ["_index"]:
        findings.append(f"_index_checksum_holds callers: {callers}")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and any(
            w in node.name.lower() for w in ("sha", "digest", "hash")
        ):
            findings.append(f"a hash-named function: {node.name}")
        if isinstance(node, ast.Constant) and node.value in SHA1_CONSTANTS:
            if isinstance(node.value, int) and not isinstance(node.value, bool):
                findings.append(f"a SHA-1 constant: {node.value:#x}")
    return findings


def _hash_importers() -> set[str]:
    """Every GP-AUTO production file importing any hash primitive."""
    found: set[str] = set()
    for path in source_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                roots = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                roots = {(node.module or "").split(".")[0]}
            else:
                continue
            if roots & HASH_MODULES:
                found.add(path.name)
    return found


CONFORMANT_SHA1 = '''"""Design basis: AP-11 §16 GP-AUTO-ST-07 confinement-gate fixture."""
import hashlib


def _index_checksum_holds(body: bytes, trailer: bytes) -> bool:
    return hashlib.sha1(body, usedforsecurity=False).digest() == trailer


def _index(body: bytes, trailer: bytes) -> bool:
    return _index_checksum_holds(body, trailer)
'''

SHA1_VIOLATIONS = {
    "from_import": CONFORMANT_SHA1.replace("import hashlib", "from hashlib import sha1"),
    "alias": CONFORMANT_SHA1.replace("import hashlib", "import hashlib as h").replace(
        "hashlib.sha1", "h.sha1"
    ),
    "sha256": CONFORMANT_SHA1.replace("hashlib.sha1(", "hashlib.sha256("),
    "second_use": CONFORMANT_SHA1 + "\nEMPTY = hashlib.sha1(b'').hexdigest()\n",
    "digest_named": CONFORMANT_SHA1.replace(
        "    return hashlib.sha1(body, usedforsecurity=False).digest() == trailer",
        "    digest = hashlib.sha1(body, usedforsecurity=False).digest()\n"
        "    return digest == trailer",
    ),
    "digest_returned": CONFORMANT_SHA1.replace(
        "trailer: bytes) -> bool:\n    return hashlib.sha1(body, usedforsecurity=False).digest()"
        " == trailer",
        "trailer: bytes) -> bytes:\n    return hashlib.sha1(body, usedforsecurity=False).digest()",
    ),
    "second_caller": CONFORMANT_SHA1
    + "\n\ndef _other(body: bytes) -> bool:\n    return _index_checksum_holds(body, body)\n",
    "hand_written": CONFORMANT_SHA1
    + "\n\ndef _rounds(word: int) -> int:\n    return (word + 0x67452301) & 0xFFFFFFFF\n",
    "hash_function": CONFORMANT_SHA1
    + "\n\ndef _sha1_block(data: bytes) -> bytes:\n    return data\n",
}


@pytest.mark.traces("ST07-G1", "OB9-9b")
def test_sha1_is_confined_to_the_index_checksum_and_no_other_module_hashes() -> None:
    """`ST07-OWNER-DECISION-02 = A`: `observation.py` makes exactly one `hashlib.sha1` call,
    inside `_index_checksum_holds`, which answers only whether the checksum holds; the digest
    is returned, stored and named nowhere; `_index` is its one caller; nothing implements a
    hash by hand; and no other GP-AUTO production module imports any hash primitive —
    `digest.py` stays the sole SHA-256 content-identity site. Every assertion fails on its
    own non-conformant fixture, written into the package and removed afterwards."""
    assert _sha1_findings(_tree()) == []
    assert _hash_importers() == {"observation.py"}
    with non_conformant_fixture("st07_sha1_conformant", CONFORMANT_SHA1) as path:
        assert _sha1_findings(ast.parse((REPOSITORY_ROOT / path).read_text("utf-8"))) == []
    for label, source in SHA1_VIOLATIONS.items():
        assert source != CONFORMANT_SHA1, label
        with non_conformant_fixture(f"st07_sha1_{label}", source) as path:
            tree = ast.parse((REPOSITORY_ROOT / path).read_text(encoding="utf-8"))
            assert _sha1_findings(tree), label
    for module in ("zlib", "binascii", "hmac", "hashlib"):
        fixture = f'"""Design basis: AP-11 fixture."""\nimport {module}\n'
        with non_conformant_fixture(f"st07_importer_{module}", fixture) as path:
            assert path.name in _hash_importers(), module
    assert not stray_fixtures()


# --- the dynamic read-only gate (AV11-6) -------------------------------------------------------


_EVENTS: list[tuple[str, tuple[Any, ...]]] = []
_STATE = {"auditing": False, "installed": False}


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if _STATE["auditing"]:
        _EVENTS.append((event, args))


@contextmanager
def _audited() -> Iterator[list[tuple[str, tuple[Any, ...]]]]:
    """Every audit event raised while the block runs. An audit hook cannot be removed, so it
    is installed once and records only while a block is active."""
    if not _STATE["installed"]:
        sys.addaudithook(_hook)
        _STATE["installed"] = True
    _EVENTS.clear()
    _STATE["auditing"] = True
    try:
        yield _EVENTS
    finally:
        _STATE["auditing"] = False


def _opens(events: list[tuple[str, tuple[Any, ...]]]) -> list[tuple[bytes, int]]:
    """Every open during the block, anywhere: the reader opens relative to a directory it has
    already reached, so an open's path is often a single component, never filterable by the
    repository's prefix."""
    found: list[tuple[bytes, int]] = []
    for event, args in events:
        if event == "open":
            path = args[0] if isinstance(args[0], bytes) else os.fsencode(str(args[0]))
            found.append((path, int(args[2])))
    return found


@pytest.mark.supports("GR9-1", "GR9-8")
@pytest.mark.traces("ST07-N1", "ST07-M4", "GR9-4", "OB9-8")
def test_every_open_during_observation_is_read_only() -> None:
    """`AV11-6`, `GR9-4`: every open the observation makes — of every directory on the way to
    an item as well as of the item — is read-only and no-follow, and no write, rename,
    removal, mode or time change, link, exec, spawn or subprocess event occurs at all."""
    with x.workspace() as base:
        repo = x.repository(base)
        os.symlink("a.txt", repo.path / "link")
        repo.write("untracked.txt", b"u\n")
        observation.observe(repo.location)  # warm: the interpreter's own lazy imports
        with _audited() as events:
            found = observation.observe(repo.location)
            recorded = list(events)
    assert isinstance(found, Determinate)
    opens = _opens(recorded)
    assert {b"HEAD", b"index", b"a.txt", b"untracked.txt", b".git"} <= {p for p, _ in opens}
    assert b"link" not in {p for p, _ in opens}
    for _, value in opens:
        assert value & os.O_ACCMODE == os.O_RDONLY, oct(value)
        assert value & os.O_NOFOLLOW, oct(value)
        assert not value & (os.O_CREAT | os.O_TRUNC | os.O_APPEND), oct(value)
    names = [event for event, _ in recorded]
    assert not [n for n in names if n.startswith(FORBIDDEN_AUDIT_EVENTS)], names


@pytest.mark.traces("ST07-N1", "OB9-8", "GR9-4", "OB9-12")
def test_observation_and_b2_touch_nothing_in_the_repository() -> None:
    """`AV11-6`, `OB9-8`: the whole `B2` act — observation and fixing — leaves every item of
    the repository, `.git` included, identical in bytes, mode and modification time: no index
    rewrite or stat refresh, no ref, object, configuration or hook written, no maintenance,
    no working-tree file touched — dirty and staged state included."""
    with x.workspace() as base, fresh_store() as store:
        repo = x.repository(base)
        repo.write("a.txt", b"dirty\n")
        repo.write("src/b.py", b"staged\n")
        repo.git("add", "src/b.py")
        repo.write("untracked.txt", b"u\n")
        epoch = x.epoch_at_s1(store, repo)
        before = x.snapshot(repo.path)
        index_stamp = (repo.path / ".git/index").stat().st_mtime_ns
        assert isinstance(observation.fix_entry_boundary(store, epoch.root), Fixed)
        assert x.snapshot(repo.path) == before
        assert (repo.path / ".git/index").stat().st_mtime_ns == index_stamp


@pytest.mark.traces("ST07-N2", "GR9-5", "OB9-8")
def test_no_hook_filter_textconv_fsmonitor_pager_or_alias_runs() -> None:
    """`GR9-5`: a repository configured to run code on every Git touch — every hook, an
    `fsmonitor`, clean and smudge filters, a `textconv` diff driver, a pager and a shell
    alias, all applied to every path — is observed, and none of it runs: the sentinel each
    would create never appears, and no exec, spawn or subprocess event occurs."""
    with x.workspace() as base:
        repo = x.repository(base)
        sentinel = base / "executed"
        script = base / "payload.sh"
        script.write_text(f"#!/bin/sh\ntouch {sentinel}\ncat\n", encoding="utf-8")
        script.chmod(0o755)
        hooks = repo.path / ".git" / "hooks"
        for name in (
            "pre-commit", "post-commit", "post-checkout", "post-index-change", "pre-push",
            "reference-transaction", "fsmonitor-watchman", "post-rewrite", "pre-auto-gc",
        ):  # fmt: skip
            hook = hooks / name
            hook.write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
            hook.chmod(0o755)
        for key, value in (
            ("core.fsmonitor", str(script)),
            ("core.pager", str(script)),
            ("filter.payload.clean", str(script)),
            ("filter.payload.smudge", str(script)),
            ("diff.payload.textconv", str(script)),
            ("alias.st", f"!{script}"),
        ):
            repo.git("config", key, value)
        repo.write(".gitattributes", b"* filter=payload diff=payload\n")
        with _audited() as events:
            found = observation.observe(repo.location)
            names = [event for event, _ in events]
        assert isinstance(found, Determinate), found
        assert not sentinel.exists()
    assert not [n for n in names if n.startswith(FORBIDDEN_AUDIT_EVENTS)], names


@pytest.mark.supports("GR9-1", "GR9-2", "GR9-3", "GR9-6")
@pytest.mark.traces("GR9-7", "ST07-G1")
def test_the_observation_grants_nothing_and_is_not_an_activation() -> None:
    """`GR9-7`: the observation derives no envelope, starts no worker and names no role,
    session, provider, tool category or input package — it grants no Git read to anyone
    (`GR9-1`…`GR9-3`, `GR9-6` are later stages')."""
    names = {n.id for n in ast.walk(_tree()) if isinstance(n, ast.Name)}
    names |= {a.name for n in ast.walk(_tree()) if isinstance(n, ast.ImportFrom) for a in n.names}
    for forbidden in (
        "Role", "AuthorityEnvelope", "WorkerActivationRecord", "SessionAnnotation",
        "ProviderAssignment", "InputPackage", "ToolCategory", "record_envelope",
        "derive_envelope",
    ):  # fmt: skip
        assert forbidden not in names, forbidden


@pytest.mark.traces("ST07-G1", "ST07-D4", "RS7-1")
def test_st07_writes_only_rc17_and_its_s2_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Across fixing, replay, an indeterminate observation and a bound-referent mismatch,
    every record ST-07 writes is `RC-17` or its M2 `S2` entry, only through `create_unit`,
    and only once."""
    units: list[tuple[str, ...]] = []
    original = CoordinationStore.create_unit

    def recording(self: CoordinationStore, records: Any) -> None:
        unit = tuple(records)
        units.append(tuple(type(r).__name__ for r in unit))
        original(self, unit)

    def refused(self: CoordinationStore, record: Any) -> None:
        raise AssertionError("ST-07 writes through create_unit only")

    with x.workspace() as base:
        repo = x.repository(base)
        with fresh_store() as store:
            epoch = x.epoch_at_s1(store, repo)
            monkeypatch.setattr(CoordinationStore, "create_unit", recording)
            monkeypatch.setattr(CoordinationStore, "create", refused)
            fault = {("read_regular", b"/.git/HEAD", 4): x.same_length(b"ref: refs/heads/mair\n")}
            assert isinstance(
                observation.fix_entry_boundary(store, epoch.root, x.FaultReader(fault)), NotFixed
            )
            assert isinstance(observation.fix_entry_boundary(store, epoch.root), Fixed)
            assert isinstance(observation.fix_entry_boundary(store, epoch.root), Replayed)
            monkeypatch.undo()
        with fresh_store() as store:
            epoch = x.epoch_at_s1(store, repo, commit="0" * 40)
            monkeypatch.setattr(CoordinationStore, "create_unit", recording)
            monkeypatch.setattr(CoordinationStore, "create", refused)
            assert isinstance(observation.fix_entry_boundary(store, epoch.root), NotFixed)
    assert units == [("EntryStateBoundaryRecord", "M2PositionEntry")]
    assert set(units[0]) == WRITTEN_BY_ST07
    writes = {
        n.attr
        for n in ast.walk(_tree())
        if isinstance(n, ast.Attribute) and n.attr in ("create", "create_unit", "_execute")
    }
    assert writes == {"create_unit"}
    assert EntryStateBoundaryRecord.__name__ in WRITTEN_BY_ST07
    assert M2PositionEntry.__name__ in WRITTEN_BY_ST07


@pytest.mark.traces("ST07-G1", "ST07-A1")
def test_the_st07_code_carries_no_provider_surface() -> None:
    """`SG11-11`, `SG11-11a`, amendment part 3: no provider SDK import in any ST-07 file,
    production or test; no prompt or provider identifier in production; no network or
    subprocess client in production."""
    for relative in ST07_PRODUCTION + ST07_TESTS:
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
                if relative in ST07_PRODUCTION:
                    root = module.split(".")[0]
                    assert root not in {"socket", "http", "urllib", "requests", "subprocess"}
    identifiers = [
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(_tree())
        if isinstance(node, ast.Name | ast.Attribute)
    ]
    assert not [i for i in identifiers if any(word in i.lower() for word in PROMPT_WORDS)]


@pytest.mark.traces("ST07-G1", "ST07-A1")
def test_the_schema_is_unchanged() -> None:
    """Plan §16: no schema change, no migration, no new table, column, constraint or
    trigger — the schema is still `/4` and its DDL is byte-identical to the pinned digest."""
    assert SCHEMA_VERSION == "gpauto.coordination-store/4"
    statements = schema_statements(build_catalogue())
    digest = hashlib.sha256("\n;\n".join(statements).encode("utf-8")).hexdigest()
    assert digest == PINNED_SCHEMA_DIGEST


# --- traceability ------------------------------------------------------------------------------


def _rows() -> dict[str, traceability.Row]:
    results = {
        node_id: True
        for node_ids in traceability.declared_evidence().values()
        for node_id in node_ids
    }
    return {row.element: row for row in traceability.matrix(results)}


ST07_DISCHARGED_FROZEN = (
    "GR9-4", "GR9-5", "GR9-7",
    "OB9-1", "OB9-2", "OB9-4", "OB9-7", "OB9-8", "OB9-9", "OB9-9b", "OB9-9c", "OB9-11",
    "OB9-12", "OB9-13", "OB9-14", "OB9-17",
    "RS7-1", "RS7-2", "RS7-3", "RS7-4", "RS7-5",
    "IX-2",
)  # fmt: skip
"""Plan §14: the frozen ST-07 rows ST-07 discharges."""

ST07_OWED_LATER = {
    "OB9-3": "GP-AUTO-ST-08",
    "OB9-5": "GP-AUTO-ST-08",
    "OB9-9a": "GP-AUTO-ST-08",
    "OB9-15": "GP-AUTO-ST-08",
    "OB9-16": "GP-AUTO-ST-08",
    "GR9-8": "GP-AUTO-ST-08",
    "IX-1": "GP-AUTO-ST-08",
    "IX-1a": "GP-AUTO-ST-08",
    "OB9-9d": "GP-AUTO-ST-16",
    "OB9-10": "GP-AUTO-ST-16",
    "OB9-6": "GP-AUTO-ST-17",
    "OB9-18": "GP-AUTO-ST-11",
    "GR9-1": "GP-AUTO-ST-13",
    "GR9-2": "GP-AUTO-ST-13",
    "GR9-6": "GP-AUTO-ST-13",
    "GR9-3": "GP-AUTO-ST-12",
}
"""Plan §14: the sixteen rows ST-07 supports and a named later stage owes."""


@pytest.mark.traces("ST07-A1")
def test_the_st07_rows_are_parsed_from_the_frozen_artifacts() -> None:
    """`TR11-4`, `TR11-8`: AP-09's identity is checked first, then every ST-07 row is found in
    AP-09, AP-07 or AP-10 — no transcribed inventory."""
    raw = traceability.AP09_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == traceability.AP09_SHA256
    assert (raw.count(b"\n"), len(raw)) == (917, 179969)
    rows = traceability.st07_elements()
    assert list(rows) == [
        *traceability.ST07_AP09_ELEMENTS,
        *traceability.ST07_AP07_ELEMENTS,
        *traceability.ST07_AP10_ELEMENTS,
    ]
    assert len(rows) == 38 and all(statement.strip() for statement in rows.values())
    assert set(ST07_DISCHARGED_FROZEN) | set(ST07_OWED_LATER) == set(rows)
    assert not set(ST07_DISCHARGED_FROZEN) & set(ST07_OWED_LATER)


@pytest.mark.traces("ST07-A1")
def test_every_st07_row_is_discharged_here_or_owed_by_a_named_later_stage() -> None:
    """Each discharged row has ST-07 as implementing and local-verifying stage and is owed by
    nobody; each owed row is undischarged, owed by exactly its named stage — one that has not
    run — with ST-07's structure recorded as support and no discharging evidence declared."""
    rows = _rows()
    for element in (*ST07_DISCHARGED_FROZEN, *traceability.ST07_CONTRACT_OBLIGATIONS):
        row = rows[element]
        assert row.disposition == DISCHARGED, element
        assert row.implementing == row.local_verifying == GPAUTO_STAGE, element
        assert element not in OWED_BY, element
    support = traceability.declared_support()
    evidence = traceability.declared_evidence()
    for element, stage in ST07_OWED_LATER.items():
        row = rows[element]
        if stage in traceability.STAGES_RUN and element not in OWED_BY:
            assert row.disposition == DISCHARGED, element
            assert row.implementing == stage, element
        else:
            assert row.disposition == UNDISCHARGED, element
            assert OWED_BY[element][0] not in traceability.STAGES_RUN, element
            assert support.get(element), element
            assert element not in evidence, element


@pytest.mark.traces("ST07-A1", "AP03-I08")
def test_ap03_i08_is_discharged_here_and_nothing_owed_elsewhere_moved() -> None:
    """`AP03-I08`, owed by ST-07 since ST-01, is discharged by ST-07's evidence. The other
    twenty rows owed at ST-06's acceptance are each still undischarged and owed by the same
    stage, and no ST-07 test declares discharging evidence for any of them; ST-07 is the last
    stage run; and every undischarged row is owed by a stage that has not run."""
    rows = _rows()
    assert rows["AP03-I08"].disposition == DISCHARGED
    assert rows["AP03-I08"].implementing == GPAUTO_STAGE
    assert "AP03-I08" not in OWED_BY
    owed_then = traceability.OWED_AT_ST06_ACCEPTANCE
    assert len(owed_then) == 21
    evidence = traceability.declared_evidence()
    for element, stage in owed_then.items():
        if element == "AP03-I08":
            assert stage == GPAUTO_STAGE
            continue
        if stage in traceability.STAGES_RUN:
            assert rows[element].disposition == DISCHARGED, element
            assert rows[element].implementing == stage, element
        else:
            assert rows[element].disposition == UNDISCHARGED, element
            assert OWED_BY[element][0] == stage, element
        assert not [n for n in evidence.get(element, []) if "st07" in n], element
    assert GPAUTO_STAGE in traceability.STAGES_RUN
    undischarged = {e for e, row in rows.items() if row.disposition == UNDISCHARGED}
    assert undischarged == set(OWED_BY)
    assert len(traceability.OWED_AT_ST07_ACCEPTANCE) == 20 + len(ST07_OWED_LATER)
    for element, stage in traceability.OWED_AT_ST07_ACCEPTANCE.items():
        if stage in traceability.STAGES_RUN and element not in OWED_BY:
            assert rows[element].disposition == DISCHARGED
            assert rows[element].implementing == stage
        else:
            assert element in undischarged
            assert OWED_BY[element][0] not in traceability.STAGES_RUN
    for element, (stage, _) in OWED_BY.items():
        assert stage not in traceability.STAGES_RUN, element
    assert traceability.unknown_elements() == []
    assert traceability.untraced_tests() == []
