"""GP-11 — authority is a *label*, and no LLM label is ever sufficient.

Design basis: design/GP-SPK-001-governance-kernel.md §13.1 requirement 11, §3, §4,
§7, §9 (`GK-INV-4`, `GK-INV-5`, `GK-INV-6`), §11.

The plan of record (revision 5 §18) scopes this file exactly, and the scope is as much
about what is *not* claimed as about what is. GP-11 proves five things, (a)-(e), and
the design's §11 records a sixth fact that is a limitation rather than a proof:

> **HUMAN authority label enforced; human identity/authenticity not proven until the
> signing/authentication stage.**

Section F asserts that sentence is recorded verbatim where the plan mandates it, and
then *demonstrates the gap* rather than papering over it: an approval carrying an
arbitrary, unauthenticated `approver_id` is accepted, because nothing in GP-SPK-001
can tell one label from another. A test that quietly passed on stronger-sounding
evidence would make the spike's verdict overclaim, which is the failure §11 exists to
prevent.

Why each mechanism is the one used
----------------------------------
**Over the table, not over call sites (a).** "No LLM authorized a transition" asserted
at today's call sites is only ever true of today's call sites. Asserted over
`LEGAL_TRANSITIONS` and over the full 3x3x3 `(from, to, actor)` grid, it is a property
of the graph, and a new edge cannot slip past it.

**Two independent refusals for one property (c).** An LLM-labelled statement is
refused twice over, by two layers that do not know about each other: `approvals.py`
pins `approver_kind` to `Literal[ActorKind.HUMAN]`, so the statement never decodes;
and `policy.refuse_unless_allowed` refuses `ActorKind.LLM` on the edge regardless of
how the object carrying it came to exist. Section C proves both, the second by handing
the kernel an object built through Pydantic's validation-free `model_construct` — the
strongest bypass available to a caller in-process. Neither refusal is a new policy
implementation: both are the frozen paths, called.

**A static import graph, not a `sys.modules` snapshot (d).** ST-9 established that
`"dbos" not in sys.modules` is order-sensitive inside a suite that elsewhere starts
DBOS, and a runtime snapshot is blind in a second way as well: an `import dbos` inside
a function body never appears in `sys.modules` until that function runs. Section D
therefore walks the package's **import graph from source**, transitively, following
intra-package edges and collecting every external root at any depth, function bodies
included. It states the result as an **allowlist** — the governance closure imports the
standard library plus exactly `pydantic` and `rfc8785` — which subsumes the plan's
`dbos`/`anthropic`/`openai` denylist: a prohibited import cannot be missed by being
absent from a list someone forgot to extend. The clean-subprocess runtime check is kept
alongside it, because the two fail differently, and **both carry negative controls**.

**What the source walk has to resolve, and why it is not optional (ST11-R01/R04).** An
import graph is only as complete as its resolver. A walk that discards the name in
`from . import workflow`, truncates `gplanner.pkg.helper` to its first component, or
reads only `Import`/`ImportFrom` nodes reports a clean closure over source that reaches
an SDK -- which is the worst possible failure for a gate, because it is indistinguishable
from a real PASS. Relative imports at every level, dotted module *and* package targets,
the initializers executed on the way to a nested module, and the conventional literal
`importlib.import_module(...)` call are therefore all resolved here. The last of those
is bounded on purpose and the bound is asserted: a computed target is not claimed.

**Whole package, not the package root (ST11-R02/R03).** Every decode-boundary scan is
recursive. A flat `glob` made all three of them claims about `src/gplanner/*.py` while
reading as claims about the package, so one subdirectory was enough to hold a raw JSON
decode path. Recursion does not widen the exemption: the approved codec is the file at
the package root, and a nested namesake is an ordinary module. The `json` ban applies to
the package and its submodules alike, since `from json.decoder import JSONDecoder`
decodes exactly as `json.loads` does.

**Gates that are themselves tested (d, e).** Plan §18(e) requires the decode gate to be
"verified against all three bypasses ... so the gate itself is tested rather than
merely written". A structural gate that has only ever been run against clean source is
evidence that the source is clean *or* that the gate is broken, and the two are
indistinguishable. Every gate in sections D and E is therefore also run against
synthetic offending source built in `tmp_path` and required to catch it. No production
file is modified, by these probes or by anything else in this file.

Scope discipline. This file adds no governance semantics, defines no policy of its own,
and duplicates no codec logic. What it asserts about the transition graph it reads from
`policy.LEGAL_TRANSITIONS`; what it asserts about statements it obtains through
`codec.decode_approval`; what it asserts about refusal it obtains by calling the kernel.
GP-04 owns the exhaustive legality matrix, GP-05 the statement's field constraints, and
GP-09 the workflow's runtime behaviour; this file asserts the *authority* property that
cuts across them, and the structural gates §13.2 requires.
"""

from __future__ import annotations

import ast
import itertools
import json
import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from conftest import Harness
from gplanner import codec, kernel, store
from gplanner.approvals import (
    PREDICATE_VERSION,
    SCOPE_APPROVAL_PREDICATE_TYPE,
    STATEMENT_TYPE,
    ApprovalStatement,
    ScopeApprovalPredicate,
    Sha256DigestSet,
    Subject,
)
from gplanner.artifacts import ScopeSpec
from gplanner.digest import SCOPE_MEDIA_TYPE, compute_digest, to_intoto_hex
from gplanner.errors import AuthorityDenied, IllegalTransition
from gplanner.policy import LEGAL_TRANSITIONS, Outcome, refuse_unless_allowed, resolve
from gplanner.states import ActorKind, ScopeState
from gplanner.store import Store

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "gplanner"

WORKFLOW_ID = "gp-spk-001-case-0001"
APPROVAL_ID = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a88"
APPROVER_ID = "owner@example.invalid"
ISSUED_AT = "2026-09-17T11:22:33Z"

#: The ten modules the plan's structural gate (revision 5 §23) names as the governance
#: layer. `errors` and `require` join them in the closure section below, derived rather
#: than listed: they are reached by import, and asserting the derived set is what makes
#: "the governance layer" a fact about the graph rather than a list kept by hand.
GOVERNANCE_SEEDS: tuple[str, ...] = (
    "canonical",
    "profile",
    "digest",
    "artifacts",
    "states",
    "policy",
    "approvals",
    "codec",
    "store",
    "kernel",
)

#: The engine's two permitted importers (§4). Outside the governance layer by design.
ENGINE_MODULES: tuple[str, ...] = ("app", "workflow")

#: Third-party roots the governance layer is permitted to reach, transitively. Exactly
#: the plan's pinned dependency set (revision 5 ST-1) **minus `dbos`**. An allowlist
#: rather than a denylist: `anthropic`, `openai`, `dbos` and anything else unnamed are
#: refused by not appearing, so the gate cannot be defeated by a name nobody predicted.
ALLOWED_THIRD_PARTY: frozenset[str] = frozenset({"pydantic", "rfc8785"})

#: The denylist the plan states literally (revision 5 §23, design §2). Asserted as well
#: as the allowlist, so the frozen wording is checked in its own right.
FORBIDDEN_ROOTS: frozenset[str] = frozenset({"dbos", "anthropic", "openai"})

#: The distribution package the source walk treats as first-party. Named once, so the
#: resolver's "is this an intra-package edge?" question has a single answer.
PACKAGE_NAME = "gplanner"

#: The conventional dynamic-import route (ST11-R04). `importlib` is standard library and
#: therefore allowlisted, and `import_module` is an ordinary call node -- so a deferred
#: loader call reached a forbidden SDK past both halves of section D until the resolver
#: below learned to read it. Aliases of both are tracked; computed targets are not
#: claimed, and section D says so in a test of its own.
IMPORTLIB_MODULE = "importlib"
IMPORT_MODULE_FUNCTION = "import_module"

#: Pydantic's validation-free constructors. Each turns an unchecked mapping into an
#: authoritative object, which is a decode path beside `codec` wearing other clothes.
UNCHECKED_CONSTRUCTORS: frozenset[str] = frozenset(
    {"model_construct", "parse_obj", "parse_raw", "construct"}
)

#: §11's sentence, mandated verbatim by plan §18 in the design doc and `CLAUDE.md`.
LIMITING_CLAIM = (
    "HUMAN authority label enforced; human identity/authenticity not proven until the "
    "signing/authentication stage."
)

# --- source-reading helpers ------------------------------------------------------


def source(module_name: str) -> str:
    return (SRC / f"{module_name}.py").read_text(encoding="utf-8")


def module_file(dotted: str, package_root: Path) -> Path | None:
    """The file `gplanner.<dotted>` would load, or `None` when nothing is there.

    A dotted name is a module *or* a package, and both are real import targets, so
    both are tried: `a.b` is `a/b.py` when that exists and `a/b/__init__.py`
    otherwise. Truncating `a.b` to its first component -- and resolving that as a
    flat file -- is what let a subpackage helper carrying a forbidden import sit
    outside the closure entirely (ST11-R01).
    """
    parts = [part for part in dotted.split(".") if part]
    if parts:
        module = package_root.joinpath(*parts[:-1]) / f"{parts[-1]}.py"
        if module.is_file():
            return module
    initializer = package_root.joinpath(*parts) / "__init__.py"
    if initializer.is_file():
        return initializer
    return None


def dotted_name(path: Path, package_root: Path) -> str:
    """`path`'s module name relative to the package root; `""` for the initializer."""
    relative = path.relative_to(package_root).with_suffix("")
    return ".".join(part for part in relative.parts if part != "__init__")


def containing_package(dotted: str, path: Path) -> str:
    """The package a relative import written inside `path` resolves against.

    `from . import x` inside `a/b.py` means `a.x`; inside `a/__init__.py` it means
    `a.x` as well, because an initializer *is* its package. Getting this wrong is
    how a relative edge ends up pointing at nothing.
    """
    if path.name == "__init__.py":
        return dotted
    return ".".join(dotted.split(".")[:-1])


def dynamic_import_target(
    node: ast.Call, importlib_aliases: frozenset[str], loader_aliases: frozenset[str]
) -> str | None:
    """The module a conventional dynamic loader call names, when it names one literally.

    `importlib` is standard library, so it is allowlisted, and `import_module` is an
    ordinary call the `Import`/`ImportFrom` collector never sees. A deferred
    `importlib.import_module("anthropic")` therefore escaped both halves of section D
    (ST11-R04): the source walk saw no import, and the clean-process probe never ran
    the function.

    The three conventional spellings are resolved -- `importlib.import_module(...)`,
    the same through a module alias, and the function imported by name -- plus the
    `__import__` builtin, which is the same construct with a different name. Aliases
    are tracked so the gate is not defeated by a rename.

    **What this deliberately does not do.** The target must be a string *literal*.
    `import_module(name)` for a computed `name` returns `None` here and is not
    reported. Detecting that would require evaluating the module, which is exactly
    the general static analyser this gate is not, and GP-SPK-001 claims no such
    coverage. The claim is bounded to the conventional literal form.
    """
    function = node.func
    if isinstance(function, ast.Attribute) and function.attr == IMPORT_MODULE_FUNCTION:
        if not (isinstance(function.value, ast.Name) and function.value.id in importlib_aliases):
            return None
    elif isinstance(function, ast.Name):
        if function.id not in loader_aliases and function.id != "__import__":
            return None
    else:
        return None
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def external_and_internal_imports(path: Path, package: str = "") -> tuple[set[str], set[str]]:
    """Every import in `path`, split into external roots and first-party module names.

    Read from the syntax tree at **any** depth, so an import inside a function body,
    a `try` block or a class body is collected exactly like a top-level one. That is
    the difference between this gate and a `sys.modules` snapshot: a deferred import is
    invisible to the snapshot until it executes, and visible here always.

    First-party names come back as dotted paths **relative to the package root**, kept
    whole, so `module_file` can try each one as a module and as a package. Four forms
    the reviewed version dropped are resolved here (ST11-R01): `from . import x`,
    `from .sub import x`, a dotted absolute `gplanner.sub.helper`, and -- through the
    closure's ancestor walk -- the package initializers executed on the way to either.
    `package` is the package those relative forms resolve against.

    Conventional dynamic loads are collected into the same sets (ST11-R04), so a
    literal `importlib.import_module("anthropic")` is an external root named
    `anthropic` and `importlib.import_module("gplanner.workflow")` is a first-party
    edge followed like any other.
    """
    external: set[str] = set()
    internal: set[str] = set()
    base = [part for part in package.split(".") if part]

    def absorb_absolute(dotted: str) -> None:
        parts = [part for part in dotted.split(".") if part]
        if not parts:
            return
        if parts[0] == PACKAGE_NAME:
            internal.add(".".join(parts[1:]))
        else:
            external.add(parts[0])

    tree = ast.parse(path.read_text(encoding="utf-8"))
    importlib_aliases: set[str] = set()
    loader_aliases: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root == IMPORTLIB_MODULE:
                    importlib_aliases.add(alias.asname or root)
                absorb_absolute(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # A relative import can only be intra-package. `level` counts the
                # leading dots: one means "this package", each further dot strips a
                # trailing component. More dots than components escapes the package
                # root, and there is nothing first-party left to follow.
                if node.level - 1 > len(base):
                    continue
                prefix = base[: len(base) - (node.level - 1)]
                target = [*prefix, *(part for part in (node.module or "").split(".") if part)]
                internal.add(".".join(target))
                for alias in node.names:
                    internal.add(".".join([*target, alias.name]))
                continue
            module = node.module or ""
            if module == IMPORTLIB_MODULE:
                for alias in node.names:
                    if alias.name == IMPORT_MODULE_FUNCTION:
                        loader_aliases.add(alias.asname or alias.name)
            absorb_absolute(module)
            parts = [part for part in module.split(".") if part]
            if parts and parts[0] == PACKAGE_NAME:
                for alias in node.names:
                    internal.add(".".join([*parts[1:], alias.name]))

    frozen_importlib = frozenset(importlib_aliases)
    frozen_loaders = frozenset(loader_aliases)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target_name = dynamic_import_target(node, frozen_importlib, frozen_loaders)
            if target_name is not None:
                absorb_absolute(target_name)
    return external, internal


def import_closure(
    seeds: tuple[str, ...], root: Path | None = None
) -> tuple[frozenset[str], frozenset[str]]:
    """`(modules reached, external roots reached)` from `seeds`, transitively.

    A fixed-point walk over first-party import edges. `__init__` is seeded implicitly
    because importing `gplanner.<anything>` executes it, so anything it imported would
    be reached by every governance module whether or not one names it. For the same
    reason every *ancestor* of a dotted target is enqueued: importing `a.b.c` runs
    `a/__init__.py` and `a/b/__init__.py` first, and a forbidden import placed in one
    of those initializers is as real as one in the leaf (ST11-R01).

    `root` defaults to the package under test and exists so a control can point the
    identical walk at synthetic source.
    """
    package_root = SRC if root is None else root
    pending: list[str] = [*seeds, ""]
    considered: set[str] = set()
    reached: set[str] = set()
    external: set[str] = set()
    while pending:
        dotted = pending.pop()
        if dotted in considered:
            continue
        considered.add(dotted)
        path = module_file(dotted, package_root)
        if path is None:
            continue
        reached.add(dotted or "__init__")
        found_external, found_internal = external_and_internal_imports(
            path, containing_package(dotted, path)
        )
        external |= found_external
        for candidate in found_internal:
            parts = [part for part in candidate.split(".") if part]
            for depth in range(len(parts) + 1):
                pending.append(".".join(parts[:depth]))
    return frozenset(reached), frozenset(external)


def package_files(package_root: Path) -> list[tuple[str, Path]]:
    """`(name relative to the package root, path)` for **every** module in the tree.

    Recursive by construction. The reviewed version scanned `glob('*.py')` in each
    decode-boundary gate, so an entire subpackage was invisible to all three of them
    and a nested module could decode JSON straight into a domain object without any
    ST-11 failure (ST11-R02). Plan §23's reference gate is recursive; so is this.
    """
    return [
        (path.relative_to(package_root).as_posix(), path)
        for path in sorted(package_root.rglob("*.py"))
    ]


def imports_json(node: ast.AST) -> bool:
    """Whether `node` reaches the standard-library `json` package in any form.

    The `Import` branch already matched `json` and `json.*`; the `ImportFrom` branch
    matched only the exact name, so `from json.decoder import JSONDecoder` was a raw
    decode path the gate did not see (ST11-R03). Both branches now ask the same
    question. A *relative* `from .json import ...` is a first-party module that merely
    shares the name -- it is scanned on its own account, and is not this.
    """
    if isinstance(node, ast.Import):
        return any(name.name == "json" or name.name.startswith("json.") for name in node.names)
    if isinstance(node, ast.ImportFrom) and not node.level:
        module = node.module or ""
        return module == "json" or module.startswith("json.")
    return False


def decode_gate(package_root: Path) -> list[str]:
    """Plan §18(e)'s gate: one JSON -> domain path, keyed on imports not call shape.

    Returns the offences found, so the same function can be asserted empty against the
    real package and non-empty against the synthetic bypasses in section E. A gate that
    is only ever run against clean source cannot distinguish clean source from a broken
    gate.

    `codec.py` is the one module permitted to touch the `json` module at all;
    `model_validate` is forbidden everywhere, `codec.py` included, because
    `model_validate_json` is the only accepted spelling (§7). The exemption is the
    approved codec **at the package root** and nothing else: a `sub/codec.py` is an
    ordinary module, not a second boundary.
    """
    offences: list[str] = []
    for name, path in package_files(package_root):
        exempt = name == "codec.py"
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not exempt and imports_json(node):
                kind = "imports json" if isinstance(node, ast.Import) else "from json import ..."
                offences.append(f"{name}:{node.lineno}: {kind}")
            elif isinstance(node, ast.Attribute) and node.attr == "model_validate":
                offences.append(f"{name}:{node.lineno}: model_validate")
    return offences


def unchecked_construction(package_root: Path) -> list[str]:
    """Offending validation-free constructions anywhere in the package tree.

    `model_construct`, `parse_obj`, `parse_raw` and `construct` each turn an unchecked
    mapping into an authoritative object. Recursive for the reason `decode_gate` is.
    """
    return [
        f"{name}:{node.lineno}: {node.attr}"
        for name, path in package_files(package_root)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Attribute) and node.attr in UNCHECKED_CONSTRUCTORS
    ]


def json_to_domain_holders(package_root: Path) -> dict[str, int]:
    """`{module: number of `model_validate_json` calls}` over the whole package tree."""
    return {
        name.removesuffix(".py"): sum(
            1
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.Attribute) and node.attr == "model_validate_json"
        )
        for name, path in package_files(package_root)
    }


def engine_importers(package_root: Path) -> set[str]:
    """Every module in the tree whose own imports reach `dbos` (§4's boundary rule)."""
    return {
        name.removesuffix(".py")
        for name, path in package_files(package_root)
        if "dbos"
        in external_and_internal_imports(
            path, containing_package(dotted_name(path, package_root), path)
        )[0]
    }


def synthetic_package(tmp_path: Path, files: dict[str, str]) -> Path:
    """A throwaway `gplanner` package written under `tmp_path`, returned as its root.

    Every negative control in sections D and E is built here rather than by touching
    `src/`. Keys are paths relative to the package root, so a control can describe a
    subpackage (`"sub/helper.py"`) as directly as a flat module, which is precisely the
    shape the reviewed gates could not see.
    """
    package = tmp_path / PACKAGE_NAME
    for relative, body in files.items():
        target = package / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return package


def in_clean_process(program: str) -> subprocess.CompletedProcess[str]:
    """Run `program` in a **fresh interpreter**, never in this already-polluted one.

    This suite starts DBOS elsewhere, so `sys.modules` here says nothing about what the
    governance layer imports (the ST-9 discovery). A new process makes the observation
    mean what it says.
    """
    return subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=120
    )


def probe_program(modules: tuple[str, ...]) -> str:
    """A clean-process probe: import `modules`, then report the forbidden roots present."""
    return (
        "import importlib, json, sys\n"
        f"for name in {list(modules)!r}:\n"
        "    importlib.import_module('gplanner.' + name)\n"
        f"forbidden = {sorted(FORBIDDEN_ROOTS)!r}\n"
        "print(json.dumps([root for root in forbidden if root in sys.modules]))\n"
    )


# --- domain builders -------------------------------------------------------------


def spec() -> ScopeSpec:
    return ScopeSpec(
        title="Governance kernel feasibility",
        problem_statement="Prove the authority model with no LLM in the loop.",
        in_scope=("digest-bound approvals",),
        out_of_scope=("signing",),
        acceptance_criteria=("no LLM label authorizes an edge",),
    )


def wire(
    subject_digest: str,
    *,
    approver_kind: str,
    approver_id: str = APPROVER_ID,
    approval_id: str = APPROVAL_ID,
) -> str:
    """The transport JSON an approval crosses the boundary as (§7).

    Built as text, because text is what the transport carries and `codec.decode_approval`
    is the only conversion from it. A statement that could only be built in-process
    would prove nothing about what an outside sender can get past the boundary.
    """
    document: dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": "gplanner.scope/v1",
                "digest": {"sha256": to_intoto_hex(subject_digest)},
            }
        ],
        "predicateType": SCOPE_APPROVAL_PREDICATE_TYPE,
        "predicate": {
            "predicate_version": PREDICATE_VERSION,
            "approval_id": approval_id,
            "workflow_id": WORKFLOW_ID,
            "from_state": str(ScopeState.SCOPE_REVIEW_PENDING),
            "to_state": str(ScopeState.SCOPE_APPROVED),
            "approver_id": approver_id,
            "approver_kind": approver_kind,
            "decision": "APPROVE",
            "issued_at": ISSUED_AT,
        },
    }
    return json.dumps(document)


def unvalidated_statement(subject_digest: str, actor_kind: ActorKind) -> ApprovalStatement:
    """An `ApprovalStatement` carrying `actor_kind`, built **past** validation.

    `model_construct` is Pydantic's documented validation-free constructor: it assigns
    fields without running a single validator, so it produces the object a
    `Literal[ActorKind.HUMAN]` field makes otherwise unreachable. This is the strongest
    in-process bypass of section C's first refusal, and it exists here so the second
    refusal is proven independent of the first rather than assumed to be.

    Nothing in production calls it -- section E asserts that -- and nothing here
    modifies production code to obtain it.
    """
    predicate = ScopeApprovalPredicate.model_construct(
        predicate_version=PREDICATE_VERSION,
        approval_id=APPROVAL_ID,
        workflow_id=WORKFLOW_ID,
        from_state=ScopeState.SCOPE_REVIEW_PENDING,
        to_state=ScopeState.SCOPE_APPROVED,
        approver_id=APPROVER_ID,
        approver_kind=actor_kind,
        decision="APPROVE",
        issued_at=ISSUED_AT,
    )
    return ApprovalStatement.model_construct(
        type_=STATEMENT_TYPE,
        subject=(
            Subject(
                name="gplanner.scope/v1",
                digest=Sha256DigestSet(sha256=to_intoto_hex(subject_digest)),
            ),
        ),
        predicateType=SCOPE_APPROVAL_PREDICATE_TYPE,
        predicate=predicate,
    )


def evidence(path: Path) -> tuple[int, int, str, int]:
    """(consumption rows, audit rows, case state, case revision), read outside the store.

    Read with a plain `sqlite3` connection rather than through `Store`, so the zero-effect
    claims in section C are observations of the database and not of the API that wrote it.
    """
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        consumptions = int(
            conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0]
        )
        audits = int(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
        row = conn.execute(
            "SELECT state, revision FROM cases WHERE workflow_id = ?", (WORKFLOW_ID,)
        ).fetchone()
        return consumptions, audits, str(row[0]), int(row[1])
    finally:
        conn.close()


@pytest.fixture
def st(h: Harness) -> Iterator[Store]:
    with store.open(h.governance_db) as opened:
        yield opened


@pytest.fixture
def pending(st: Store) -> tuple[Store, str]:
    """A case in `SCOPE_REVIEW_PENDING`, reached through the kernel's own mutators.

    The subject digest is pinned against the §5 pipeline, so a statement built from it
    below is bound to the artifact the case genuinely carries. A refusal in section C
    therefore cannot be a mis-built fixture wearing the label's clothes.
    """
    model = spec()
    ref = kernel.open_case(st, WORKFLOW_ID, model)
    assert ref.digest == compute_digest(model, SCOPE_MEDIA_TYPE)
    assert kernel.submit_for_review(st, WORKFLOW_ID, ActorKind.SYSTEM) is (
        ScopeState.SCOPE_REVIEW_PENDING
    )
    return st, ref.digest


# =================================================================================
# Section A — (a) no edge in LEGAL_TRANSITIONS names ActorKind.LLM
# =================================================================================


def test_a_no_edge_in_the_frozen_graph_names_an_llm_authority() -> None:
    """`GK-INV-5`, over the table. The authorities present are exactly `SYSTEM`, `HUMAN`."""
    authorities = {rule.authority for rule in LEGAL_TRANSITIONS}
    assert ActorKind.LLM not in authorities
    assert authorities == {ActorKind.SYSTEM, ActorKind.HUMAN}


def test_a_the_token_llm_appears_nowhere_in_the_frozen_graph() -> None:
    """Stronger than the authority column alone: no field of any row mentions `LLM`.

    A row is `(from, to, authority, requires_approval, design row)`. Checking only
    `authority` would leave a future row free to smuggle the token in elsewhere and be
    read later as though the graph knew about LLMs at all. It does not.
    """
    for rule in LEGAL_TRANSITIONS:
        rendered = (
            f"{rule.from_state}|{rule.to_state}|{rule.authority}|"
            f"{rule.requires_approval}|{rule.row}"
        )
        assert "LLM" not in rendered, rendered


def test_a_the_llm_actor_kind_exists_so_that_it_can_be_refused() -> None:
    """§3: `ActorKind.LLM` is declared precisely so the refusal is testable.

    Its absence from the enum would make section B vacuous -- "no LLM may authorize"
    would then be a claim about a token the code cannot even express.
    """
    assert ActorKind.LLM in set(ActorKind)
    assert str(ActorKind.LLM) == "LLM"


# =================================================================================
# Section B — (b) ActorKind.LLM is refused on every ordered pair, legal or not
# =================================================================================

#: Every ordered pair over the *current* enum, derived so a new state widens the matrix
#: instead of escaping it.
ALL_PAIRS: tuple[tuple[ScopeState, ScopeState], ...] = tuple(
    itertools.product(list(ScopeState), list(ScopeState))
)

LEGAL_PAIRS: frozenset[tuple[ScopeState, ScopeState]] = frozenset(
    (rule.from_state, rule.to_state) for rule in LEGAL_TRANSITIONS
)


@pytest.mark.parametrize("pair", ALL_PAIRS, ids=lambda p: f"{p[0]}->{p[1]}")
def test_b_an_llm_label_is_never_allowed_on_any_ordered_pair(
    pair: tuple[ScopeState, ScopeState],
) -> None:
    """All nine cells, not only the two edges an approval could plausibly target."""
    assert resolve(pair[0], pair[1], ActorKind.LLM).outcome is not Outcome.ALLOW


@pytest.mark.parametrize("pair", ALL_PAIRS, ids=lambda p: f"{p[0]}->{p[1]}")
def test_b_an_llm_label_raises_the_refusal_that_names_the_real_reason(
    pair: tuple[ScopeState, ScopeState],
) -> None:
    """The raising face refuses too, and the two refusals stay distinct.

    On a legal edge the refusal is `AuthorityDenied` -- the edge exists and this actor
    may not take it. Everywhere else it is `IllegalTransition` -- no such edge, so no
    actor could take it. Collapsing them would send an operator after the wrong fix.
    """
    expected = AuthorityDenied if pair in LEGAL_PAIRS else IllegalTransition
    with pytest.raises(expected):
        refuse_unless_allowed(pair[0], pair[1], ActorKind.LLM)


def test_b_the_only_allowed_cells_in_the_whole_grid_are_the_two_frozen_edges() -> None:
    """The 3x3x3 `(from, to, actor)` grid, in full: 27 cells, exactly 2 `ALLOW`.

    This is the form of (a) that no new call site can regress and no new *edge* can
    either: if a row naming `ActorKind.LLM` were ever added, an extra `ALLOW` cell
    would appear here and this assertion would name it.
    """
    allowed = {
        (from_state, to_state, actor)
        for from_state, to_state in ALL_PAIRS
        for actor in list(ActorKind)
        if resolve(from_state, to_state, actor).outcome is Outcome.ALLOW
    }
    assert allowed == {
        (
            ScopeState.SCOPE_DRAFTING,
            ScopeState.SCOPE_REVIEW_PENDING,
            ActorKind.SYSTEM,
        ),
        (
            ScopeState.SCOPE_REVIEW_PENDING,
            ScopeState.SCOPE_APPROVED,
            ActorKind.HUMAN,
        ),
    }
    assert len(list(ScopeState)) ** 2 * len(list(ActorKind)) == 27


def test_b_the_refusal_reason_cites_the_invariant_and_both_actor_kinds() -> None:
    """A refusal an operator can act on without re-deriving the table."""
    verdict = resolve(
        ScopeState.SCOPE_REVIEW_PENDING, ScopeState.SCOPE_APPROVED, ActorKind.LLM
    )
    assert verdict.outcome is Outcome.REFUSE_AUTHORITY
    assert "HUMAN" in verdict.reason
    assert "LLM" in verdict.reason
    assert verdict.row == "SPK1-2"


# =================================================================================
# Section C — (c) an LLM- or SYSTEM-labelled statement never reaches the kernel
# =================================================================================


@pytest.mark.parametrize("label", ["LLM", "SYSTEM"])
def test_c_a_statement_labelled_llm_or_system_fails_the_transport_decode(
    pending: tuple[Store, str], label: str
) -> None:
    """Refused by the frozen `gp_transport_decode` site, on the model's own constraint.

    No second policy implementation is involved and none is possible: `approver_kind`
    is `Literal[ActorKind.HUMAN]`, so the refusal is `literal_error` at exactly that
    field and it happens during the single JSON -> domain parse (§7).
    """
    _, subject_digest = pending
    with pytest.raises(ValidationError) as refusal:
        codec.decode_approval(wire(subject_digest, approver_kind=label))

    errors = refusal.value.errors()
    assert [(error["type"], error["loc"]) for error in errors] == [
        ("literal_error", ("predicate", "approver_kind"))
    ]


@pytest.mark.parametrize("label", ["LLM", "SYSTEM"])
def test_c_a_refused_label_leaves_no_consumption_no_audit_and_no_advance(
    pending: tuple[Store, str], h: Harness, label: str
) -> None:
    """Rejection is inert: nothing is burnt, nothing is recorded, nothing moves."""
    _, subject_digest = pending
    before = evidence(h.governance_db)

    with pytest.raises(ValidationError):
        codec.decode_approval(wire(subject_digest, approver_kind=label))

    assert evidence(h.governance_db) == before
    consumptions, audits, state, _ = before
    assert (consumptions, audits, state) == (0, 0, str(ScopeState.SCOPE_REVIEW_PENDING))


def test_c_the_kernel_signature_cannot_be_handed_an_undecoded_payload() -> None:
    """There is no alternate entry point: governance takes domain objects only.

    Read from the source, over every public function in `kernel.py`. A parameter typed
    `dict`, `bytes`, `Any` or `Mapping` would be a second ingestion path beside `codec`,
    reachable without the validation that refuses an LLM label in the first place.
    """
    tree = ast.parse(source("kernel"))
    public = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    ]
    assert [node.name for node in public] == [
        "open_case",
        "submit_for_review",
        "apply_scope_approval",
    ]
    annotations = {
        f"{node.name}.{arg.arg}": ast.unparse(arg.annotation) if arg.annotation else None
        for node in public
        for arg in node.args.args
    }
    assert annotations == {
        "open_case.store": "Store",
        "open_case.workflow_id": "str",
        "open_case.spec": "ScopeSpec",
        "submit_for_review.store": "Store",
        "submit_for_review.workflow_id": "str",
        "submit_for_review.actor_kind": "ActorKind",
        "apply_scope_approval.store": "Store",
        "apply_scope_approval.workflow_id": "str",
        "apply_scope_approval.statement": "ApprovalStatement",
    }


def test_c_even_an_unvalidated_llm_statement_is_refused_by_the_policy_layer(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The second, independent refusal — defence in depth, proven rather than assumed.

    The statement here bypassed validation entirely (`model_construct`), so it carries
    `approver_kind=ActorKind.LLM` as a real field value. The kernel refuses it anyway,
    at §10 step 5a, by calling `policy.refuse_unless_allowed` — the same frozen guard
    section B exercises directly. `AuthorityDenied`, not `ValidationError`: this is the
    authority model speaking, not the schema.
    """
    opened, subject_digest = pending
    statement = unvalidated_statement(subject_digest, ActorKind.LLM)
    assert statement.predicate.approver_kind is ActorKind.LLM  # the bypass really worked

    with pytest.raises(AuthorityDenied) as refusal:
        kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)

    assert "SPK1-2" in str(refusal.value)
    assert "LLM" in str(refusal.value)


def test_c_the_unvalidated_llm_refusal_burns_nothing_either(
    pending: tuple[Store, str], h: Harness
) -> None:
    """§10's ordering, at the one place it matters most.

    Every policy check precedes the claim in step 5f, so the refused approval's id is
    still unconsumed, the case has not moved, and no `scope.approved` audit event
    exists. A guard that consumed on the way to refusing would satisfy a weaker reading
    of "refused" while recording that an LLM-labelled approval had been used.
    """
    opened, subject_digest = pending
    with pytest.raises(AuthorityDenied):
        kernel.apply_scope_approval(
            opened, WORKFLOW_ID, unvalidated_statement(subject_digest, ActorKind.LLM)
        )

    consumptions, audits, state, revision = evidence(h.governance_db)
    assert (consumptions, audits) == (0, 0)
    assert state == str(ScopeState.SCOPE_REVIEW_PENDING)
    assert revision == 2, "the submit's revision, unchanged by the refusal"
    assert opened.find_consumption(APPROVAL_ID) is None
    assert opened.read_audit(WORKFLOW_ID) == ()


def test_c_the_same_approval_labelled_human_does_advance_the_case(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The negative control for this whole section.

    Identical statement, identical binding, identical id — only the label differs, and
    it is the only thing that differed in every refusal above. Without this, "refused"
    could mean the fixture was broken rather than that the label was rejected.
    """
    opened, subject_digest = pending
    statement = codec.decode_approval(wire(subject_digest, approver_kind="HUMAN"))
    outcome = kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)

    assert outcome.applied is True
    assert outcome.state is ScopeState.SCOPE_APPROVED
    consumptions, audits, state, _ = evidence(h.governance_db)
    assert (consumptions, audits, state) == (1, 1, str(ScopeState.SCOPE_APPROVED))


def test_c_no_workflow_or_engine_layer_reinterprets_the_label(h: Harness) -> None:
    """`GK-INV-6` in the direction (c) needs: orchestration never reads the label.

    `approver_kind` appears nowhere in `workflow.py`'s or `app.py`'s code, and the only
    `ActorKind` member either names is `SYSTEM` — the claim `_submit_for_review` makes
    about itself, which `policy` then adjudicates. A layer that inspected the label
    would be a second place the authority model could be decided, and DBOS could reach
    it without any governance code running.
    """
    for module_name in ENGINE_MODULES:
        tree = ast.parse(source(module_name))
        attributes = {
            ast.unparse(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and ast.unparse(node).startswith("ActorKind.")
        }
        assert attributes <= {"ActorKind.SYSTEM"}, module_name
        identifiers = {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
        } | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        for forbidden in ("approver_kind", "approver_id", "predicate", "AuthorityDenied"):
            assert forbidden not in identifiers, f"{module_name}: {forbidden}"


# =================================================================================
# Section D — (d) the governance layer's transitive imports
# =================================================================================


def test_d_the_governance_closure_is_the_ten_seeds_plus_errors_require_and_init() -> None:
    """What "the governance layer" *is*, derived from the import graph rather than listed.

    The plan's gate names ten modules; `errors` and `require` are reached from them and
    are therefore part of the layer whether or not anyone lists them. `app` and
    `workflow` are not reachable: the engine sits above governance, never inside it.
    """
    reached, _ = import_closure(GOVERNANCE_SEEDS)
    assert reached == frozenset(
        {*GOVERNANCE_SEEDS, "errors", "require", "__init__"}
    )
    assert not reached & set(ENGINE_MODULES)


def test_d_the_governance_closure_imports_only_the_standard_library_and_two_pins() -> None:
    """The allowlist form of (d), which subsumes every denylist.

    Everything the governance layer imports transitively, at any depth and inside any
    function body, is either in the standard library or is one of the two pinned
    third-party packages. `dbos`, `anthropic` and `openai` are excluded by not being
    named — as is any SDK nobody thought to prohibit.
    """
    _, external = import_closure(GOVERNANCE_SEEDS)
    third_party = {
        root
        for root in external
        if root not in sys.stdlib_module_names and root != "__future__"
    }
    assert third_party == set(ALLOWED_THIRD_PARTY)


def test_d_the_governance_closure_names_no_forbidden_root() -> None:
    """The plan's denylist (revision 5 §23, design §2), asserted in its own wording."""
    _, external = import_closure(GOVERNANCE_SEEDS)
    assert not external & FORBIDDEN_ROOTS


def test_d_the_import_graph_gate_detects_an_engine_import_in_real_source() -> None:
    """The negative control, taken from production code rather than a mock.

    Seeded at `workflow`, the identical walk reports `dbos`. The gate above therefore
    passes because the governance layer is clean, not because the walk cannot see an
    engine import.
    """
    reached, external = import_closure(("workflow",))
    assert "dbos" in external
    assert "workflow" in reached
    assert external & FORBIDDEN_ROOTS == {"dbos"}


def test_d_the_import_graph_gate_detects_an_import_hidden_in_a_function_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bypass a `sys.modules` snapshot cannot see, caught here.

    A deferred `import dbos` inside a function never enters `sys.modules` until that
    function runs, so a runtime probe would report the layer clean. The syntax tree
    reports it whether it ever runs or not. Synthetic source in `tmp_path`: no
    production file is touched.
    """
    package = tmp_path / "gplanner"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "kernel.py").write_text(
        "from gplanner import policy\n\n\ndef decide() -> None:\n    import dbos\n",
        encoding="utf-8",
    )
    (package / "policy.py").write_text(
        "def helper() -> None:\n    from anthropic import Anthropic\n", encoding="utf-8"
    )
    monkeypatch.setattr(sys.modules[__name__], "SRC", package)

    reached, external = import_closure(("kernel",))
    assert reached == {"kernel", "policy", "__init__"}
    assert external & FORBIDDEN_ROOTS == {"dbos", "anthropic"}


# --- ST11-R01 / ST11-R04 negative controls ---------------------------------------
#
# Every escape the discovery review demonstrated is rebuilt here, in `tmp_path`, and
# required to fail the gate. The reviewed walk discarded relative imported names,
# truncated dotted paths to their first component, resolved everything as a flat
# `<name>.py`, and read only `Import`/`ImportFrom` nodes -- so each source below passed
# all 57 tests while carrying a forbidden dependency. No production file is touched by
# any of them.

#: A helper whose only content is a deferred LLM SDK import: invisible to a runtime
#: snapshot, and the payload each ST11-R01 control is trying to reach.
DEFERRED_LLM_HELPER = "def helper():\n    import anthropic\n    return anthropic\n"

#: An engine module, in the shape `workflow.py` really has.
ENGINE_SOURCE = "from dbos import DBOS\n"


def test_d_the_closure_reaches_the_engine_through_a_deferred_relative_import(
    tmp_path: Path,
) -> None:
    """ST11-R01, the plainest form: `from . import workflow` inside a function body.

    The reviewed resolver recorded the *package* and dropped the imported name, then
    looked for a file named after the package. The edge vanished, and with it the
    whole of `workflow`'s DBOS dependency.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "policy.py": "def _probe():\n    from . import workflow\n    return workflow\n",
            "workflow.py": ENGINE_SOURCE,
        },
    )
    reached, external = import_closure(("policy",), root=package)
    assert reached == {"policy", "workflow", "__init__"}
    assert external & FORBIDDEN_ROOTS == {"dbos"}


@pytest.mark.parametrize(
    ("form", "files"),
    [
        (
            "from . import sibling",
            {
                "__init__.py": "",
                "policy.py": (
                    "def _probe():\n    from . import review_bridge\n    return review_bridge\n"
                ),
                "review_bridge.py": DEFERRED_LLM_HELPER,
            },
        ),
        (
            "from .sibling import name",
            {
                "__init__.py": "",
                "policy.py": (
                    "def _probe():\n    from .review_bridge import helper\n    return helper\n"
                ),
                "review_bridge.py": DEFERRED_LLM_HELPER,
            },
        ),
        (
            "from .. import module, written inside a subpackage",
            {
                "__init__.py": "",
                "policy.py": "from gplanner.inner import leaf\n",
                "inner/__init__.py": "",
                "inner/leaf.py": (
                    "def _probe():\n    from .. import review_bridge\n    return review_bridge\n"
                ),
                "review_bridge.py": DEFERRED_LLM_HELPER,
            },
        ),
    ],
    ids=["from-dot-import", "from-dot-module-import", "from-dot-dot-import"],
)
def test_d_the_closure_follows_every_relative_import_form(
    tmp_path: Path, form: str, files: dict[str, str]
) -> None:
    """ST11-R01: all three relative spellings reach the helper, including `..`.

    The third case is the one a flat resolver cannot get right by accident: the
    relative base is the *subpackage* the importing file sits in, and one extra dot
    strips a component from it.
    """
    package = synthetic_package(tmp_path, files)
    reached, external = import_closure(("policy",), root=package)
    assert "review_bridge" in reached, form
    assert external & FORBIDDEN_ROOTS == {"anthropic"}, form


def test_d_the_closure_reaches_a_subpackage_helper_through_a_dotted_import(
    tmp_path: Path,
) -> None:
    """ST11-R01: `from gplanner.review_imports import bridge`, the P19 escape.

    `gplanner.review_imports` was truncated to `gplanner` and resolved as
    `gplanner.py`, which does not exist -- so the subpackage, its initializer and its
    helper were all outside the closure. The dotted path is kept whole here and tried
    as a module *and* as a package.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "policy.py": (
                "def _probe():\n"
                "    from gplanner.review_imports import bridge\n"
                "    return bridge\n"
            ),
            "review_imports/__init__.py": "",
            "review_imports/bridge.py": DEFERRED_LLM_HELPER,
        },
    )
    reached, external = import_closure(("policy",), root=package)
    assert reached == {"policy", "review_imports", "review_imports.bridge", "__init__"}
    assert external & FORBIDDEN_ROOTS == {"anthropic"}


def test_d_the_closure_executes_every_package_initializer_on_the_path(tmp_path: Path) -> None:
    """ST11-R01: importing `a.b.c` runs `a/__init__.py`, so the gate must read it.

    Here the leaf is clean and the *initializer* carries the SDK. A walk that enqueued
    only the leaf would report the closure clean while the import statement it followed
    had already executed the forbidden module.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "policy.py": "def _probe():\n    import gplanner.review_imports.bridge\n",
            "review_imports/__init__.py": "import openai\n",
            "review_imports/bridge.py": "def helper():\n    return None\n",
        },
    )
    reached, external = import_closure(("policy",), root=package)
    assert "review_imports" in reached
    assert "review_imports.bridge" in reached
    assert external & FORBIDDEN_ROOTS == {"openai"}


@pytest.mark.parametrize(
    ("form", "body"),
    [
        (
            "importlib.import_module",
            "def _probe():\n    import importlib\n\n"
            '    return importlib.import_module("anthropic")\n',
        ),
        (
            "module alias",
            'import importlib as il\n\n\ndef _probe():\n    return il.import_module("anthropic")\n',
        ),
        (
            "imported function",
            "from importlib import import_module\n\n\n"
            'def _probe():\n    return import_module("anthropic")\n',
        ),
        (
            "aliased function",
            "from importlib import import_module as load\n\n\n"
            'def _probe():\n    return load("anthropic")\n',
        ),
        (
            "__import__ builtin",
            'def _probe():\n    return __import__("anthropic")\n',
        ),
    ],
    ids=["attribute", "module-alias", "function", "function-alias", "builtin"],
)
def test_d_the_structural_gate_catches_the_conventional_dynamic_loader(
    tmp_path: Path, form: str, body: str
) -> None:
    """ST11-R04: a deferred literal loader call is an import, and is read as one.

    `importlib` is standard library and therefore allowlisted, the call is not an
    import node, and the clean-process probe never runs the function -- so the P21
    mutation escaped both halves of section D. Aliases are covered because a rename is
    the first thing that would defeat a gate keyed on one spelling.
    """
    package = synthetic_package(tmp_path, {"__init__.py": "", "policy.py": body})
    _, external = import_closure(("policy",), root=package)
    assert external & FORBIDDEN_ROOTS == {"anthropic"}, form


def test_d_a_dynamic_first_party_load_is_followed_like_any_other_edge(tmp_path: Path) -> None:
    """ST11-R04 meeting ST11-R01: a literal first-party target is a closure edge.

    `importlib.import_module("gplanner.workflow")` is the same reach into the engine
    that `from . import workflow` is, written the other way.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "policy.py": (
                "import importlib\n\n\n"
                'def _probe():\n    return importlib.import_module("gplanner.workflow")\n'
            ),
            "workflow.py": ENGINE_SOURCE,
        },
    )
    reached, external = import_closure(("policy",), root=package)
    assert "workflow" in reached
    assert external & FORBIDDEN_ROOTS == {"dbos"}


def test_d_a_computed_dynamic_import_target_is_not_claimed_to_be_detected(
    tmp_path: Path,
) -> None:
    """The boundary of the ST11-R04 claim, stated as a passing test rather than implied.

    Resolving `import_module(name)` for a computed `name` means evaluating the module,
    which is the general static analyser this gate is not and GP-SPK-001 does not
    claim to be. What *is* closed is the conventional literal route. Recording the
    limit here keeps the gate's strength readable, in the same spirit as section F.

    Note also what the gate does see: `importlib` is collected as an ordinary external
    root. It is filtered out of the allowlist assertion only because it is standard
    library, not because the walk missed it.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "policy.py": (
                "import importlib\n\n\n"
                "def _probe(name):\n    return importlib.import_module(name)\n"
            ),
        },
    )
    _, external = import_closure(("policy",), root=package)
    assert not external & FORBIDDEN_ROOTS
    assert "importlib" in external


def test_d_a_clean_process_importing_the_governance_layer_loads_no_forbidden_module() -> None:
    """The runtime half, in a fresh interpreter (the ST-9 discovery).

    A second mechanism rather than a restatement: this one observes what the interpreter
    actually loaded, including anything a dependency might drag in behind the package's
    own import statements, which a source walk cannot see.
    """
    result = in_clean_process(probe_program(GOVERNANCE_SEEDS))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


def test_d_the_clean_process_probe_detects_the_engine_when_it_is_present() -> None:
    """The negative control for the runtime probe.

    The same program, seeded with `workflow`, reports `dbos`. An empty result above is
    therefore evidence about the governance layer and not about a probe that reports
    nothing whatever it is pointed at.
    """
    result = in_clean_process(probe_program(("workflow",)))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ["dbos"]


def test_d_app_and_workflow_remain_the_only_modules_importing_the_engine() -> None:
    """§4's boundary rule, over every file in the package."""
    assert engine_importers(SRC) == set(ENGINE_MODULES)


def test_d_the_engine_boundary_scan_reaches_nested_modules(tmp_path: Path) -> None:
    """The §4 scan was flat too, for the same reason the decode scans were.

    Rebuilt recursively alongside them: a nested module importing the engine is an
    engine importer, whatever directory it sits in.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "workflow.py": ENGINE_SOURCE,
            "review_probe/__init__.py": "",
            "review_probe/engine.py": "def go():\n    import dbos\n",
        },
    )
    assert engine_importers(package) == {"workflow", "review_probe/engine"}


# =================================================================================
# Section E — (e) one decode path, with the gate itself tested
# =================================================================================


def test_e_the_package_has_exactly_one_json_to_domain_path() -> None:
    """The gate, over the real package: no offence anywhere."""
    assert decode_gate(SRC) == []


@pytest.mark.parametrize(
    ("bypass", "body"),
    [
        ("import json", "import json\n"),
        ("import json as j", "import json as j\n"),
        ("from json import loads", "from json import loads\n"),
    ],
)
def test_e_the_decode_gate_catches_each_of_the_three_json_import_forms(
    tmp_path: Path, bypass: str, body: str
) -> None:
    """Plan §18(e): the gate is *verified against all three bypasses*, not merely written.

    Keying on imports rather than call shape is precisely what makes the alias and
    `from`-forms detectable (plan R-11); asserting that here is what turns the claim
    into evidence. The three files live in `tmp_path`.
    """
    (tmp_path / "kernel.py").write_text(body, encoding="utf-8")
    offences = decode_gate(tmp_path)
    assert len(offences) == 1, (bypass, offences)
    assert offences[0].startswith("kernel.py:1:")


def test_e_the_decode_gate_permits_the_same_import_in_codec_only(tmp_path: Path) -> None:
    """The exemption is real and is exactly one file wide."""
    (tmp_path / "codec.py").write_text("import json\n", encoding="utf-8")
    assert decode_gate(tmp_path) == []
    (tmp_path / "store.py").write_text("import json\n", encoding="utf-8")
    assert [offence.split(":")[0] for offence in decode_gate(tmp_path)] == ["store.py"]


def test_e_the_decode_gate_catches_model_validate_even_inside_codec(tmp_path: Path) -> None:
    """`model_validate` is forbidden everywhere, `codec.py` included (§7).

    The forbidden two-step fails only at run time, only on the decode path, and reads as
    natural code — which is why the ban is package-wide rather than a convention.
    """
    (tmp_path / "codec.py").write_text(
        "def f(blob, Model):\n    return Model.model_validate(blob)\n", encoding="utf-8"
    )
    assert [offence.split(": ")[1] for offence in decode_gate(tmp_path)] == ["model_validate"]


def test_e_the_decode_gate_is_not_fooled_by_prose_naming_the_pattern() -> None:
    """Read from the syntax tree, so a docstring explaining the ban is not an offence.

    `codec.py` and `approvals.py` both describe `json.loads` + `model_validate` in prose;
    both are clean. A text-matching gate would report them and would then be turned off.
    """
    assert "model_validate" in source("codec")
    assert "json.loads" in source("approvals")
    assert decode_gate(SRC) == []


def test_e_no_production_module_builds_a_domain_object_past_validation() -> None:
    """The bypass section C uses deliberately exists nowhere in production source.

    `model_construct`, `parse_obj`, `parse_raw` and `construct` each turn an unchecked
    mapping into an authoritative object. Section C uses `model_construct` to prove the
    policy layer refuses independently; production must never need it, or the decode
    boundary would have a hole beside it.
    """
    assert unchecked_construction(SRC) == []


def test_e_codec_is_the_only_module_that_converts_json_into_a_domain_object() -> None:
    """The positive half of (e): the one path, named.

    `model_validate_json` appears in `codec.py` and nowhere else, twice — once for the
    stored preimage envelope, once for the approval transport — which is exactly the two
    frozen decode sites (§7).
    """
    holders = json_to_domain_holders(SRC)
    assert {name: count for name, count in holders.items() if count} == {"codec": 2}


# --- ST11-R02 / ST11-R03 negative controls ---------------------------------------
#
# Each of the three decode-boundary scans was `glob('*.py')`, so a subpackage was
# invisible to all of them at once, and the `ImportFrom` branch matched only the exact
# module name `json`. The four sources below are the discovery review's escapes, and
# each is now required to be reported.


def test_e_the_decode_gate_scans_nested_packages_for_raw_json_decoding(tmp_path: Path) -> None:
    """ST11-R02: the forbidden two-step, one directory down (the P16 escape)."""
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "codec.py": "",
            "review_probe/__init__.py": "",
            "review_probe/decode.py": (
                "import json\n"
                "from gplanner.approvals import ApprovalStatement\n\n\n"
                "def decode(blob):\n"
                "    return ApprovalStatement.model_validate(json.loads(blob))\n"
            ),
        },
    )
    offences = decode_gate(package)
    assert [offence.split(": ", 1)[1] for offence in offences] == [
        "imports json",
        "model_validate",
    ]
    assert all(offence.startswith("review_probe/decode.py:") for offence in offences)


def test_e_the_unchecked_construction_gate_scans_nested_packages(tmp_path: Path) -> None:
    """ST11-R02: validation-free construction, one directory down (the P17 escape)."""
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "review_probe/__init__.py": "",
            "review_probe/decode.py": (
                "from gplanner.approvals import ScopeApprovalPredicate\n\n\n"
                "def decode(mapping):\n"
                "    return ScopeApprovalPredicate.model_construct(**mapping)\n"
            ),
        },
    )
    assert unchecked_construction(package) == ["review_probe/decode.py:5: model_construct"]


def test_e_the_one_decode_path_claim_scans_nested_packages(tmp_path: Path) -> None:
    """ST11-R02: `model_validate_json` outside codec, one directory down (P18).

    The positive claim -- "`codec` is the only module that converts JSON into a domain
    object" -- is only as wide as the scan behind it. Over a flat glob it was a claim
    about the package root.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "codec.py": "",
            "review_probe/__init__.py": "",
            "review_probe/decode.py": (
                "from gplanner.approvals import ApprovalStatement\n\n\n"
                "def decode(blob):\n"
                "    return ApprovalStatement.model_validate_json(blob)\n"
            ),
        },
    )
    holders = json_to_domain_holders(package)
    assert {name: count for name, count in holders.items() if count} == {"review_probe/decode": 1}


def test_e_the_codec_exemption_is_the_root_module_not_a_nested_namesake(tmp_path: Path) -> None:
    """Recursion must not widen the exemption: there is exactly one approved codec.

    Exempting on `path.name` alone would have turned `sub/codec.py` into a second
    decode boundary the moment the scan became recursive -- trading one false negative
    for another. The exemption is the file at the package root.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "codec.py": "import json\n",
            "review_probe/__init__.py": "",
            "review_probe/codec.py": "import json\n",
        },
    )
    assert decode_gate(package) == ["review_probe/codec.py:1: imports json"]


@pytest.mark.parametrize(
    "where", ["approvals.py", "review_probe/decode.py"], ids=["flat", "nested"]
)
def test_e_the_decode_gate_catches_a_json_submodule_from_import(
    tmp_path: Path, where: str
) -> None:
    """ST11-R03: `from json.decoder import JSONDecoder` is a raw decode path (P20).

    The `Import` branch already matched `json.*`; the `ImportFrom` branch matched only
    the exact name, so the submodule spelling parsed JSON into unchecked Python data
    outside `codec` with all 57 tests green. Asserted flat and nested, because the two
    defects composed: the flat escape needed only ST11-R03, the nested one needs
    ST11-R02 as well.
    """
    files = {
        "__init__.py": "",
        "codec.py": "",
        where: (
            "def decode(blob):\n"
            "    from json.decoder import JSONDecoder\n\n"
            "    return JSONDecoder().decode(blob)\n"
        ),
    }
    if "/" in where:
        files[f"{where.rsplit('/', 1)[0]}/__init__.py"] = ""
    package = synthetic_package(tmp_path, files)
    assert decode_gate(package) == [f"{where}:2: from json import ..."]


def test_e_the_json_submodule_ban_does_not_reach_a_first_party_namesake(tmp_path: Path) -> None:
    """A *relative* `from .json import ...` is a first-party module, not the stdlib one.

    It is scanned on its own account like any other module in the tree. Reporting it as
    a stdlib JSON import would be a false positive, and a gate that cries wolf is a gate
    someone turns off.
    """
    package = synthetic_package(
        tmp_path,
        {
            "__init__.py": "",
            "codec.py": "",
            "store.py": "from .json import helper\n",
            "json.py": "def helper():\n    return None\n",
        },
    )
    assert decode_gate(package) == []


# =================================================================================
# Section F — what GP-11 does NOT prove (§11), recorded rather than quietly improved
# =================================================================================


def test_f_the_limiting_claim_is_recorded_verbatim_in_the_design_baseline() -> None:
    """Plan §18 mandates this sentence **verbatim** in the design document.

    The plan names three verbatim locations: `docs/gp-spk-001-validation.md`, that
    document's requirement-11 row, and `design/GP-SPK-001-governance-kernel.md`. Only
    the last exists yet -- the validation document is ST-12's obligation -- so only the
    last is asserted. Requiring a document this stage is not authorized to write would
    make GP-11 fail for a reason that has nothing to do with authority.
    """
    text = (REPO / "design" / "GP-SPK-001-governance-kernel.md").read_text(encoding="utf-8")
    collapsed = " ".join(text.replace("**", "").replace(">", " ").split())
    assert LIMITING_CLAIM in collapsed


def test_f_claude_md_records_the_gap_under_known_gaps() -> None:
    """Plan §18's *separate*, weaker obligation for `CLAUDE.md`, asserted as written.

    The plan requires the verbatim sentence in the documents above; what it requires of
    `CLAUDE.md` is that the gap is "recorded as such ... under *Known gaps*". So this
    asserts the substance the plan names -- label, unproven identity, the signing stage,
    and a pointer to §11 -- and does not demand a wording the plan never mandated there.
    """
    text = (REPO / "CLAUDE.md").read_text(encoding="utf-8")
    known_gaps = text.split("## Known gaps", 1)
    assert len(known_gaps) == 2, "CLAUDE.md must carry a Known gaps section"
    collapsed = " ".join(known_gaps[1].replace("*", "").split())
    for phrase in ("unsigned and unauthenticated", "is a label", "not proven", "signing"):
        assert phrase in collapsed, phrase
    assert "design §11" in collapsed


@pytest.mark.parametrize("module_name", ["approvals", "kernel", "workflow"])
def test_f_every_module_that_touches_authority_records_the_same_limit(
    module_name: str,
) -> None:
    """The limit travels with the code, not only with the documentation."""
    docstring = ast.get_docstring(ast.parse(source(module_name)))
    assert docstring is not None
    collapsed = " ".join(docstring.replace("**", "").replace(">", " ").split())
    assert LIMITING_CLAIM in collapsed, module_name


def test_f_an_arbitrary_unauthenticated_approver_id_is_accepted(
    pending: tuple[Store, str], h: Harness
) -> None:
    """The gap itself, demonstrated — this is a limitation, not a defect to fix here.

    `approver_id` is an opaque label that nothing verifies. A statement claiming an
    approver that plainly is not the one the case belongs to is accepted and drives the
    edge, because GP-SPK-001 has no way to tell. That is what the mandated sentence
    means, stated as a passing test so the spike's verdict cannot be read as stronger
    than it is.

    What *is* enforced, and is the whole of requirement 11: the **label**. Every test in
    sections B and C above refuses `LLM` regardless of who claims it.
    """
    opened, subject_digest = pending
    statement = codec.decode_approval(
        wire(subject_digest, approver_kind="HUMAN", approver_id="definitely-not-a-human")
    )
    outcome = kernel.apply_scope_approval(opened, WORKFLOW_ID, statement)

    assert outcome.applied is True
    assert outcome.state is ScopeState.SCOPE_APPROVED
    assert statement.predicate.approver_id == "definitely-not-a-human"


def test_f_nothing_in_the_package_claims_to_authenticate_or_sign(h: Harness) -> None:
    """§2 and §20: signing and identity authentication are deferred, not partially done.

    A module that imported a signing or crypto library would be the beginning of the
    claim §11 says this spike does not make. The allowlist in section D already excludes
    them; this states the absence in the vocabulary a reader of §11 will look for.
    """
    _, external = import_closure(GOVERNANCE_SEEDS)
    signing_roots = {"cryptography", "nacl", "jwt", "dsse", "securesystemslib", "hmac", "ssl"}
    assert not external & signing_roots
    assert "hashlib" in external, "hashing is identity (§6), and is the only crypto here"


def test_f_the_approval_record_carries_no_signature_field() -> None:
    """§8: the statement *is* the payload a signature would later cover, and is unsigned.

    A field named for a signature, present but unchecked, would be the most readable
    possible overclaim: an auditor would see one and assume something verified it.
    """
    fields = set(ApprovalStatement.model_fields) | set(ScopeApprovalPredicate.model_fields)
    for name in fields:
        assert "signature" not in name.lower()
        assert "signed" not in name.lower()
    assert "signatures" not in fields, "no DSSE envelope exists in GP-SPK-001"
