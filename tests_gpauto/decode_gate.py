"""The GP-AUTO decode / import gate — a separate GP-AUTO equivalent of the frozen one.

Design basis: `CLAUDE.md` "JSON ingestion — one path, enforced"; AP-11 §14 (`SD11-4`,
`SD11-12a`(ii), `SD11-12b`), §16 (`GP-AUTO-ST-01` static gates); `DC-1`, `DC-2`.

The frozen rule, unchanged: domain models are `strict=True` with `tuple[...]` fields,
strict validation refuses a `list`, and `json.loads` produces lists — so
`json.loads(...)` + `model_validate(...)` fails at run time on a *valid* artifact, and
only on the decode path, which is exercised less than encode. `model_validate_json` is
the sole permitted entry point.

**The method is the frozen one and is not re-invented.** The gate keys on *imports*
rather than call shape, so `import json as j` and `from json import loads` are caught
too, and it reads the syntax tree rather than the source text, so a docstring naming
the pattern is not mistaken for using it.

**It keys on the import *root*, not on a spelling.** `json` is a package, so
`from json.decoder import JSONDecoder` reaches the same decoder the frozen rule exists
to keep behind one boundary — and a gate matching only the module name `json` would
have let it through. Every import **rooted in** the `json` package is a finding: the
bare module, any alias, any submodule, any alias of a submodule, and any `from` import
naming the package or one of its submodules. Matching on the root is what makes the
rule import-keyed rather than spelling-specific, so a submodule nobody anticipated is
covered by the same line that covers `json` itself.

Only **absolute** imports match. A relative `from .json import x` names a local module
that happens to share the name and is not the standard library's package; the GP-AUTO
package has no such module, so the distinction changes nothing today and keeps the rule
saying what it means.

**Why this is a separate invocation rather than an extension of the spike's gate.**
`SD11-10` keeps GP-SPK-001's test modules untouched — they are that stage's closed
evidence — so the GP-AUTO gate is its own module over its own scope, applying the same
rule (`SD11-12b`).

**At `GP-AUTO-ST-01` the expected number of `json` importers is zero, not one.**
`GP-AUTO-ST-01` creates no codec — that is `GP-AUTO-ST-02`'s — so there is nothing to
exempt, and the gate carries no exemption at all. When the codec lands, the exemption
it needs is that stage's to add, under that stage's authorization.

**At `GP-AUTO-ST-02` the codec exists, and still needs no exemption.** It decodes
through `model_validate_json`, which takes bytes, so it imports no `json` either: the
expected number of `json` importers stays **zero**, exactly as the spike's own gate
expects of `gplanner/codec.py`. Nothing above is relaxed.

**What `GP-AUTO-ST-02` adds is the rule that makes the gate load-bearing** (`DC-1`,
`SD11-12b`): *every JSON → domain conversion lives behind one enforced codec
boundary*. In the production package, `model_validate_json` may appear only in
`CODEC_MODULE`, and `validate_json` — a JSON → domain path that is not
`model_validate_json` at all — may appear nowhere. The rule is scoped to the
production package because that is where the boundary is; the test tree exercises
models directly, as the spike's does, and the `json`-import and `model_validate` rules
continue to cover it unchanged. This rule is **additive**: it can only produce more
findings, never fewer.

Runnable on its own: `python tests_gpauto/decode_gate.py`.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

if __package__ in (None, ""):  # pragma: no cover - only when run as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_scope import REPOSITORY_ROOT, configured_package_path, gpauto_source_files

CODEC_MODULE = "codec.py"
"""The one production module permitted to turn JSON into a domain object (`DC-1`)."""

JSON_PACKAGE_ROOT = "json"
"""The standard-library package no GP-AUTO module may import from, at any depth."""


def rooted_in_json(module: str) -> bool:
    """Is `module` the `json` package or anything inside it?

    `json` matches; `json.decoder` and any deeper submodule match; `jsonschema` does
    **not** — the dot is what makes it a submodule rather than a longer name.
    """
    return module == JSON_PACKAGE_ROOT or module.startswith(f"{JSON_PACKAGE_ROOT}.")


def offenders() -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """`(paths inspected, findings)` over the configured GP-AUTO scope.

    The inspected-path list is returned rather than logged, because `SD11-12b`'s first
    half requires the gate to *enumerate what it inspected*: a gate reporting success
    over an empty list is a verification defect, and a caller that cannot see the list
    cannot tell the difference.
    """
    inspected = gpauto_source_files()
    package = configured_package_path().relative_to(REPOSITORY_ROOT)
    codec = package / CODEC_MODULE
    findings: list[str] = []
    for relative in inspected:
        tree = ast.parse((REPOSITORY_ROOT / relative).read_text(encoding="utf-8"))
        in_package = relative.is_relative_to(package)
        for node in ast.walk(tree):
            if in_package and isinstance(node, ast.Attribute):
                if node.attr == "model_validate_json" and relative != codec:
                    findings.append(f"{relative}:{node.lineno}: JSON decode outside the codec")
                elif node.attr == "validate_json":
                    findings.append(f"{relative}:{node.lineno}: validate_json")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if rooted_in_json(alias.name):
                        findings.append(f"{relative}:{node.lineno}: imports {alias.name}")
            elif (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and rooted_in_json(node.module or "")
            ):
                findings.append(f"{relative}:{node.lineno}: from {node.module} import")
            elif isinstance(node, ast.Attribute) and node.attr == "model_validate":
                findings.append(f"{relative}:{node.lineno}: model_validate")
    return inspected, tuple(findings)


def main() -> int:
    inspected, findings = offenders()
    print(f"GP-AUTO decode/import gate — inspected {len(inspected)} file(s):")
    for relative in inspected:
        print(f"  {relative}")
    if findings:
        print("\nFINDINGS:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(
        "\nNo findings: no import rooted in the `json` package and no `model_validate` in"
        " GP-AUTO code, and no JSON decode in the package outside the codec."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
