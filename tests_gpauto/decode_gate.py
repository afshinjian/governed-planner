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

**Why this is a separate invocation rather than an extension of the spike's gate.**
`SD11-10` keeps GP-SPK-001's test modules untouched — they are that stage's closed
evidence — so the GP-AUTO gate is its own module over its own scope, applying the same
rule (`SD11-12b`).

**At `GP-AUTO-ST-01` the expected number of `json` importers is zero, not one.**
`GP-AUTO-ST-01` creates no codec — that is `GP-AUTO-ST-02`'s — so there is nothing to
exempt, and the gate carries no exemption at all. When the codec lands, the exemption
it needs is that stage's to add, under that stage's authorization.

Runnable on its own: `python tests_gpauto/decode_gate.py`.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

if __package__ in (None, ""):  # pragma: no cover - only when run as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_scope import REPOSITORY_ROOT, gpauto_source_files


def offenders() -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """`(paths inspected, findings)` over the configured GP-AUTO scope.

    The inspected-path list is returned rather than logged, because `SD11-12b`'s first
    half requires the gate to *enumerate what it inspected*: a gate reporting success
    over an empty list is a verification defect, and a caller that cannot see the list
    cannot tell the difference.
    """
    inspected = gpauto_source_files()
    findings: list[str] = []
    for relative in inspected:
        tree = ast.parse((REPOSITORY_ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "json" or alias.name.startswith("json."):
                        findings.append(f"{relative}:{node.lineno}: imports json")
            elif isinstance(node, ast.ImportFrom) and (node.module or "") == "json":
                findings.append(f"{relative}:{node.lineno}: from json import")
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
    print("\nNo findings: no `json` import and no `model_validate` in GP-AUTO code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
