# governed-planner

Upstream planning system for the sibling `governed-runtime` execution runtime.

The intended pipeline is Owner → Scoper → Scope Spec → approval → Designer →
review → approval → Planner → authorization → `HANDOFF_CONTRACT` →
`governed-runtime`.

**None of those AI planning layers is authorized for implementation.** Every stage
is LLM-driven, so building them first would mean the governance properties — who
may authorize what, against which exact artifact, how many times — could only ever
be observed through a non-deterministic component.

This repository currently contains one bounded feasibility spike, **GP-SPK-001**,
whose objective is to prove the governance authority model with zero LLM
involvement over the narrowest useful slice:

```
SCOPE_DRAFTING -> SCOPE_REVIEW_PENDING -> SCOPE_APPROVED
```

It returns a PASS/FAIL verdict on three candidate decisions: content-addressed
artifact identity (RFC 8785 JCS + SHA-256), digest-bound single-use approvals, and
DBOS-on-SQLite as the durable workflow engine.

## Design

`design/GP-SPK-001-governance-kernel.md` is the authoritative baseline. Code cites
its sections. Start there.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
.venv/bin/ruff check src tests
.venv/bin/mypy --strict src/gplanner
```

## Status

GP-SPK-001 is in progress. The verdict will be recorded in
`docs/gp-spk-001-validation.md`, per requirement, with the exact commands run and
their actual output.
