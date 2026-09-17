# GP-SPK-001 — Governance Kernel Feasibility

Status: design baseline for the spike. Authoritative; code cites its sections.
Plan of record: revision 5, approved 2026-09-15.

---

## §1 Purpose and the reason for the ordering

`governed-planner` will become the upstream planning system that feeds
`HANDOFF_CONTRACT` artifacts into `governed-runtime`. The intended pipeline is
Owner → Scoper → Scope Spec → approval → Designer → review → approval → Planner →
authorization → handoff.

Every stage of that pipeline is LLM-driven. Building them first would mean the
governance properties — who may authorize what, against which exact artifact, how
many times — could only ever be observed through a non-deterministic component. A
wrongly authorized transition could then never be attributed to the authority
model versus the model output.

GP-SPK-001 inverts the order. It sets out to prove the authority model with **zero
LLM involvement**, over the narrowest useful slice, and to return a PASS/FAIL
verdict on three candidate decisions:

1. content-addressed artifact identity (RFC 8785 JCS + SHA-256);
2. digest-bound, single-use approvals;
3. DBOS-on-SQLite as the durable workflow engine.

No planning agent is authorized for implementation until that verdict exists.

## §2 Scope

In scope: `SCOPE_DRAFTING → SCOPE_REVIEW_PENDING → SCOPE_APPROVED`, driven by
deterministic code plus one human-labelled approval record.

Out of scope, binding — not built, not stubbed, not imported: Scoper / Designer /
Reviewer / Planner agents; any LLM call, SDK, prompt, or `anthropic`/`openai`
import; cryptographic signing; `SCOPE_REJECTED`, revision loops, or any state
beyond the three above; `HANDOFF_CONTRACT`; any read or write of
`governed-runtime`; Spec Kit, OpenSpec, Serena, BrownKit; web UI; any CLI beyond
the test harness; Postgres, DBOS queues, multi-executor, Conductor; schema
migrations; mutation-testing tooling.

## §3 States and the transition table

| State | Meaning |
|---|---|
| `SCOPE_DRAFTING` | A scope specification exists and may still change. |
| `SCOPE_REVIEW_PENDING` | Submitted; awaiting a human approval bound to its exact digest. |
| `SCOPE_APPROVED` | Terminal in this spike. |

`ActorKind` is `HUMAN`, `SYSTEM`, `LLM`. `LLM` exists **precisely so it can be
proven never sufficient** (§9). Asserting that over the table is stronger evidence
than asserting it over current call sites.

| Row | From | To | Authority | Approval required |
|---|---|---|---|---|
| `SPK1-1` | `SCOPE_DRAFTING` | `SCOPE_REVIEW_PENDING` | `SYSTEM` | no |
| `SPK1-2` | `SCOPE_REVIEW_PENDING` | `SCOPE_APPROVED` | `HUMAN` | yes |

There are 9 ordered pairs over 3 states. Exactly 2 are legal. The other 7 — all
three self-loops (including `SCOPE_APPROVED → SCOPE_APPROVED`), both backward
edges, the `DRAFTING → APPROVED` skip, and `APPROVED → REVIEW_PENDING` — refuse
with `REFUSE_NOT_IN_GRAPH`. No legal edge names `ActorKind.LLM`.

## §4 Module boundaries

The boundaries are load-bearing, not organizational. They are what make
requirements 6 and 11 testable with no workflow engine present.

| Rule | Consequence |
|---|---|
| `artifacts` imports neither `states` nor `approvals` | identity is a pure function of content |
| `policy` imports neither `store` nor `dbos` | legality is decidable with no I/O |
| `kernel` does not import `dbos` | the authority model is provable with the engine absent |
| `codec` is the only JSON → domain boundary | exactly one decode path (§7) |
| `workflow`/`app` are the only importers of `dbos` | the engine supplies durability, never decisions |

`store` stores, re-verifies digests, and enforces uniqueness. It never decides
whether a transition is legal. `kernel` is the only mutator of case state.

## §5 Canonicalization — two separate layers

**Layer 1, `canonical`: genuine RFC 8785 / JCS.** Accepts every valid JSON value,
including finite floats, booleans and `null`. Refuses only non-JSON values
(non-`str` mapping keys, `NaN`/`Infinity`, `bytes`, `set`, `Decimal`, `datetime`).
It never coerces and applies no application policy.

**Layer 2, `profile`: `gplanner.payload-profile/1`.** A named, versioned
governed-planner restriction on what may appear in a content-addressed payload.
Permits objects with string keys, arrays, strings, booleans, integers. Forbids two
values JCS itself accepts:

- **floats** — JCS serializes `1.0` as `1`, so two distinct values would map to one
  identity. Reject rather than silently coerce.
- **`null`** — absent-key versus `null`-key changes the digest, and `exclude_none`
  would make that configuration-dependent.

This restriction is **not** described as RFC 8785 anywhere, and `PAYLOAD_PROFILE`
is recorded inside every hashed preimage so a verifier knows which subset produced
the digest.

Fixed order: Pydantic validation → `model_dump(mode="json")` → profile guard →
JCS → UTF-8 bytes → SHA-256.

## §6 Identity

```
PREIMAGE_VERSION = "gplanner.preimage/1+jcs-rfc8785"
preimage = {preimage_version, payload_profile, media_type, payload}
digest   = "sha256:" + sha256(rfc8785.dumps(preimage)).hexdigest()
```

`artifacts.canonical_preimage` stores the **exact bytes** fed to SHA-256, so
`sha256(canonical_preimage)` reproduces the digest directly, with no
re-serialization anywhere on the read path. There is exactly one authoritative
stored byte representation.

Three properties, each answering a defect observed in `governed-runtime`:

1. **Domain separation** — `media_type` is inside the hashed preimage, so a
   `ScopeSpec` digest can never equal an `ApprovalStatement` digest with the same
   payload.
2. **Algorithm recorded in the artifact** — `governed-runtime` can read
   `preimage_version` and `payload_profile` and know which scheme produced the
   digest.
3. **Externally reproducible** — the preimage is plain JSON; a third party can
   reconstruct it and run `sha256sum`.

Wire format is `sha256:<64 lowercase hex>`. in-toto's `subject[].digest` is
`{"sha256": "<bare hex>"}` without the prefix; `digest` owns the conversion in one
place.

## §7 JSON ingestion — one frozen path

Domain models use `ConfigDict(strict=True)` with `tuple[...]` fields. Strict
validation rejects a `list`, and `json.loads` produces lists. Therefore:

> **`json.loads(...)` followed by `model_validate(...)` is forbidden package-wide.**

Every JSON → domain conversion uses Pydantic's JSON-aware validation, which maps
JSON arrays to tuples while keeping strict member checking. All of it lives in
`codec`.

Artifact recovery is a single parse of the authoritative bytes through a validated
envelope, not an extract-and-re-serialize:

```python
class ScopePreimage(BaseModel):
    # The envelope carries the SAME guarantees as the domain model it wraps.
    # Not inherited, not implied by the nested model: it must be stated here.
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    preimage_version: Literal[PREIMAGE_VERSION]   # foreign scheme REFUSED, not decoded
    payload_profile:  Literal[PAYLOAD_PROFILE]
    media_type:       Literal[SCOPE_MEDIA_TYPE]
    payload:          ScopeSpec

def decode_scope_from_preimage(blob: bytes) -> ScopeSpec:
    return ScopePreimage.model_validate_json(blob).payload
```

**`model_config` on the envelope is load-bearing and is not optional.** Pydantic's
default is to *ignore* unknown fields, and configuration is per-class: the nested
`ScopeSpec`'s strictness says nothing about the envelope. Measured on pydantic
2.13.5, an envelope declared without `model_config` has `model_config == {}`,
**accepts an unknown top-level field and silently discards it**, and is **mutable**.
With the configuration above the same input is rejected with `extra_forbidden`.

What `extra="forbid"` does and does not establish. It **enforces the approved
envelope schema**: a preimage carrying a field this design never defined is
refused outright rather than silently ignored, so undeclared envelope data can
never be accepted and then dropped on the floor.

It does **not** establish that every distinct accepted byte string decodes to a
distinct domain object, and no claim to that effect should be read into it. Two
inputs differing only in insignificant JSON whitespace have different SHA-256
values yet decode to equal `ScopeSpec` objects — decode is not injective over
arbitrary accepted JSON, with or without this setting.

Nor is that what `GK-INV-1` asserts. `GK-INV-1` is about the **authoritative
canonical preimage bytes** and their digest relationship: identity is
`sha256(canonical_preimage)`, those stored bytes are the single authoritative
representation, and they always rehash to their digest. **Canonical production and
schema validation are separate contracts.** §5's fixed pipeline is what makes the
stored bytes canonical; the envelope schema governs what may be accepted when
reading them back. Neither substitutes for the other.

- `extra="forbid"` — an unrecognized envelope field is refused, never dropped.
- `strict=True` — no coercion of the envelope's own fields.
- `frozen=True` — a decoded envelope cannot be mutated after the digest is checked.

The single `model_validate_json` parse is unchanged; the configuration constrains
that parse, it does not add a second one.

Re-emitting the extracted payload as JSON would place a second, plausible-looking
serialization path beside the identity path — the drift that produced
`governed-runtime`'s two incompatible canonicalizers.

Approval transport is **JSON text**, sent with
`WorkflowSerializationFormat.PORTABLE` so DBOS stores it as JSON rather than
pickle. `workflow` holds the sole transport-decoding adapter; the kernel signature
takes an `ApprovalStatement` and never a `dict`.

## §8 Approval record

in-toto Statement v1 shape, greenfield (`governed-runtime` has no in-toto usage).
Unsigned: the statement *is* the payload a signature would later cover.

Structurally constrained: exactly one `subject`; digest `^[0-9a-f]{64}$`;
`approval_id` `^[0-9a-f]{32}$`; bounded `workflow_id` and `approver_id`;
`approver_kind` is `Literal[HUMAN]`; `decision` is `Literal["APPROVE"]`;
`issued_at` RFC 3339 with offset.

Deliberately **not** validated, and why:

| Field | Not validated | Reason |
|---|---|---|
| `approval_id` | UUID v4 version/variant bits | `HEX32` checks 32 lowercase hex only. uuid4 is relied on for **generation** — unpredictability and uniqueness. Validating version bits would assert something the encoding cannot establish about a value's origin: a false assurance on an authority-bearing field. |
| `issued_at` | semantics | Syntax only. No trusted clock, no freshness, no TTL, no ordering. |
| `approver_id` | authenticity | An opaque, unauthenticated label. See §11. |

The record is **immutable**. Consumption is a fact recorded elsewhere
(`approval_consumptions`), so the statement's digest never changes and no field
needs excluding from any preimage.

## §9 Invariants

| ID | Statement |
|---|---|
| `GK-INV-1` | Artifact identity is `sha256(canonical_preimage)`; the stored preimage bytes are the single authoritative representation and always rehash to their digest. |
| `GK-INV-2` | An approval authorizes exactly one `(subject_digest, workflow_id, from_state → to_state)` tuple. |
| `GK-INV-3` | An `approval_id` authorizes at most one committed transition, across processes and across restarts. A replay of that same committed transition changes nothing and is reported as a replay. |
| `GK-INV-4` | Only a statement **labelled** `ActorKind.HUMAN` may authorize `SCOPE_REVIEW_PENDING → SCOPE_APPROVED`. *(Label only — §11.)* |
| `GK-INV-5` | No edge in `LEGAL_TRANSITIONS` names `ActorKind.LLM` as its authority. |
| `GK-INV-6` | The kernel decides and never orchestrates; the workflow orchestrates and never decides. |

## §10 Approval application — replay-first ordering

All steps inside one `BEGIN IMMEDIATE` transaction:

1. Load the case.
2. Validate the statement; compute `approval_digest`.
3. **Look up `approval_id` in `approval_consumptions` — before any transition evaluation.**
4. If a consumption row exists:
   - all of `approval_digest`, `workflow_id`, `subject_digest`, `from_state`,
     `to_state` match **and** the case is already in `to_state` → idempotent replay:
     return `ApplyOutcome(state=to_state, applied=False)`, writing nothing;
   - otherwise → `ApprovalReplay`.
5. Only when no consumption row exists: check legality and authority; workflow
   binding; `from_state` binding; subject digest (→ `StaleApproval`); re-derive the
   digest from the **stored bytes**; claim the approval; CAS-advance the case;
   append **exactly one** audit event; commit.

**Why step 3 precedes step 5.** After the first successful transition the case is
`SCOPE_APPROVED`. A replayed step would evaluate `SCOPE_APPROVED → SCOPE_APPROVED`,
find no such edge, and raise `IllegalTransition` before ever reaching the
idempotency branch. DBOS steps are at-least-once, so this is not hypothetical.

All policy checks precede consumption, so a refused approval is never burnt.
Consumption and the state update are adjacent in one transaction.

`BEGIN IMMEDIATE` takes the write lock at `BEGIN`, so concurrent submission of the
same statement is deterministic, not a tolerated race: exactly one `applied=True`,
one `applied=False`, one consumption row, one audit event.

## §11 What this spike proves about authority — and what it does not

Signing and identity authentication are deferred, so the verdict must not
overclaim.

**Must prove** (proof obligation on GP-11; not yet established — see §13.1):
no edge names `ActorKind.LLM`; `LLM` is refused on every ordered pair;
a statement carrying `approver_kind="LLM"` or `"SYSTEM"` fails validation before
reaching the kernel; the governance layer imports no LLM SDK.

**Not proven:** that the approval was produced by the claimed human. The approval
channel is unauthenticated — anyone able to call `DBOSClient.send` against the
system database can mint a statement labelled `HUMAN` with an arbitrary
`approver_id`, and nothing here detects it.

> **HUMAN authority label enforced; human identity/authenticity not proven until
> the signing/authentication stage.**

## §12 Storage boundary

Two databases, never joined.

`dbos_sys.sqlite` is DBOS's own and is **opaque**: never read, written, or queried
by governance code. Test code touches it only through DBOS's public API.

`governance.sqlite` is ours — stdlib `sqlite3`, no ORM, WAL, `synchronous=FULL`,
`foreign_keys=ON`, `busy_timeout=10000`, STRICT tables, refuse-on-stale-schema with
no migration path.

Single-use rests on the `approval_id` PRIMARY KEY plus a `SELECT` under
`BEGIN IMMEDIATE`. It depends on DBOS in no way.

**Explicit trade-off:** the governance commit and DBOS's step checkpoint are *not*
one transaction. A crash between them re-runs the step on recovery. That is not a
defect to engineer away — it is the condition under which `GK-INV-3` must hold, and
GP-10b will test it directly (§13.1, requirement 10). That test does not yet exist.

## §13 PASS / FAIL

### §13.1 The eleven requirements and their acceptance evidence

**None of the rows below is yet satisfied.** ST-0 proved engine feasibility only
(§14); every row here is an open proof obligation for its named stage.

| # | Requirement | Accepted only when |
|---|---|---|
| 1 | `ScopeSpec` is a validated Pydantic model | GP-01 green: rejects empty `acceptance_criteria`, extra fields, wrong types, non-`str` members; is frozen |
| 2 | Serialization is deterministic | GP-02(a) green, **including byte-identical output across a subprocess launched with a different `PYTHONHASHSEED`** |
| 3 | Identity is SHA-256 of canonical content | GP-03 green, including a **frozen golden digest constant** so serialization drift breaks the build loudly, **and** the digest **independently recomputed in-test** rather than by calling the production function; plus `sha256(stored canonical_preimage)` reproducing the digest with no re-serialization |
| 4 | Approval references the exact digest | GP-05 green: every binding field broken in isolation is refused |
| 5 | An approval for one digest cannot authorize a modified artifact | GP-06 green, all variants, including the negative case (unchanged spec stays valid) and the reorder case |
| 6 | Invalid transitions rejected by deterministic policy | GP-04 green: exactly 2 of 9 ordered pairs legal; the other 7 refused; parametrized over `list(ScopeState)` so a new state cannot slip in |
| 7 | The workflow can stop waiting for human approval | GP-09: status `PENDING`, and the case never advances with no approval sent |
| 8 | DBOS persists workflow state | GP-09 + GP-10a: state survives with no process running |
| 9 | Resumes from the approval wait after restart | GP-10a green under real `-SIGKILL`, with **`DBOS.sleep` recorded and `DBOS.recv` unconsumed before the kill**, and **`DBOS.recv` completed after recovery** — i.e. a previously entered durable receive, not merely recovery across the pre-`recv` window |
| 10 | The approval cannot be consumed twice | GP-07 green across **all five modes** (same statement twice; same id different workflow; same id different content; matching row with the case not in `to_state`; different id against an approved case) **plus the concurrency case**; and GP-10b green, including **exactly one barrier entry**, **exactly one** consumption row, **exactly one** transition audit event, and the recovered worker **exiting normally** with the workflow `SUCCESS` |
| 11 | No LLM decision may authorize a state transition | GP-11 (a)–(e) green, **with the §11 limiting claim recorded** |

GP-10a and GP-10b are distinct obligations and neither substitutes for the other.
GP-10a must prove resumption of an entered receive. GP-10b must prove convergence
across the **cross-database crash window** — governance committed, DBOS step *not*
checkpointed — which is the only place `GK-INV-3` is exercised against
at-least-once replay.

### §13.2 Structural gates

Beyond the eleven rows, the spike requires four gates: the governance layer imports neither `dbos` nor any LLM SDK; the
decode gate finds no `json` import outside `codec` and no `model_validate`
anywhere; `ruff` and `mypy --strict` clean; and `docs/gp-spk-001-validation.md`
records the verdict per requirement with exact commands and actual output, the §11
sentence verbatim, and an explicit statement that **mutation coverage is not
claimed**.

Failures worth naming in advance:

- DBOS cannot resume a `recv`-parked workflow from SQLite after a real SIGKILL →
  **FAIL the DBOS candidacy**; evaluate Temporal or a hand-rolled journal.
- JCS output is not byte-stable across processes → **FAIL the canonicalization
  strategy.**
- Single-use cannot be enforced atomically across a crash → **FAIL the authority
  model.** The one failure that would invalidate the planned pipeline rather than
  a component of it.

## §14 Recorded results

| Step | Result | Evidence |
|---|---|---|
| ST-0 (hard gate, R-1) | **PASS** | Durable receive entered and deadline checkpoint committed before a real SIGKILL (`returncode=-9`); approval delivered with no workflow process alive; recovered process consumed it; `status=SUCCESS`. Step names moved from `['_prepare','DBOS.sleep']` to `['_prepare','DBOS.recv','DBOS.sleep']`, so the receive was consumed by the recovered execution. Independently verified by the reviewer through read-only public-API inspection of the saved database. |
