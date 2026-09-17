# Governed Planner
Upstream planning system for the sibling `governed-runtime` execution runtime.
Phase: GP-SPK-001 (governance kernel feasibility; ST-1 scaffolding complete).

Rules:
- No AI planning layer is authorized. No Scoper, Designer, Reviewer or Planner.
  No LLM call, SDK or prompt anywhere in this repository.
- The kernel decides; the workflow engine only makes it durable. `kernel.py` and
  `store.py` must not import `dbos`.
- RFC 8785 / JCS is the sole canonicalization for artifact identity. Do not port
  `governed-runtime`'s hand-rolled `canonical_json`.
- Tables and typed models over prose. Every module docstring opens with
  `Design basis: design/GP-SPK-001-governance-kernel.md §N`.
- `governed-runtime` is never modified from here.

## Design baseline
`design/GP-SPK-001-governance-kernel.md` is authoritative. Code cites its sections.
The approved implementation plan is revision 5 (external to this repo).

## JSON ingestion — one path, enforced
Domain models are `strict=True` with `tuple[...]` fields. Strict validation rejects
a `list`; `json.loads` produces lists. So **`json.loads(...)` +
`model_validate(...)` is forbidden package-wide** — it fails at runtime with
`tuple_type`, and only on the decode path, which is exercised less than encode.

Use `model_validate_json` exclusively, and keep every JSON → domain conversion in
`codec.py`. A verification gate scans for the forbidden pattern; it keys on
*imports* rather than call shape so `import json as j` and `from json import loads`
are also caught.

## Implementation obligations carried from review
Recorded here because a plan is read once and this file is read every session.

- **ST0-R01 (from ST-0 review).** The ST-0 driver asserted only that stdout
  contained `consumed:`, and the worker accepted any non-`None` receive result. A
  regression returning a *different* non-`None` message would have passed. When the
  reusable recovery harness is built (ST-10), assert through the public API: the
  **exact** expected workflow result, the **exact** receive output, the workflow
  identity, and a **completed** receive. A stdout substring is not sufficient
  evidence.
- **ST0-R02 (from ST-0 review).** State the synchronization guarantee precisely:
  **"receive entered, deadline checkpoint committed, receive result not yet
  checkpointed."** Do **not** claim the predicate proves `recv_setup` has returned
  or that the thread is already blocked in `event.wait`. `record_sleep` commits the
  deadline *inside* `recv_setup` (`_sys_db.py:3305`), before it returns; the block
  itself is later (`_sys_db.py:3470`). The R-1 conclusion is unaffected — the
  receive has genuinely been entered — but the mechanism was described too strongly
  in the plan.
- **ST8-R02 (from ST-8 review). OWNER disposition: the plan §16 sentence is
  inaccurate — it is a plan inconsistency, not a behaviour gap.** Revision 5 §16 says
  `_submit_for_review` is "idempotent at the store level regardless". It is not, and
  must not become so. `SPK1-1` is a **transition**, and §3's frozen graph contains no
  `SCOPE_REVIEW_PENDING → SCOPE_REVIEW_PENDING` edge, so a re-run is refused as an
  illegal self-loop by `policy.refuse_unless_allowed` — which is the correct and
  intended behaviour. (§16's neighbouring claim about `open_case` *is* accurate:
  `open_case` is not a transition and is idempotent for identical content.)
  **The frozen transition graph remains authoritative.** No `submit_for_review` replay
  or idempotency semantics are authorized, none were invented, and no legal self-loop
  was added. **ST-10 recovery logic must not rely on that sentence**: an at-least-once
  re-delivery of the submit step raises `IllegalTransition`, and a recovery harness
  that assumes silent absorption will mis-read that refusal as a defect. Treat a
  repeated submit as *already submitted* by reading the case state, never by expecting
  the kernel to absorb it.

## DBOS API facts, verified by running (not by reading)
- `StepInfo` is a **`TypedDict`** — use `step["function_name"]`, never attribute
  access. `WorkflowStatus` is a plain class — use `status.name`. Mixed conventions
  in one API. The approved plan contains a stale example at its line 982 using
  `s.function_name`; **this file supersedes it.**
- `recovery_attempts` was **2** after a single SIGKILL (direct execution starts at
  1, recovered queue dispatch increments). Never assert `recovery_attempts == 1`.
- `DBOS.recv`'s timeout is a **durable deadline** committed at first execution, so a
  short timeout silently converts "resumed correctly" into "timed out". Use a long
  timeout and assert on returned values and final state, never on elapsed time.
- Workflow recovery is gated on `application_version` (`_recovery.py:57`), and a
  workflow is recorded under the function name it was **started** with. A process
  that registers a different function does not retarget an existing workflow.

## Known gaps
- Approvals are unsigned and unauthenticated. `approver_kind=HUMAN` is a *label*;
  human identity/authenticity is not proven until the signing stage. See design §11.
- `approval_id` is validated as 32 lowercase hex only, not as UUID v4. uuid4 is
  relied on for generation, not validation. See design §8.
- `issued_at` is syntax-checked only. No trusted clock, no freshness, no TTL.
- No audit hash-chaining yet; `audit_events` is append-only by convention.
- Mutation-testing tooling is deferred to GP-SPK-002. Guard IDs are frozen now so
  the harness ports later without touching source. **GP-SPK-001 does not claim
  mutation coverage.**
- Two guards are model-enforced rather than single deletable lines
  (`gp_preimage_envelope`, `gp_transport_decode`); they need schema mutation, not
  line deletion.

## Coordination
Implementation runs under a Claude ↔ Codex review protocol; see `.coord/PROTOCOL.md`.

`.coord/` is local coordination state, excluded via `.git/info/exclude`. That
exclude applies to **this checkout only** — it is not distributed with the
repository, so a fresh clone does not inherit it.

What the exclusion achieves: the coordination files' **contents** stay out of
normal `git status` and staging. What it does **not** achieve: it is not secrecy
about the arrangement — this file documents it — and it is **not a security
boundary**, since neither a local exclude nor a tracked ignore rule prevents
`git add -f`. Keeping `.coord/` untracked is a working convention that depends on
not force-adding it, not an enforcement mechanism.

It is absent from `.gitignore` deliberately, so that the ignore rule itself is not
carried into tracked project history.
