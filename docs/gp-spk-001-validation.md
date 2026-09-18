# GP-SPK-001 Final Validation

Design basis: `design/GP-SPK-001-governance-kernel.md` §13 (PASS / FAIL), §13.1 (the
eleven requirements), §13.2 (structural gates). Plan of record: revision 5, external
to this repository.

---

## 1. Executive verdict

**Overall result: PASS.**

All eleven frozen requirements of §13.1 are satisfied, and all four §13.2 structural
gates pass, measured independently at the baseline recorded in §2.

### What GP-SPK-001 proves

1. **Content-addressed artifact identity is viable.** RFC 8785 / JCS plus SHA-256
   over a versioned preimage produces a byte-stable identity that is reproducible
   across processes with different `PYTHONHASHSEED`, recomputable in-test without
   calling the production digest function, and re-derivable from the stored
   canonical bytes with no re-serialization anywhere on the read path.
2. **Digest-bound, single-use approvals are viable.** An approval authorizes exactly
   one `(subject_digest, workflow_id, from_state → to_state)` tuple; every binding
   field broken in isolation is refused; and an `approval_id` authorizes at most one
   committed transition across threads, across processes, and across a real crash.
3. **DBOS-on-SQLite is viable as the durable workflow engine for this shape.** A
   workflow parked in a durable `DBOS.recv` survives `SIGKILL` of its worker,
   accepts an approval delivered while no worker is alive, and is resumed to
   `SUCCESS` by a replacement process — including across the cross-database window
   in which the governance commit is durable and the DBOS step checkpoint is not.

None of the three candidate decisions is rejected. No failure named in advance by
§13.2 ("DBOS cannot resume a `recv`-parked workflow", "JCS output is not byte-stable
across processes", "single-use cannot be enforced atomically across a crash")
occurred.

### What GP-SPK-001 deliberately does not prove

> **HUMAN authority label enforced; human identity/authenticity not proven until the
> signing/authentication stage.**

It further does not prove: that any approval was signed; that `approver_id` names a
real person; that `issued_at` is fresh, ordered, or truthful; that the audit trail is
tamper-evident (no hash-chaining exists); or that the test suite kills arbitrary
mutants. **Mutation coverage is NOT claimed.** See §8, Known limitations, which is
part of this verdict and not an appendix to it.

---

## 2. Baseline

| | |
|---|---|
| Repository | `/root/workspace/governed-planner` |
| Branch | `main` |
| HEAD | `8bd1d663fc4ade6331693ef9d56375b9d9290f87` — *test(governance): complete ST-11 authority gates* |
| Worktree / index at validation | clean; no staged changes; no untracked project files |
| Production source | 15 modules under `src/gplanner/` |
| Tests | 13 test modules, 707 collected tests |
| Validation run (UTC) | 2026-09-18, 18:25–18:29 |
| Python / pytest / mypy / ruff | 3.13.5 / 9.1.1 / 2.3.1 / 0.16.7 |
| Pinned runtime deps | `dbos==2.31.1`, `pydantic 2.13.5`, `rfc8785 0.1.4` |

All measurements in §7 were taken on this HEAD, by this document's author, in this
session. They are not restatements of the ST-11 closure figures, though they agree
with them.

---

## 3. Requirement matrix

The eleven requirements are §13.1's, verbatim in ID and substance. "Evidence" cites
implementation and the test that establishes acceptance; test module counts are the
independently measured collection figures from §7.

| # | Requirement | Verdict | Evidence | Limitation |
|---|---|---|---|---|
| 1 | `ScopeSpec` is a validated Pydantic model | **PASS** | `src/gplanner/artifacts.py` — `ConfigDict(frozen=True, extra="forbid", strict=True)`, seven fields, no identity/lifecycle field. `tests/test_gp01_scope_spec_model.py` (27 tests): empty `acceptance_criteria` → `too_short`; extra field → `extra_forbidden`; wrong type → `string_type`; non-`str` member refused at exact loc `("in_scope", 1)`; `list` refused for a `tuple` field; frozen asserted. | Validation is structural. No semantic review of scope content is performed or claimed. |
| 2 | Serialization is deterministic | **PASS** | `src/gplanner/canonical.py` (RFC 8785 / JCS, layer 1) and `src/gplanner/profile.py` (`gplanner.payload-profile/1`, layer 2). `tests/test_gp02_canonical_jcs.py` (59 tests), including `test_serialization_is_byte_identical_across_a_different_hash_seed`, which runs two fresh interpreters under `PYTHONHASHSEED=0` and `=12345` via `subprocess` and requires byte-identical hex output equal to the in-process result. | The profile forbids floats and `null` inside hashed payloads (§5). That restriction is governed-planner's, and is *not* described as RFC 8785 anywhere. |
| 3 | Identity is SHA-256 of canonical content | **PASS** | `src/gplanner/digest.py`, `src/gplanner/artifacts.py`. `tests/test_gp03_digest_identity.py` (72 tests): frozen golden constant `GOLDEN_DIGEST = sha256:b33872d93a58014a33d53376783fa984abe3e7c17cbdae12e18b5dc9f027179e` with `GOLDEN_BYTE_LEN = 521`; `independent_digest()` recomputes identity in-test from `rfc8785.dumps` + `hashlib` without calling `digest.py`; `test_the_stored_preimage_bytes_rehash_to_the_digest_with_no_reserialization`. Re-measured live in §7's identity gate: `sha256(444 stored bytes)` reproduced `sha256:169e3849edf77c29175ff1a0a25a1f21ed859b1fd543437b20ed7e6dd7a3b4d5`. | SHA-256 is used for identity, not for authentication. Nothing signs the preimage (see requirement 11 and §8). |
| 4 | Approval references the exact digest | **PASS** | `src/gplanner/approvals.py` (in-toto Statement v1 shape; exactly one subject; `^[0-9a-f]{64}$` digest), `src/gplanner/codec.py`. `tests/test_gp05_approval_statement.py` (168 tests): `test_f_a_valid_statement_binds_the_expected_tuple`, then each binding field broken in isolation — wrong `workflow_id`, wrong `from_state`, wrong `to_state`, wrong subject digest — each failing only its own binding. | `approval_id` is validated as 32 lowercase hex, **not** as UUID v4; `issued_at` is syntax-checked only (§8). |
| 5 | An approval for one digest cannot authorize a modified artifact | **PASS** | `src/gplanner/kernel.py` (§10 step 5, `StaleApproval`), `src/gplanner/store.py` (digest re-derivation from stored bytes). `tests/test_gp06_stale_approval.py` (11 tests): revised artifact refused; reorder of `in_scope` stales the approval; one trailing space in `title` stales it; **negative case** — an unchanged re-serialization leaves the approval valid; byte-for-byte revert restores acceptance; the same digest in another workflow still fails workflow binding. | Staleness is detected by digest inequality. It does not classify *how* the artifact changed, and is not an authorization audit of the change. |
| 6 | Invalid transitions rejected by deterministic policy | **PASS** | `src/gplanner/policy.py` (`LEGAL_TRANSITIONS`, `resolve`, `refuse_unless_allowed`; imports neither `store` nor `dbos`). `tests/test_gp04_transition_policy.py` (99 tests): `test_c_exactly_two_of_nine_pairs_are_legal`; the seven illegal pairs refuse with `REFUSE_NOT_IN_GRAPH`; the matrix is derived by `itertools.product` over `list(ScopeState)`, so a new state widens the matrix rather than escaping it. Re-measured live in §7's authority gate: 27 `(from, to, actor)` cells, exactly 2 `ALLOW`. | Legality is decided with no I/O and no engine. It says nothing about whether the *actor label* is authentic (requirement 11). |
| 7 | The workflow can stop waiting for human approval | **PASS** | `src/gplanner/workflow.py`, `src/gplanner/app.py`. `tests/test_gp09_workflow_suspends.py` (28 tests): `test_a_the_workflow_opens_and_submits_the_case_then_parks_in_the_durable_receive` — `_open_case` and `_submit_for_review` checkpointed, `DBOS.sleep` recorded, `DBOS.recv` **not** yet recorded; `test_a_with_no_approval_delivered_the_case_never_advances` — asserted over the governance database, not over elapsed time. | The engine's receive timeout is a **durable deadline** committed at first execution. Waiting is asserted by state, never by wall-clock duration. |
| 8 | DBOS persists workflow state | **PASS** | `tests/test_gp09_workflow_suspends.py::test_a_dbos_reports_the_parked_workflow_as_pending_under_the_pinned_version` — `status=PENDING`, `name=scope_approval_workflow`, `app_version` pinned. `tests/test_gp10_restart_recovery.py::test_a_durable_receive_resumes_after_real_sigkill` — after `SIGKILL`, with no process alive, DBOS still reports `PENDING` and the case is still `SCOPE_REVIEW_PENDING`. | Recovery is gated on `application_version` (`dbos/_recovery.py:57`), and a workflow is recorded under the function name it was *started* with. A process registering a different function retargets nothing. |
| 9 | Resumes from the approval wait after restart | **PASS** | GP-10a — see §5.1. Entered receive proven before the kill (`DBOS.sleep` recorded, `DBOS.recv` absent); real `SIGKILL` (`returncode=-9`); approval delivered with no worker alive; replacement process recovered the same workflow to `SUCCESS`; `DBOS.recv` **completed** afterwards with output exactly equal to the delivered text. | Per **ST0-R02**: the pre-kill predicate states *receive entered, deadline checkpoint committed, receive result not yet checkpointed.* It does **not** assert that `recv_setup` has returned or that the thread is already blocked in `event.wait`. |
| 10 | The approval cannot be consumed twice | **PASS** | `src/gplanner/kernel.py` §10 replay-first ordering; `src/gplanner/store.py` (`approval_id` PRIMARY KEY under `BEGIN IMMEDIATE`). `tests/test_gp07_duplicate_approval.py` (39 tests) covers all five modes — same statement twice; same id different workflow; same id different content; matching row with the case moved away; different id against an approved case — **plus** the concurrency case in both thread and process form. GP-10b — see §5.2 — adds exactly one barrier entry, exactly one consumption row, exactly one `scope.approved` audit event, and the recovered worker exiting normally with the workflow `SUCCESS`. | The governance commit and the DBOS step checkpoint are **not** one transaction (§12). That is the condition `GK-INV-3` exists for, not a defect engineered away. See also the ST8-R02 boundary in §8. |
| 11 | No LLM decision may authorize a state transition | **PASS** | §13.2(a)–(e) covered by `tests/test_gp11_authority_label.py` (78 tests) — see §6. No edge names `ActorKind.LLM`; the complete 27-cell `(from, to, actor)` grid contains nine `LLM`-labelled cells and all nine are refused, while across the complete grid exactly two cells are `ALLOW` (both non-`LLM`, see §6.1); an `LLM`- or `SYSTEM`-labelled statement fails the transport decode with `literal_error` at `("predicate","approver_kind")`; policy independently raises `AuthorityDenied` on a statement built past validation with `model_construct`; the governance import closure names no LLM SDK. | **HUMAN authority label enforced; human identity/authenticity not proven until the signing/authentication stage.** |

**11 of 11 PASS. 0 FAIL. No requirement is marked partially satisfied, and no
evidence gap is carried.**

---

## 4. Stage evidence

| Stage | Objective | What it established |
|---|---|---|
| ST-0 | DBOS SQLite durable-receive feasibility (hard gate, R-1) | Durable receive entered and its deadline checkpointed before a real `SIGKILL` (`returncode=-9`); approval delivered with no workflow process alive; recovered process consumed it; `status=SUCCESS`. Recorded in design §14 and independently verified at the time by the reviewer through read-only public-API inspection. Superseded in strength — not merely repeated — by ST-10, which re-establishes the same property through the full governance stack with exact-value assertions. |
| ST-1 | Scaffolding | Package layout, tooling, gate harness (`tests/test_gp00_scaffolding.py`, `tests/test_gp00_harness.py`; 3 + 13 tests). |
| ST-2 | `ScopeSpec`, error hierarchy, `require` | Requirement 1. Frozen ST2-R* finding set: empty. |
| ST-3 | RFC 8785 / JCS + payload profile | Requirement 2; the two-layer split of §5. |
| ST-4 | Digest identity, authoritative preimage, `codec` | Requirement 3; the single JSON → domain boundary of §7. |
| ST-5 | Deterministic transition policy | Requirement 6; `LEGAL_TRANSITIONS` frozen at exactly two edges. |
| ST-6 | Approval statement and approval codec | Requirements 4 and 11's schema half; `approver_kind` as `Literal[ActorKind.HUMAN]`. |
| ST-7 | Governance SQLite store | §12's storage boundary: STRICT tables, WAL, `synchronous=FULL`, refuse-on-stale-schema, no ORM, no dependence on DBOS. |
| ST-8 | Stale approval, replay, transaction ownership | Requirements 5 and 10's non-crash half; the §10 replay-first ordering; `_require_transaction_ownership`. ST8-R02 disposition recorded (see §8). |
| ST-9 | DBOS workflow integration | Requirements 7 and 8. `workflow.py` and `app.py` are the only importers of `dbos`. Findings ST9-R01/R02/R03 remediated and closed. |
| ST-10 | Real SIGKILL / restart recovery | Requirements 9 and 10's crash half — GP-10a and GP-10b, §5. Findings ST10-R01/R02 closed. |
| ST-11 | Authority and structural gates | Requirement 11 and §13.2's first three gates, §6. Findings ST11-R01…R04 closed; `R3_IMPLEMENTATION_CORRECT` and `R5_ALL_FIVE_CORRECT` remained settled dispositions and were not reopened. |
| ST-12 | Final validation | This document — §13.2's fourth gate. |

Every stage ran under the `.coord/PROTOCOL.md` review protocol: implement → one Codex
discovery review → frozen findings → bounded remediation → bounded closure → owner
commit. Prior stages are closed and frozen; they are cited here as evidence, not
reopened as review targets.

### 4.1 Git-history qualification

The repository was initialized empty and carried **no commits** through the ST-8
implementation and the ST8-R01 remediation. The first truthful Git baseline is the
import commit `cf2b453` — *chore(repo): establish post-ST8 initial baseline* — created
only after that remediation. Nothing was lost and nothing was reconstructed: that
commit is an import of the then-current tree, and it does not retroactively establish
historical stage provenance for ST-0 through ST-7.

Evidence therefore has two forms, and this report does not blur them:

* **Pre-baseline (ST-0 … ST-8).** Established by the `.coord` SHA-256 manifest chain —
  per-stage `start_hashes.json` / `end_hashes.json` / `scope_verification.json`, present
  for ST-3 through ST-8 — together with each stage's evidence directory and its
  independent Codex review record. That chain joins the Git history at the baseline
  commit: all **29/29** files in `cf2b453` were re-verified during this validation to
  be byte-identical to `.coord/st8_r01_evidence/end_hashes.json` (SHA-256 recomputed
  from the commit's blobs; zero missing entries, zero mismatches).
* **Post-baseline (ST-8 closure onward).** Established by ordinary Git commits and
  diffs: `6bcaf52` (ST-8 closure), `e2ece73` (ST-9), `2b26646` (ST-10), `8bd1d66`
  (ST-11).

ST-0 through ST-2 predate even the manifest chain; their provenance rests on the design
document's recorded results (§14), the ST-2 Codex `REVIEW_PASS` record retained at
`.coord/st3_review_evidence/st2_review_pass.md`, and the fact that their artifacts are
present and passing at this HEAD.

---

## 5. Recovery validation

Both obligations are distinct and neither substitutes for the other. GP-10a proves
resumption of an **entered** receive; GP-10b proves convergence across the
**cross-database crash window**.

### 5.1 GP-10a — durable receive resumes after real SIGKILL

`tests/test_gp10_restart_recovery.py::test_a_durable_receive_resumes_after_real_sigkill`.
Recorded run: `.coord/st10_evidence/gp10a.events.jsonl`, `gp10a.resume.log`.

| Claim | Measured |
|---|---|
| Workflow parked durably | Steps at park: `_open_case`✓, `_submit_for_review`✓, `DBOS.sleep`✓; `DBOS.recv` **absent**. Case `SCOPE_REVIEW_PENDING` rev 2; 0 consumptions; 0 audit rows. |
| Real worker process received `SIGKILL` | `kill9 pid=3564838 returncode=-9 is_sigkill=true`. |
| Original process was gone | Parent waited on the killed child; subsequent observation labelled `no_process_alive` still reports `status=PENDING`, `recovery_attempts=1`. |
| Approval delivered while no original worker alive | `approval_sent_with_no_process_alive` for `sha256:ad39cb06…c9133`; governance immediately after send: still `SCOPE_REVIEW_PENDING`, 0 consumptions — delivery alone authorizes nothing. |
| A replacement worker recovered the same workflow | New process pid 3564992; DBOS logged `Recovering 1 workflows from application version gp-spk-001`; resumed under the same `workflow_id`, `name=scope_approval_workflow`, `app_version=gp-spk-001`. |
| Final governance state | `SCOPE_APPROVED`, revision 3. |
| Exactly one consumption | 1 row: `a1b2c3d4e5f60718293a4b5c6d7e8f90`, approval digest `sha256:4ac09059…0cf4c`, subject `sha256:ad39cb06…c9133`, `SCOPE_REVIEW_PENDING → SCOPE_APPROVED`. |
| Exactly one `scope.approved` audit | 1 row, checked against every audit row in the whole database, not only this workflow's. |
| Exact receive/result identity preserved | Per **ST0-R01**, asserted through the public API: `DBOS.recv` present and **completed**, with output **exactly equal** to the delivered approval string; workflow result obtained via `DBOSClient.retrieve_workflow(WORKFLOW_ID).get_result()` and required to be exactly `SCOPE_APPROVED`; workflow identity (`name`, `app_version`, `workflow_id`) asserted. The worker's stdout line is corroboration only — a stdout substring is not sufficient evidence. |
| Recovery accounting | `recovery_attempts=2` after the single SIGKILL. `== 1` is never asserted: direct execution starts at 1 and recovered dispatch increments. |

`test_a_kill_lands_past_the_submit_checkpoint` additionally measures that `_open_case`
and `_submit_for_review` are durably **completed** before the kill — so recovery skips
them rather than replaying `SPK1-1`. The proof rests on that measured checkpoint, never
on the plan §16 sentence (see §8, ST8-R02).

### 5.2 GP-10b — crash between governance commit and DBOS checkpoint

`tests/test_gp10_restart_recovery.py::test_b_crash_between_governance_commit_and_dbos_checkpoint`,
with `test_b_the_replayed_step_really_re_executes_and_the_kernel_still_absorbs_it` as
its non-vacuity control. Recorded run: `.coord/st10_evidence/gp10b.events.jsonl`,
`gp10b.resume.log`.

| Claim | Measured |
|---|---|
| Governance commit externally durable | Observed from the parent over its own connection while the committing worker was still alive and parked: case `SCOPE_APPROVED` rev 3, exactly 1 consumption, exactly 1 `scope.approved` audit whose `workflow_id` and canonical `detail_json` bytes match the expected transition detail. |
| DBOS apply-step checkpoint absent | `status=PENDING`; completed steps `_open_case`, `_submit_for_review`, `DBOS.recv`, `DBOS.sleep` — `_apply_with_optional_barrier` **not** among them. This is the §12 window. |
| Worker was SIGKILLed | `kill9 pid=3562836 returncode=-9 is_sigkill=true`, inside that window. |
| Uncheckpointed step actually replayed | Proven by the re-armed control, which respawns recovery with the crash flag still set — the one thing GP-10b's own recovery phase never does — and waits for `barrier.log` to reach **2** lines: direct observable proof that the step re-executed against a case already `SCOPE_APPROVED`. Barrier accounting: normal lifecycle **1 → 1**; re-armed control **1 → 2 → 2**. |
| Kernel replay semantics absorbed the repeat | Convergence comes from `governance.sqlite`'s §10 step-4 match branch (`applied=False`, nothing written). Nothing in the workflow layer decides it; there is no code there that could. |
| No duplicate consumption or audit | After recovery: consumption count 1, `scope.approved` audit count 1, case still `SCOPE_APPROVED` rev 3. |
| Final workflow converged to SUCCESS | `status=SUCCESS`, `name=_crashable_scope_approval_workflow`, `recovery_attempts=3`, `_apply_with_optional_barrier` completed; recovered worker exited **normally** (`returncode=0`); public result exactly `SCOPE_APPROVED`. |
| Exact consumption/audit identity preserved | Whole-row equality against the pre-crash snapshot, all 7 consumption columns and all 5 audit columns — including `consumed_at`, `seq`, `workflow_id` and the canonical detail bytes. A row silently replaced by a re-derived lookalike with a fresh timestamp would fail. Fixed values across the crash: approval id `a1b2c3d4e5f60718293a4b5c6d7e8f90`, approval digest `sha256:be954ddd…1b6f08`, subject `sha256:ad39cb06…c9133`. |

Detection controls (`tests/test_gp10_restart_recovery.py`, section C — 16 test functions
expanding under parametrization to **19 executed cases**, of which 13 were added during
remediation) establish that these assertions are capable of failing: a duplicate
consumption row, a duplicate audit row, a digest-shaped-but-wrong consumption digest,
a correct-looking audit filed under another workflow, an empty `{}` audit detail,
a single corrupted detail field, a replacement row with a fresh timestamp, and a
substituted approval message are each shown to be **detected**.

### 5.3 The ST8-R02 boundary, stated rather than hidden

`_submit_for_review` **is not generally idempotent**, and must not become so. `SPK1-1`
is a transition, and §3's frozen graph contains no `SCOPE_REVIEW_PENDING →
SCOPE_REVIEW_PENDING` edge, so a re-run is refused as an illegal self-loop by
`policy.refuse_unless_allowed`. That is the correct and intended behaviour, and the
frozen transition graph remains authoritative.

Revision 5 §16's sentence calling `_submit_for_review` "idempotent at the store level
regardless" is inaccurate. The owner disposition is that this is a **plan
inconsistency, not a behaviour gap**. No `submit_for_review` replay or idempotency
semantics were authorized, none were invented, and no legal self-loop was added.

Consequently, **recovery across the submit/checkpoint window was not tested, and no
such guarantee is claimed here.** GP-10a and GP-10b both place their crash strictly
*after* the submit checkpoint, and GP-10a measures that placement rather than assuming
it. A repeated submit is to be treated as *already submitted* by reading the case
state — never by expecting the kernel to absorb it.

---

## 6. Authority and structural validation

`tests/test_gp11_authority_label.py` — 78 tests, sections A–F, covering plan §18(a)–(e).

### 6.1 Authority

* **27-cell grid.** `(from, to, actor)` over `list(ScopeState)` × `list(ScopeState)` ×
  `list(ActorKind)` = 3 × 3 × 3 = 27 cells, derived from the enums so a new state or
  actor widens the grid instead of escaping it.
* **Exactly two allowed cells.** `SCOPE_DRAFTING → SCOPE_REVIEW_PENDING` by `SYSTEM`,
  and `SCOPE_REVIEW_PENDING → SCOPE_APPROVED` by `HUMAN`. Re-measured live in §7.
* **No LLM-authorized edge.** `GK-INV-5` asserted over the table, not over call sites:
  no row's authority is `ActorKind.LLM`, and the token `LLM` appears in no field of any
  row. `ActorKind.LLM` exists in the enum **precisely so the refusal is testable** —
  without it, "no LLM may authorize" would be a claim about a token the code cannot
  express. `LLM` is refused on all nine ordered pairs, with the two refusals kept
  distinct: `AuthorityDenied` on a legal edge (the edge exists, this actor may not take
  it) and `IllegalTransition` elsewhere (no such edge).
* **LLM/SYSTEM-labelled approval rejection.** `codec.decode_approval` refuses both
  labels during the single JSON → domain parse, with errors exactly
  `[("literal_error", ("predicate", "approver_kind"))]` — the model's own
  `Literal[ActorKind.HUMAN]` constraint, not a second policy implementation.
* **Independent policy refusal after schema bypass.** A statement built with
  `model_construct` — carrying `approver_kind=ActorKind.LLM` as a real field value past
  validation — is refused anyway by `kernel.apply_scope_approval` at §10 step 5a with
  `AuthorityDenied` naming `SPK1-2` and `LLM`. Defence in depth, proven rather than
  assumed.
* **Zero state, consumption and audit effects on rejected authority.** Both rejection
  layers leave the case at `SCOPE_REVIEW_PENDING` revision 2, with 0 consumption rows
  and 0 audit rows, and `find_consumption(APPROVAL_ID) is None`. Every policy check
  precedes the claim in §10 step 5f, so a refused approval is never burnt.
* **Negative control.** The identical statement, identical binding, identical id,
  differing only in the label `HUMAN`, does advance the case — 1 consumption, 1 audit,
  `SCOPE_APPROVED` — so "refused" cannot mean "the fixture was broken".
* **No layer reinterprets the label.** `approver_kind`, `approver_id`, `predicate` and
  `AuthorityDenied` appear nowhere in `workflow.py` or `app.py`, and the only
  `ActorKind` member either names is `SYSTEM` (`GK-INV-6`).

### 6.2 Structural

* **Transitive import closure excluding DBOS and LLM SDKs.** A static walk from the ten
  governance seeds reaches 13 first-party modules; its only non-stdlib roots are
  `pydantic` and `rfc8785`. Run as a *closure from source*, not a `sys.modules`
  snapshot, so a deferred import inside a function body is still found. A second,
  independent check imports the governance layer in a clean interpreter and asserts
  `dbos`, `anthropic` and `openai` are absent from `sys.modules`. The two are
  complementary: the runtime check catches what executes, the static closure catches
  what would.
* **Recursive decode-boundary scanning.** All three decode scans — `json` imports plus
  `model_validate`; unchecked constructors (`model_construct`, `parse_obj`, `parse_raw`,
  `construct`); and `model_validate_json` holders — walk `rglob("*.py")` over the whole
  package. The codec exemption **narrowed** as the scan widened: it is the file whose
  relative path is exactly `codec.py`, so a nested `sub/codec.py` is an ordinary module
  and buys no second decode boundary.
* **JSON-submodule detection.** A module is an offence when it is exactly `json` or
  begins with `json.`, so `import json`, `import json as j`, `import json.decoder`,
  `from json import loads` and `from json.decoder import JSONDecoder` are all caught.
  A *relative* `from .json import …` is excluded, because it names a first-party module
  that merely shares the name and is scanned on its own account — the false-positive
  boundary is asserted, so the gate stays one a maintainer will leave switched on.
* **Conventional literal dynamic-import detection.** `importlib.import_module("x")`,
  `import importlib as il` → `il.import_module("x")`, `from importlib import
  import_module` → `import_module("x")`, the aliased `load("x")` form, and
  `__import__("x")`. Aliases are tracked per file from that file's own imports, so a
  rename does not defeat the gate. Resolved targets feed the ordinary classification:
  `"anthropic"` becomes a forbidden external root; `"gplanner.workflow"` becomes a
  first-party closure edge followed like any other.
* **Explicit bound.** The target must be a **string literal**. A *computed* dynamic
  import target is **not** detected, and no claim to the contrary is made.
  `test_d_a_computed_dynamic_import_target_is_not_claimed_to_be_detected` records that
  bound as a passing test, and also records that `importlib` is nonetheless collected as
  an ordinary external root (filtered from the allowlist assertion only because it is
  standard library). The claim is "conventional literal dynamic loading is detected",
  not "arbitrary dynamic loading is detected".

### 6.3 Preserved review dispositions

These are historical dispositions carried forward from closed stages. They are recorded
for provenance and are **not** new requirements introduced by this document:

* **`R3_IMPLEMENTATION_CORRECT`** — settled: `CLAUDE.md` is not required to contain the
  §11 limitation sentence verbatim. Plan §18 mandates the verbatim sentence in the
  design document and in this validation document; what it requires of `CLAUDE.md` is
  that the gap is recorded as such under *Known gaps*, which it is.
* **`R5_ALL_FIVE_CORRECT`** — settled: plan §18 (a) frozen graph, (b) LLM refusal,
  (c) approval rejection, (d) structural closure, (e) decode boundary remain covered in
  full.

### 6.4 Adversarial probes — bounded, and not mutation coverage

Fourteen escape probes and the eight original guard-probe runs — `M0`, an **unmodified
passing baseline control**, plus the **seven mutations** `M1`–`M7` — were rebuilt and
re-run against the hardened ST-11 suite, each against a disposable copy outside the
repository. All 14 escapes fail the suite; `M0` passes as the control it is, and the
seven original mutations produce identical failure counts against a suite 21 tests
larger. The independent closure verifier reproduced 34 of 34 controls (31 expected
failing runs, 3 passing controls).

These are **bounded adversarial controls on specific named guards**. They are not a
mutation-testing campaign, they do not sample the mutant space, and **mutation coverage
is NOT claimed** — see §8.

---

## 7. Verification commands and results

Run at the §2 baseline. Pytest ran with `PYTHONDONTWRITEBYTECODE=1`, `-p
no:cacheprovider` and `--basetemp` under `.coord/st12_evidence/`; ruff and mypy caches
were redirected there too. Those flags exist only to keep the run from writing into the
project tree; they change no gate's meaning. `ruff format --check` was **not** imposed —
it is not an authoritative project gate. Raw logs: `.coord/st12_evidence/*.log`,
`.coord/st12_evidence/st12_gates.json`.

| # | Gate | Exact command | Measured result | Exit |
|---|---|---|---|---|
| 1 | Collection | `.venv/bin/python -m pytest -p no:cacheprovider --collect-only -q` | **707 tests collected in 0.19s** | 0 |
| 2 | Full suite | `.venv/bin/python -m pytest -p no:cacheprovider -q` | **707 passed in 92.11s (0:01:32)** | 0 |
| 3 | GP-11 | `.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_gp11_authority_label.py` | **78 passed in 1.87s** | 0 |
| 4 | GP-10 | `.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_gp10_restart_recovery.py` | **28 passed in 25.32s** | 0 |
| 5 | GP-09 | `.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_gp09_workflow_suspends.py` | **28 passed in 31.33s** | 0 |
| 6 | Lint | `.venv/bin/ruff check src tests` | **All checks passed!** | 0 |
| 7 | Types | `.venv/bin/mypy --strict src/gplanner` | **Success: no issues found in 15 source files** | 0 |
| 8 | Structural | `.venv/bin/python .coord/st12_evidence/st12_gates.py` | **STRUCTURAL PASS: 10 seeds; 13 first-party modules reached; third-party roots `['pydantic', 'rfc8785']`; no dbos/LLM SDK loaded or statically reachable** | 0 |
| 9 | Decode | *(same runner)* | **DECODE PASS: 15 files scanned recursively; zero forbidden json imports and zero `model_validate`/`model_construct` sites; `codec.py` alone holds 2 `model_validate_json` sites** | 0 |
| 10 | Authority | *(same runner)* | **AUTHORITY PASS: 27 cells evaluated; exactly 2 ALLOW `[('SCOPE_DRAFTING','SCOPE_REVIEW_PENDING','SYSTEM'), ('SCOPE_REVIEW_PENDING','SCOPE_APPROVED','HUMAN')]`; 0 LLM ALLOW** | 0 |
| 11 | Identity | *(same runner)* | **IDENTITY PASS: 1 artifact row; `sha256(444 stored bytes)` == `sha256:169e3849edf77c29175ff1a0a25a1f21ed859b1fd543437b20ed7e6dd7a3b4d5` with no re-serialization; envelope fields `['media_type','payload','payload_profile','preimage_version']`** | 0 |

Collection by module, independently measured, summing to 707:

| Module | Tests | | Module | Tests |
|---|---:|---|---|---:|
| `test_gp00_scaffolding.py` | 3 | | `test_gp06_stale_approval.py` | 11 |
| `test_gp00_harness.py` | 13 | | `test_gp07_duplicate_approval.py` | 39 |
| `test_gp01_scope_spec_model.py` | 27 | | `test_gp08_store_boundary.py` | 82 |
| `test_gp02_canonical_jcs.py` | 59 | | `test_gp09_workflow_suspends.py` | 28 |
| `test_gp03_digest_identity.py` | 72 | | `test_gp10_restart_recovery.py` | 28 |
| `test_gp04_transition_policy.py` | 99 | | `test_gp11_authority_label.py` | 78 |
| `test_gp05_approval_statement.py` | 168 | | **Total** | **707** |

Every count matches the expected post-ST-11 baseline exactly: 707 collected, 707 passed,
ST-11 = 78, GP-10 = 28, GP-09 = 28, ruff PASS, strict mypy PASS on 15 source files,
structural / decode / identity PASS. **No count differed, so no discrepancy required
investigation.**

One operational note, recorded because the distinction matters: the identity gate's runner
deletes `identity.sqlite` and its `-wal`/`-shm` siblings before it runs, so the recorded
measurement is always taken over exactly one freshly written artifact. It does not have
to. The runner calls `kernel.open_case` only — it never calls `_submit_for_review` — and
`open_case` is not a transition and is idempotent for identical content, so re-running the
gate against the existing database succeeds again and leaves the case in `SCOPE_DRAFTING`
at revision 1, with one artifact and the same digest. The ST8-R02 self-loop refusal of
§5.3 belongs to `_submit_for_review`, which **is** a transition; no gate in this section
exercises it.

---

## 8. Known limitations

These bound the verdict in §1 and §9. A PASS on all eleven requirements means those
eleven requirements were met — it does not extend past the following.

1. **Human authority is a label, not an identity.**

   > **HUMAN authority label enforced; human identity/authenticity not proven until the
   > signing/authentication stage.**

   The approval channel is unauthenticated: anyone able to call `DBOSClient.send`
   against the system database can mint a statement labelled `HUMAN` with an arbitrary
   `approver_id`, and nothing here detects it. This is demonstrated as a *passing* test
   (`test_f_an_arbitrary_unauthenticated_approver_id_is_accepted`, approver
   `"definitely-not-a-human"`) so the verdict cannot be read as stronger than it is.
   What *is* enforced, and is the whole of requirement 11, is the label. Design §11.
2. **No signing, no cryptographic authority, no proven real-world authorship.**
   Approvals are unsigned; the statement *is* the payload a signature would later cover.
   The governance import closure contains no signing or crypto library
   (`cryptography`, `nacl`, `jwt`, `dsse`, `securesystemslib`, `hmac`, `ssl` are all
   absent); `hashlib` is present because hashing is *identity* (§6), not authentication.
   No field of `ApprovalStatement` or `ScopeApprovalPredicate` is named for a signature
   — a present-but-unchecked signature field would be the most readable possible
   overclaim.
3. **ST8-R02 — `_submit_for_review` is not generally idempotent.** A repeated submit is
   refused as an illegal self-loop, by design. Recovery across the submit/checkpoint
   window was not tested and is not claimed. See §5.3.
4. **Mutation coverage is NOT claimed.** Mutation-testing tooling is out of scope for
   GP-SPK-001 and deferred to GP-SPK-002. Guard IDs are frozen now so the harness ports
   later without touching source. The adversarial probes of §6.4 are bounded controls on
   specific named guards, not a sampled mutant population. Two guards are model-enforced
   rather than single deletable lines (`gp_preimage_envelope`, `gp_transport_decode`) and
   need schema mutation, not line deletion.
5. **`approval_id` is validated as 32 lowercase hex, not as UUID v4.** `uuid4` is relied
   on for *generation* — unpredictability and uniqueness — not for validation.
   Validating version bits would assert something the encoding cannot establish about a
   value's origin: a false assurance on an authority-bearing field. Design §8.
6. **`issued_at` is syntax-checked only.** RFC 3339 with offset, and nothing more. No
   trusted clock, no freshness, no TTL, no ordering.
7. **No audit hash-chaining.** `audit_events` is append-only by convention, not by
   construction. The audit trail is not tamper-evident.
8. **Structural detection is bounded at literal dynamic-import targets.** Conventional
   literal loaders are detected; an arbitrary *computed* target is not, and that bound is
   asserted rather than left implicit. See §6.2.
9. **Decode is not injective over arbitrary accepted JSON.** `extra="forbid"` enforces
   the approved envelope schema — an undeclared field is refused, never silently dropped
   — but two inputs differing only in insignificant whitespace have different SHA-256
   values and decode to equal `ScopeSpec` objects. `GK-INV-1` is a claim about the
   *authoritative canonical preimage bytes* and their digest, not about decode
   injectivity. Design §7.
10. **Scope boundary.** GP-SPK-001 proves feasibility over
    `SCOPE_DRAFTING → SCOPE_REVIEW_PENDING → SCOPE_APPROVED` with zero LLM involvement.
    **No claim is made beyond that frozen feasibility scope.** Not built, not stubbed,
    not imported: Scoper / Designer / Reviewer / Planner agents; any LLM call, SDK or
    prompt; `SCOPE_REJECTED`, revision loops, or any further state; `HANDOFF_CONTRACT`;
    any read or write of `governed-runtime`; Postgres, DBOS queues, multi-executor or
    Conductor; schema migrations. The verdict is version-specific to the pinned
    `dbos==2.31.1`, and does not transfer to another engine or another backing store.
11. **Pre-baseline Git provenance.** ST-0 through ST-8 have no Git commit history,
    because none was ever created. Their provenance is the `.coord` manifest chain and
    stage evidence, as qualified in §4.1. No lost history existed and none is implied.

---

## 9. Final verdict

**GP-SPK-001 — Governance Kernel Feasibility: PASS.**

All eleven §13.1 requirements PASS, with zero FAIL and zero unresolved evidence gaps.
All four §13.2 structural gates pass: the governance layer imports neither `dbos` nor
any LLM SDK; the decode gate finds no `json` import outside `codec` and no
`model_validate` anywhere; `ruff` and `mypy --strict` are clean; and this document
records the verdict per requirement with exact commands and actual output, the §11
sentence verbatim, and an explicit statement that mutation coverage is not claimed.

The three candidate decisions are accepted: **RFC 8785 / JCS + SHA-256** for
content-addressed artifact identity; **digest-bound, single-use approvals** for
authority; and **DBOS-on-SQLite (`dbos==2.31.1`)** as the durable workflow engine. None
of the three pre-named failure modes occurred.

This verdict is bounded exactly by §8. In particular it is a verdict on the **authority
model**, not on human authenticity: *HUMAN authority label enforced; human
identity/authenticity not proven until the signing/authentication stage.* Mutation
coverage is NOT claimed.

Per design §1, the precondition it existed to satisfy is now met: **no planning agent
was authorized for implementation until this verdict existed. It now does.** Authorizing
any subsequent stage remains an owner decision, and nothing in this document performs
it.
