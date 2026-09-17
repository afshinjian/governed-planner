"""The approval record — in-toto Statement v1, unsigned.

Design basis: design/GP-SPK-001-governance-kernel.md §8, §11.

An approval is the one place in this spike where authority is *claimed* rather than
derived, so the record's job is to make the claim precise and bounded. §8 fixes the
shape: in-toto Statement v1, exactly one subject, a governed-planner predicate naming
the `(workflow, from → to)` edge and the approver, and nothing else. Every field is
either a `Literal` or a pattern-constrained string, so a statement that does not say
exactly one thing does not validate at all.

Unsigned, deliberately. The statement *is* the payload a signature would later cover,
so adding DSSE later wraps this shape rather than changing it. Nothing here signs,
verifies, or authenticates, and there is no field into which a signature could be
smuggled.

> **HUMAN authority label enforced; human identity/authenticity not proven until the
> signing/authentication stage.** (§11, quoted verbatim.)

That sentence is the limit of what this module establishes. `approver_kind` is
`Literal[ActorKind.HUMAN]`, so a statement labelled `SYSTEM` or `LLM` fails validation
before any kernel sees it — which is real, and is §11's "must prove" list in its GP-05
half. `approver_id` is an opaque, unauthenticated label, and the approval channel is
unauthenticated: anyone able to reach it can mint a statement labelled `HUMAN`. The
label is enforced; the identity behind it is not established here.

Three deliberate non-validations, each a *narrower* claim than the encoding might
tempt a reader into (§8's table):

* **`approval_id` is 32 lowercase hex and nothing more.** uuid4 is relied on for
  *generation* — unpredictability and uniqueness. It is not relied on for validation:
  version and variant bits cannot establish where a value came from, so checking them
  would put a false assurance on an authority-bearing field. Single-use rests on the
  `approval_id` PRIMARY KEY (§12), never on the value's shape.
* **`issued_at` is syntax only.** RFC 3339 §5.6 `date-time` with an explicit offset.
  No trusted clock, no freshness, no TTL, no ordering — and no calendar arithmetic, so
  a syntactically well-formed impossible date is accepted.
* **`approver_id` is a bounded opaque string.** See above.

What this module must not become. It holds no policy about which edges are legal
(`policy.py`), no opinion about artifact identity (`digest.py`), and no comparison
against a live case — whether a statement's binding matches the case in front of it is
the kernel's decision, made under §10's ordering, and a helper here would be a second
opinion sitting outside the layer that owns it. It therefore imports Pydantic and the
state vocabulary, and nothing else.

The bare `sha256` hex pattern is consequently restated here rather than imported from
`digest.py`, exactly as `ArtifactRef` restates the prefixed form (see `artifacts.py`).
GP-05 asserts the two spellings agree.
"""

from __future__ import annotations

import re
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from gplanner.states import ActorKind, ScopeState

# The aliases exist so the constants below can be typed by the same literal the model
# fields use. A type checker rejects `Literal[SOME_CONSTANT]`, so the alias is the
# literal and the constant is annotated with it: a drift between the two lines is a
# type error rather than a surprise at run time. Same arrangement as `digest.py`.
StatementType = Literal["https://in-toto.io/Statement/v1"]
ScopeApprovalPredicateType = Literal["https://governed-planner/ScopeApproval/v1"]
PredicateVersion = Literal["gplanner.scope-approval/v1"]
Decision = Literal["APPROVE"]

#: Fixed by in-toto, not by us. A statement must carry it explicitly (see below).
STATEMENT_TYPE: Final[StatementType] = "https://in-toto.io/Statement/v1"

#: Fixed by the approved plan of record (revision 5 §6), not chosen here. ST-6 briefly
#: froze a versionless `urn:` form on the reasoning `digest.py` gives for
#: `SCOPE_MEDIA_TYPE`; that reasoning does not reach this constant, because the plan
#: specifies the predicate URI separately and a stage may not amend it (ST6-R01).
SCOPE_APPROVAL_PREDICATE_TYPE: Final[ScopeApprovalPredicateType] = (
    "https://governed-planner/ScopeApproval/v1"
)

#: The predicate schema version, also fixed by the plan. It is not a second statement of
#: the URI's version: `predicateType` names the predicate, this names its schema
#: revision, and both are `Literal`-pinned so neither can drift unobserved.
PREDICATE_VERSION: Final[PredicateVersion] = "gplanner.scope-approval/v1"

#: §8: `^[0-9a-f]{32}$`. Lowercase only, for the reason a digest is lowercase only —
#: hex is case-insensitive as an encoding, so accepting both cases would give one
#: approval two spellings of the primary key that enforces its single use.
APPROVAL_ID_PATTERN: Final[str] = r"^[0-9a-f]{32}$"

#: §6/§8: in-toto's `subject[].digest` map carries **bare** hex, with no `sha256:`
#: prefix. Restated from `digest.py` rather than imported; GP-05 pins the two together.
BARE_SHA256_PATTERN: Final[str] = r"^[0-9a-f]{64}$"

#: Fixed by the plan of record (revision 5 §6, `WORKFLOWID`), not chosen here: letters,
#: digits, underscore, dot, colon and hyphen, length 1-128 (ST6-R02). A workflow
#: identity is an opaque handle, so the constraint is on shape and size only -- no
#: whitespace and no path or URL punctuation, so the value cannot change meaning when it
#: later appears in a log line, a database key or an error message.
WORKFLOW_ID_PATTERN: Final[str] = r"^[A-Za-z0-9_.:-]{1,128}$"

#: RFC 3339 §5.6 `date-time` with a mandatory offset, **component-bounded and ASCII**.
#:
#: Every group is written `[0-9]` rather than `\d`, and every component carries its own
#: range. `\d` is Unicode-wide in Python, so a pattern built from it accepted
#: `２０２６-０９-１７T１１:２２:３３Z`; unbounded two-digit groups additionally accepted hour 24,
#: minute 60, second 61, month 13, day 32, offset hour 24 and offset minute 60. RFC 3339
#: §5.6 bounds each of those, and RFC 5234 B.1 defines `DIGIT` as ASCII 0-9 (ST6-R05).
#:
#: `T`/`t` and `Z`/`z` are both accepted because RFC 3339 §5.6 expressly permits the
#: lowercase alternatives; narrowing them would refuse timestamps the cited standard
#: allows while still calling the check RFC 3339.
#:
#: Second 60 is accepted (leap second), 61 is not. The offset is the one part this spike
#: insists on: with no trusted clock available a local-time instant cannot be
#: interpreted at all, whereas an offset instant can at least be compared once freshness
#: enters scope.
#:
#: **Syntax only, and only per-component.** No calendar consistency is checked, so
#: `2026-02-30T00:00:00Z` is well-formed here and is accepted; no freshness, TTL,
#: ordering or clock trust of any kind is implied.
ISSUED_AT_PATTERN: Final[str] = (
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"[Tt](?:[01][0-9]|2[0-3]):[0-5][0-9]:(?:[0-5][0-9]|60)"
    r"(?:\.[0-9]+)?"
    r"(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)

#: `fullmatch` rather than a reliance on `$`: in Python `$` also matches before a
#: trailing newline, so `"...Z\n"` would pass an otherwise identical pattern. Same
#: reasoning, and the same arrangement, as `digest.py`'s `_DIGEST_PATTERN`.
_ISSUED_AT_RE: Final[re.Pattern[str]] = re.compile(ISSUED_AT_PATTERN)

#: Upper bound for the opaque labels (`subject[].name`, `approver_id`). Fixed at 256 by
#: the plan of record (revision 5 §6, `ACTORID` and `Subject.name`), not chosen here
#: (ST6-R03). Bounded at all because an unbounded string in an authority-bearing record
#: is a storage and log hazard; the exact number is a policy choice, not a property of
#: anything being described.
MAX_LABEL_LENGTH: Final[int] = 256

Hex32 = Annotated[str, StringConstraints(pattern=APPROVAL_ID_PATTERN)]
BareSha256 = Annotated[str, StringConstraints(pattern=BARE_SHA256_PATTERN)]
WorkflowId = Annotated[str, StringConstraints(pattern=WORKFLOW_ID_PATTERN)]
Label = Annotated[str, StringConstraints(min_length=1, max_length=MAX_LABEL_LENGTH)]


def _parse_rfc3339_or_raise(value: str) -> str:
    """Return `value` if it is an RFC 3339 `date-time` with an offset; else raise.

    A helper rather than an inline check so the guard site above stays **one deletable
    line**: GP-SPK-002's mutation harness proves a guard is tested by deleting its line
    and requiring the suite to go red, and a multi-line check deletes into a syntax
    error, which is reported as an error rather than a kill and proves nothing.

    `ValueError`, not a `GovernedPlannerError`: this runs inside Pydantic validation, and
    Pydantic collects `ValueError` into the `ValidationError` a caller of `codec` already
    expects. Raising a governance error here would escape validation as a second,
    unrelated exception type from the same call.
    """
    if _ISSUED_AT_RE.fullmatch(value) is None:
        raise ValueError(
            f"{value!r} is not an RFC 3339 date-time with an explicit offset "
            "(ASCII digits; month 01-12, day 01-31, hour 00-23, minute 00-59, "
            "second 00-60, offset hour 00-23 and offset minute 00-59)"
        )
    return value


class Sha256DigestSet(BaseModel):
    """in-toto's `subject[].digest` map, admitting exactly the approved algorithm.

    One key, closed. A statement offering `sha512` instead, or `sha256` *and* something
    else, is refused rather than partially understood: an approval that references an
    artifact under an algorithm this spike does not compute would be binding to a
    digest nothing here can reproduce.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: Bare hex. `digest.to_intoto_hex` is the one conversion from our `sha256:<hex>`
    #: wire format, and refusing the prefixed spelling here is what makes going through
    #: it mandatory rather than merely available.
    sha256: BareSha256


class Subject(BaseModel):
    """What the approval is *about*: a name and the exact bytes it names.

    `name` is a label for humans and logs, never an identity — two subjects with the
    same name and different digests are two different artifacts, and the digest is what
    decides. Nothing downstream may key on `name`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    name: Label
    digest: Sha256DigestSet


class ScopeApprovalPredicate(BaseModel):
    """The governed-planner predicate: who approved which edge of which case, and when.

    Field order here is the order §8 lists them, and is the order they appear on the
    wire. It is not load-bearing for identity — RFC 8785 sorts keys when this record is
    later content-addressed — but it keeps the model readable against the design.

    `from_state` and `to_state` are `ScopeState`, not `Literal`s pinned to the one edge
    §3 says needs an approval. Whether an edge is legal is `policy.py`'s single
    declarative answer, and encoding a second copy of it here would be exactly the
    duplicated-authority-model problem that table exists to avoid. A statement may
    therefore *name* an illegal edge; it simply cannot authorize one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    predicate_version: PredicateVersion
    approval_id: Hex32
    workflow_id: WorkflowId
    from_state: ScopeState
    to_state: ScopeState
    approver_id: Label
    #: `Literal[ActorKind.HUMAN]`, so `SYSTEM` and `LLM` fail validation before the
    #: kernel is reached (§11). A **label**, never a proof of who produced this.
    approver_kind: Literal[ActorKind.HUMAN]
    #: One decision. `SCOPE_REJECTED` and revision loops are out of scope (§2), so a
    #: rejection has no state to move a case to and is deliberately absent rather than
    #: accepted and ignored.
    decision: Decision
    #: Deliberately an unconstrained `str` at the type level. The syntax check lives in
    #: the validator below, which is the plan's registered `gp_approval_issued_at_syntax`
    #: guard site; a `StringConstraints` pattern here as well would mean deleting that
    #: guard still left the field validated, and the mutation harness would record a
    #: survivor for a guard that is in fact covered.
    issued_at: str

    @field_validator("issued_at")
    @classmethod
    def _rfc3339_with_offset(cls, value: str) -> str:
        """The one place `issued_at` syntax is decided (plan §10's guard registry)."""
        return _parse_rfc3339_or_raise(value)  # guard:gp_approval_issued_at_syntax


class ApprovalStatement(BaseModel):
    """An in-toto Statement v1 carrying one `ScopeApproval` predicate.

    **Exactly one subject.** `GK-INV-2` says an approval authorizes one
    `(subject_digest, workflow_id, from_state → to_state)` tuple; two subjects would
    make "the digest this approval references" ambiguous, and zero would make it empty.
    The bound is on the model, so neither is reachable.

    **`_type` and `predicateType` have no defaults.** A statement has to *say* what it
    is. Defaulting either would mean accepting an untyped blob and labelling it
    ourselves, which is the read-side mistake `ScopePreimage` avoids by pinning its
    envelope members to `Literal`s (§7): a foreign statement is refused, never decoded
    under rules that did not produce it.

    **Only `_type` needs an alias, and `populate_by_name=True` accompanies it.** Pydantic
    reserves leading-underscore attribute names for private state, so the in-toto
    spelling cannot be a field name; `predicateType` is already a legal identifier and is
    therefore the field name itself, with no alias to keep in step. The plan of record
    (revision 5 §6) fixes exactly this arrangement -- `type_` aliased to `_type`,
    `populate_by_name=True` -- so `type_` and `_type` are both accepted on input while
    `encode_approval`'s `by_alias=True` always emits `_type` on the wire (ST6-R04).

    **One measured laxity, recorded rather than papered over.** With an alias present,
    an input carrying *both* spellings (`{"_type": <valid>, "type_": <anything>}`) takes
    the alias and silently discards the field-name value; an unrelated unknown key still
    raises `extra_forbidden`. This is Pydantic 2.13.5 behaviour under the configuration
    the plan fixes, not a choice made here, and no frozen requirement rejects it.

    Closing it would need a `model_validator(mode="before")`, and one was written during
    ST-6 and removed: a before-validator at the model root hands Pydantic a Python
    object, which **defeats the JSON-aware array → tuple mapping** and makes `subject`
    fail with `tuple_type` -- i.e. it silently converts `model_validate_json` into
    exactly the `json.loads` + `model_validate` two-step §7 forbids package-wide.
    Trading the frozen decode guarantee for a narrower extra-field check is the wrong
    trade. The laxity stands, is pinned by a GP-05 test, and is stated here.
    """

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, populate_by_name=True
    )

    type_: StatementType = Field(alias="_type")
    subject: Annotated[tuple[Subject, ...], Field(min_length=1, max_length=1)]
    predicateType: ScopeApprovalPredicateType
    predicate: ScopeApprovalPredicate
