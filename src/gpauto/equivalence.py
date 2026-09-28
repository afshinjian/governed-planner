"""Authority-bearing content equivalence: a predicate over one identity, never a selection.

Design basis: AP-07 §5.4 (`EQ-0`…`EQ-10`), §5.2 (`ID-6`, `ID-13`), §23 (`VM-11`);
AP-03 §4.3 (the closed projection), §4.4 (the four required properties), §4.5 (no
ordering, ranking, merge or selection), §4.6; `AP03-I04`, `AP03-I05`; AP-11 §8
(`MU11-3`), §16 (`GP-AUTO-ST-02`).

> **`EQ-0`.** Two `AuthorizationRecord`s `r₁`, `r₂` under one `RA-00` identity are
> content-equivalent iff `normform(project(r₁)) == normform(project(r₂))`, where
> `project` extracts exactly AP-03 §4.3's left-hand column and `normform` is the
> denotational normalization of `EQ-3` serialized under JCS.

That sentence is the whole design, and each clause is realized separately:

* **`project`** is `record.content` — ST-01's `AuthorityBearingContent` *is* the
  closed left-hand column, `RA-01`…`RA-09` plus the liveness-relevant facts. The
  record's own instance identity, and everything else in AP-03 §4.3's right-hand
  column, is outside it and cannot enter the comparison (`EQ-8`).
* **Closed and total** (`EQ-2`, `EQ-6`). `PROJECTION` maps each
  `AuthorityBearingContentClass` to the field that carries it, and the normal form is
  built by walking that mapping. If the mapping and the model ever disagree — a class
  with no field, a field with no class — the comparison is **indeterminate**, never a
  comparison of whatever happened to line up. Nested structures are walked whole, so
  unenumerated content is compared rather than dropped: authority-bearing by default.
* **`normform` is denotational** (`EQ-3`). A reference normalizes as the identity of
  the thing referenced — its kind and its value, **exactly**, with no case folding,
  trimming or Unicode normalization that could make two supplied identifiers compare
  equal (`ID-6`). A role set, and every set-valued bounds dimension, normalizes as a
  **set**: duplicates collapse and members take a canonical order derived from each
  member's own canonical bytes. Ordering members *inside one value* is not consulting
  arrival, insertion or storage order, and no record order is read anywhere
  (`PA-04`, `AP04-I08`). A ceiling is a set of members, each normalized
  dimension-wise; a label normalizes as presence.
* **Serialized under JCS, compared as bytes** (`EQ-4`). Reflexivity, symmetry and
  transitivity then hold *by construction*: they are properties of byte equality of a
  deterministic normal form, so *"all visible records of this identity agree"* cannot
  depend on which pairs were compared in which order. `tests_gpauto` demonstrates the
  three properties rather than asserting them.
* **Under one `RA-00` identity only** (`EQ-5`). The only public comparison takes two
  *records* and **refuses** — it does not answer `NOT_EQUIVALENT` — when their
  authorization identities differ: cross-identity equivalence is meaningless and is
  not computed. There is deliberately no public comparison of bare projections, since
  one would compute exactly that.

**Indeterminate is not equivalence, and it is not an exception sink either** (`EQ-6`,
`P-04`). The outcome is three-valued so that *could not be compared* is never silently
folded into either answer. But indeterminacy is an **architectural** condition with an
enumerated cause, not "anything that went wrong", so exactly three causes produce it
and each is detected on purpose:

1. **The record cannot be decoded** — `pydantic.ValidationError` from the codec
   (`EQ-2`, `DC-3`).
2. **The projection is not total, or carries a value the normal form does not
   recognize** — `_Indeterminate`, raised by this module (`EQ-2`, `EQ-6`, `P-04`).
3. **A string in the projection is not representable in JCS** — `_Indeterminate`,
   raised where that string is normalized (`EQ-6`, `ID-6`).

**Everything else surfaces.** A `RuntimeError`, an assertion, a defect in normal-form
code, an unanticipated exception from anywhere on this path — none of those is an
inability to determine; each is a fault in the software, and reporting one as
`INDETERMINATE` would let a bug present as a governance condition the OWNER is then
asked to resolve. The unrepresentable-string check is therefore made **here**, before
JCS is called, rather than by catching whatever the canonicalizer raises: that keeps the
condition named and owned, and leaves any exception out of `canonical_bytes` free to be
what it is — a defect.

Recording the resulting `AuthorityAmbiguity` and refusing to begin the stage is root
resolution's (`GP-AUTO-ST-06`), not this module's.

**The comparison produces no identity, no key and no ranking** (`EQ-7`, `EQ-10`). Its
normal form and bytes are internal, recomputed on every call, returned to nobody and
stored nowhere. The outcome is a predicate result over exactly two records: there is
no comparator, no ordering, no *"which record to use"*, and no operation taking a set
of candidates and returning one (AP-03 §4.5 — *the absence is the model*).

The guard identifier `ga_equivalence_compare` is fixed where the guard is written, on
every line whose mutation would change the predicate's answer (`MU11-3`).
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from pydantic import ValidationError

from gpauto.authorization import AuthorityBearingContent, AuthorizationRecord
from gpauto.bounds import (
    AuthoritativeInputDesignation,
    AuthorityCeilingMember,
    ReadBoundary,
    WriteBoundary,
)
from gpauto.codec import decode_authorization_record
from gpauto.identity import DomainIdentity
from gpauto.schema import DomainModel
from gpauto.vocabulary import AuthorityBearingContentClass
from gplanner.canonical import canonical_bytes

type NormalValue = str | bool | list[NormalValue] | dict[str, NormalValue]
"""The JSON shapes a normal form is built from. No number, no null: nothing in the
projection is numeric or nullable, so either would mean an unrecognized value."""


class EquivalenceOutcome(StrEnum):
    """The three results of one comparison (`EQ-4`, `EQ-6`). Only `EQUIVALENT` is
    equivalence; `INDETERMINATE` is treated as conflicting, never as agreement."""

    EQUIVALENT = "EQUIVALENT"
    NOT_EQUIVALENT = "NOT_EQUIVALENT"
    INDETERMINATE = "INDETERMINATE"


class CrossIdentityComparison(Exception):
    """Two records under different `RA-00` identities were offered for comparison.

    Different identities are different authorizations regardless of content
    similarity, so the question has no answer and is **not computed** (`EQ-5`).
    """


PROJECTION: Final[Mapping[AuthorityBearingContentClass, str]] = MappingProxyType(
    {
        AuthorityBearingContentClass.PROJECT: "project",
        AuthorityBearingContentClass.STAGE: "stage",
        AuthorityBearingContentClass.CONTRACT: "contract",
        AuthorityBearingContentClass.REPOSITORY_BOUNDARY: "repository_boundary",
        AuthorityBearingContentClass.BASELINE: "baseline",
        AuthorityBearingContentClass.AUTHORIZED_ROLES: "authorized_roles",
        AuthorityBearingContentClass.AUTHORITY_CEILING: "authority_ceiling",
        AuthorityBearingContentClass.OWNER_HUMAN_LABEL_PRESENCE: "owner_human_label_present",
        AuthorityBearingContentClass.PREFLIGHT_PERMISSION: "preflight_permission",
        AuthorityBearingContentClass.LIVENESS_FACTS: "liveness",
    }
)
"""AP-03 §4.3's left-hand column: each projection class and the field carrying it.

Read-only for the reason `bounds.GIT_GRANTABILITY` is: `Final` stops rebinding the
name, not editing the object, and an editable projection would let one assignment
move a class out of the comparison — which AP-03 §4.3 rule 1 permits only by naming
it explicitly in a frozen phase, never at run time.
"""

SET_VALUED_FIELDS: Final[frozenset[tuple[type[DomainModel], str]]] = frozenset(
    {
        (AuthorityBearingContent, "authorized_roles"),
        (AuthorityBearingContent, "authority_ceiling"),
        (AuthorityCeilingMember, "action_classes"),
        (AuthorityCeilingMember, "tool_categories"),
        (AuthorityCeilingMember, "external_action_classes"),
        (ReadBoundary, "scopes"),
        (WriteBoundary, "scopes"),
        (AuthoritativeInputDesignation, "designated_scopes"),
    }
)
"""Every tuple in the projection, each denoting a **set** (`EQ-3`).

A role set is a set. A ceiling is a set of members (`RA-07`, role-indexed), each
normalized dimension-wise; a member's class, category and scope dimensions are bounds,
and a bound is the set it admits. A tuple field **not** listed here is not guessed to be
either a set or a sequence: meeting one makes the comparison indeterminate.
"""


class _Indeterminate(Exception):
    """The comparison cannot be determined, for one of the enumerated reasons (`EQ-6`).

    Raised only by this module, only for a cause the docstring above names. It is **not**
    a wrapper for arbitrary failures: nothing catches a broad exception and re-raises it
    as this, because that is how a defect becomes an architectural condition.
    """


def compare_records(first: AuthorizationRecord, second: AuthorizationRecord) -> EquivalenceOutcome:
    """Are two records under **one** `RA-00` identity content-equivalent? (`EQ-0`)

    Raises `CrossIdentityComparison` rather than answer for two identities (`EQ-5`).
    The records' own instance identities are not consulted (`EQ-8`).
    """
    same_identity = first.authorization_identity == second.authorization_identity
    if not same_identity:  # guard:ga_equivalence_compare
        raise CrossIdentityComparison("equivalence is defined only within one RA-00 identity")
    return _compare_projections(first.content, second.content)


def compare_encoded_records(first: bytes | str, second: bytes | str) -> EquivalenceOutcome:
    """`compare_records` over records still in their JSON form.

    Each is decoded through the codec, and a record that cannot be decoded — unreadable,
    carrying an undeclared field, under a shape the running definition does not cover —
    makes the comparison **indeterminate**, never equivalent (`EQ-2`, `EQ-6`). Two
    encodings differing only in representation compare as what they denote, not as
    bytes (`EQ-1`, `ID-13`).
    """
    try:
        first_record = decode_authorization_record(first)
        second_record = decode_authorization_record(second)
    except ValidationError:
        return EquivalenceOutcome.INDETERMINATE
    return compare_records(first_record, second_record)


def _compare_projections(
    first: AuthorityBearingContent, second: AuthorityBearingContent
) -> EquivalenceOutcome:
    """Byte equality of the two JCS-serialized normal forms (`EQ-0`, `EQ-4`).

    Only `_Indeterminate` is caught — a non-total projection, an unrecognized value, or
    a string JCS cannot represent, each raised deliberately by the normal-form code
    below. A `canonical_bytes` call that fails for any other reason **propagates**: the
    normal form is built from `str`, `bool`, `list` and `dict` with string keys only, and
    every string is checked for representability before it gets here, so there is no
    remaining JCS refusal that is not a defect in this module.

    This is also why no spike exception class is named: none needs to be. `SD11-16`
    keeps the spike's error module inert with respect to GP-AUTO, and narrowing by
    *detecting the condition ourselves* rather than by catching the canonicalizer's
    exception satisfies both constraints at once.
    """
    try:
        first_form = canonical_bytes(_normal_form(first))
        second_form = canonical_bytes(_normal_form(second))
    except _Indeterminate:
        return EquivalenceOutcome.INDETERMINATE  # guard:ga_equivalence_compare
    if first_form == second_form:  # guard:ga_equivalence_compare
        return EquivalenceOutcome.EQUIVALENT
    return EquivalenceOutcome.NOT_EQUIVALENT


def _normal_form(content: AuthorityBearingContent) -> dict[str, NormalValue]:
    """`normform(project(r))`: one entry per projection class, and only if total."""
    classes_total = set(PROJECTION) == set(AuthorityBearingContentClass)
    fields_total = set(PROJECTION.values()) == set(type(content).model_fields)
    if not (classes_total and fields_total):  # guard:ga_equivalence_compare
        raise _Indeterminate("the projection mapping is not total over the projection")
    return {
        str(projection_class): _normalize(getattr(content, field), type(content), field)
        for projection_class, field in PROJECTION.items()
    }


def _normalize(value: object, owner: type[DomainModel], field: str) -> NormalValue:
    """The denotational normal form of one value found at `owner.field` (`EQ-3`)."""
    if isinstance(value, DomainIdentity):
        # A reference normalizes as the thing referenced: its kind and its content,
        # verbatim. The kind keeps a RefusalId and an EnvelopeViolationId with equal
        # values apart where one field admits several identity types.
        normalized = _normalize_model(value)
        normalized["identity_kind"] = type(value).__name__
        return normalized
    if isinstance(value, DomainModel):
        return _normalize_model(value)
    if isinstance(value, tuple):
        if (owner, field) not in SET_VALUED_FIELDS:
            raise _Indeterminate(f"{owner.__qualname__}.{field} is not a known set-valued field")
        members = {
            canonical_bytes(member): member
            for member in (_normalize(item, owner, field) for item in value)
        }
        return [members[key] for key in sorted(members)]  # guard:ga_equivalence_compare
    if isinstance(value, StrEnum):
        return _representable(value.value, owner, field)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _representable(value, owner, field)
    raise _Indeterminate(f"unrecognized value at {owner.__qualname__}.{field}")


def _representable(value: str, owner: type[DomainModel], field: str) -> str:
    """A string JCS cannot encode cannot be compared — that, and nothing wider (`EQ-6`).

    JCS emits UTF-8, so a `str` Python can hold but UTF-8 cannot encode — a lone
    surrogate in a supplied identifier, for instance — has no canonical form and
    therefore no comparable normal form. Detecting it here, on the value, is what lets
    `_compare_projections` catch one named condition instead of every exception: the
    architectural inability is recognized as such, and a fault in the canonicalizer or
    in this module stays a fault.

    No normalization of any kind is applied — no case folding, no trimming, no Unicode
    normalization — because two supplied identifiers that differ must keep differing
    (`ID-6`, `EQ-3`).
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _Indeterminate(
            f"{owner.__qualname__}.{field} holds text that is not representable in JCS"
        ) from exc
    return value


def _normalize_model(model: DomainModel) -> dict[str, NormalValue]:
    """Every declared field of a nested structure — nothing dropped (`EQ-2`)."""
    return {
        name: _normalize(getattr(model, name), type(model), name)
        for name in type(model).model_fields
    }
