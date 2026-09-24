"""Authority-bearing equivalence: AP-03 §4.4's four properties, demonstrated.

Design basis: AP-07 §5.4 (`EQ-0`…`EQ-10`), §5.1 (`ID-6`), §5.2 (`ID-13`), §23
(`VM-11`); AP-03 §4.3, §4.4, §4.5; `AP03-I04`, `AP03-I05`; AP-11 §16 (`GP-AUTO-ST-02`
tests and negative tests), §8 (`MU11-7`).

AP-03 §4.4 names four required properties. Each is shown here rather than asserted:

* **Reflexive, symmetric, transitive** — over every pair and every triple of a family
  mixing equivalent and non-equivalent records.
* **Denotational, not representational** — permuted and repeated set members,
  re-serialized records, and a different record instance identity are all
  `EQUIVALENT`.
* **Total over the projection** — each of `RA-01`…`RA-09` plus liveness is shown to
  change the answer; an incomplete projection, an unknown shape, an unreadable record
  and an unrepresentable value are all `INDETERMINATE`, never `EQUIVALENT`.
* **Only within one `RA-00` identity** — cross-identity comparison is **refused**, not
  answered.

The tests the equivalence guard's mutants are killed by take no fixtures and call the
predicate through its module, so a mutant substituted into the module is the thing
they exercise (`MU11-7`, `test_ga13`).
"""

from __future__ import annotations

import ast
import itertools
from collections.abc import Iterator
from pathlib import Path

import pytest

import fixtures
import st02_support
from gpauto import equivalence
from gpauto.authorization import AuthorityBearingContent, AuthorizationRecord
from gpauto.equivalence import (
    PROJECTION,
    SET_VALUED_FIELDS,
    CrossIdentityComparison,
    EquivalenceOutcome,
)
from gpauto.identity import OwnerAuthorizationId, ProjectId
from gpauto.schema import DomainModel
from gpauto.vocabulary import AuthorityBearingContentClass
from introspect import reachable_models

GPAUTO_STAGE = "GP-AUTO-ST-02"

EQUIVALENT = EquivalenceOutcome.EQUIVALENT
NOT_EQUIVALENT = EquivalenceOutcome.NOT_EQUIVALENT
INDETERMINATE = EquivalenceOutcome.INDETERMINATE


# --- Reflexive, symmetric, transitive --------------------------------------------


@pytest.mark.traces("EQ-4", "EQ-0", "AP03-I04", "ST02-A2")
def test_a_record_is_equivalent_to_itself() -> None:
    """Reflexivity, for the base record and for each single-class variant."""
    base = st02_support.record()
    assert equivalence.compare_records(base, base) is EQUIVALENT
    for build in st02_support.DIFFERING_IN_ONE_CLASS.values():
        variant = st02_support.record(build())
        assert equivalence.compare_records(variant, variant) is EQUIVALENT


def _family() -> list[AuthorizationRecord]:
    """Records under one identity, several mutually equivalent and several not."""
    members = [
        st02_support.record(),
        st02_support.permuted(),
        st02_support.record(record_token="third-record"),
    ]
    members.extend(
        st02_support.record(build(), record_token=f"variant-{projection_class}")
        for projection_class, build in st02_support.DIFFERING_IN_ONE_CLASS.items()
    )
    return members


@pytest.mark.traces("EQ-4", "AP03-I04", "ST02-A2")
def test_equivalence_is_reflexive_symmetric_and_transitive_over_a_family() -> None:
    """All three properties, over every pair and every triple of the family.

    Transitivity is what makes *"all visible records of this identity agree"*
    independent of which pairs were compared in which order (`EQ-4`). The family is
    built so that both answers occur, or the check would be vacuous.
    """
    family = _family()
    outcome = {
        (i, j): equivalence.compare_records(family[i], family[j])
        for i, j in itertools.product(range(len(family)), repeat=2)
    }
    assert set(outcome.values()) == {EQUIVALENT, NOT_EQUIVALENT}

    for i in range(len(family)):
        assert outcome[(i, i)] is EQUIVALENT
    for i, j in itertools.product(range(len(family)), repeat=2):
        assert outcome[(i, j)] is outcome[(j, i)], (i, j)
    for i, j, k in itertools.product(range(len(family)), repeat=3):
        if outcome[(i, j)] is EQUIVALENT and outcome[(j, k)] is EQUIVALENT:
            assert outcome[(i, k)] is EQUIVALENT, (i, j, k)


# --- Denotational, not representational ------------------------------------------


@pytest.mark.traces("EQ-3", "ST02-A2")
def test_permuted_and_repeated_set_members_are_equivalent() -> None:
    """A role set compares as a set, and a ceiling's set-valued dimensions as bounds.

    Every member list is reversed and one member repeated, in the role set and in each
    of the ceiling's set-valued dimensions: the records denote the same authority.
    """
    assert (
        equivalence.compare_records(st02_support.record(), st02_support.permuted())
        is EQUIVALENT
    )


@pytest.mark.traces("EQ-8", "ST02-A2")
def test_the_records_own_instance_identity_does_not_enter_the_comparison() -> None:
    """`EQ-8`: a record's instance identity is non-authority-bearing, by explicit name."""
    first = st02_support.record(record_token="record-one")
    second = st02_support.record(record_token="record-two")
    assert first.identity != second.identity
    assert equivalence.compare_records(first, second) is EQUIVALENT


@pytest.mark.traces("EQ-1", "ID-13", "ST02-A2")
def test_re_serialized_records_compare_as_what_they_denote() -> None:
    """`EQ-1`: over the projection, never over stored bytes.

    Compact, indented, and member-reordered encodings of one record are three
    different byte strings — and so, by `ID-13`, three different content digests —
    and they are equivalent. Comparing bytes would make a re-serialization a conflict
    and halt GP-AUTO on formatting, which AP-03 §4.4 forbids by name.
    """
    record = st02_support.record()
    compact = record.model_dump_json()
    indented = record.model_dump_json(indent=2)
    tail = compact[1:].split(',"content":', 1)
    reordered = '{"content":' + tail[1][:-1] + "," + tail[0] + "}"
    assert len({compact, indented, reordered}) == 3
    for other in (indented, reordered):
        assert equivalence.compare_encoded_records(compact, other) is EQUIVALENT


# --- Total over the projection: differing content is not equivalent ---------------


@pytest.mark.traces("ST02-N3", "ST02-T3", "EQ-0", "AP03-I04")
def test_differing_content_in_any_projection_class_is_not_equivalent() -> None:
    """`RA-01`…`RA-09` plus liveness: each class, changed alone, changes the answer.

    Keyed by the closed vocabulary and checked to cover it exactly, so no class can be
    missing from the demonstration without this test failing.
    """
    assert set(st02_support.DIFFERING_IN_ONE_CLASS) == set(AuthorityBearingContentClass)
    base = st02_support.record()
    for projection_class, build in st02_support.DIFFERING_IN_ONE_CLASS.items():
        variant = st02_support.record(build(), record_token="variant")
        assert variant.content != base.content, projection_class
        assert equivalence.compare_records(base, variant) is NOT_EQUIVALENT, projection_class
        assert equivalence.compare_records(variant, base) is NOT_EQUIVALENT, projection_class


@pytest.mark.traces("ST02-N3", "ST02-T3", "EQ-0")
def test_differing_liveness_facts_are_not_equivalent() -> None:
    """The liveness-relevant facts are in the projection (AP-03 §4.3), establisher and all.

    Two suspensions established by different governance events are different facts,
    and so are two suspensions whose establishers share a token but not a kind.
    """
    from gpauto.authorization import SuspendedDisposition
    from gpauto.identity import EnvelopeViolationId, RefusalId

    by_refusal = st02_support.record(
        st02_support.content(
            liveness=SuspendedDisposition(established_by_event=RefusalId(value="e"))
        )
    )
    by_violation = st02_support.record(
        st02_support.content(
            liveness=SuspendedDisposition(established_by_event=EnvelopeViolationId(value="e"))
        )
    )
    assert equivalence.compare_records(by_refusal, by_violation) is NOT_EQUIVALENT
    assert equivalence.compare_records(st02_support.record(), by_refusal) is NOT_EQUIVALENT


@pytest.mark.traces("ID-6", "EQ-3")
@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("project-token", "PROJECT-TOKEN"),
        ("project-token", "project-token "),
        ("project-token", " project-token"),
        (st02_support.E_ACUTE_COMPOSED, st02_support.E_ACUTE_DECOMPOSED),
    ],
    ids=["case", "trailing-space", "leading-space", "nfc-vs-nfd"],
)
def test_supplied_identifiers_are_compared_verbatim(first: str, second: str) -> None:
    """`ID-6`: never normalized in any way that could make two identifiers compare equal.

    A reference normalizes as the identity of the thing referenced (`EQ-3`), and the
    identity *is* its token: no case folding, no trimming, no Unicode normalization.
    """
    one = st02_support.record(st02_support.content(project=ProjectId(value=first)))
    two = st02_support.record(st02_support.content(project=ProjectId(value=second)))
    assert equivalence.compare_records(one, two) is NOT_EQUIVALENT


# --- Total over the projection: indeterminate is not equivalence ------------------


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("ST02-A2", "ST02-N3")
def test_an_unrepresentable_value_makes_the_comparison_indeterminate() -> None:
    """`EQ-6`: a projection class that cannot be normalized is indeterminate — even
    when the record is compared with itself. Indeterminate is **not** equivalence."""
    broken = st02_support.record(
        st02_support.content(project=ProjectId(value=st02_support.LONE_SURROGATE))
    )
    assert equivalence.compare_records(broken, broken) is INDETERMINATE
    assert equivalence.compare_records(broken, st02_support.record()) is INDETERMINATE


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("EQ-2", "ST02-A2")
def test_a_projection_mapping_that_is_not_total_is_indeterminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`EQ-2`: the projection is enumerated and closed. If a class ever had no entry,
    the comparison is indeterminate — never a comparison of what happened to remain."""
    reduced = {
        key: value
        for key, value in PROJECTION.items()
        if key is not AuthorityBearingContentClass.LIVENESS_FACTS
    }
    monkeypatch.setattr(equivalence, "PROJECTION", reduced)
    base = st02_support.record()
    assert equivalence.compare_records(base, base) is INDETERMINATE


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("EQ-3")
def test_a_tuple_not_known_to_be_a_set_is_indeterminate(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tuple is not guessed to be a set or a sequence: unknown ⇒ indeterminate."""
    roles = (AuthorityBearingContent, "authorized_roles")
    reduced = frozenset(entry for entry in SET_VALUED_FIELDS if entry != roles)
    monkeypatch.setattr(equivalence, "SET_VALUED_FIELDS", reduced)
    base = st02_support.record()
    assert equivalence.compare_records(base, base) is INDETERMINATE


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("EQ-2", "DC-3")
def test_an_unreadable_or_open_record_makes_the_comparison_indeterminate() -> None:
    """`EQ-6`: absent, unreadable or unrecognized ⇒ indeterminate, never equivalent.

    An undeclared field makes the projection non-total (`EQ-2`), so a record carrying
    one is not partially compared: it is not compared at all.
    """
    good = st02_support.record().model_dump_json()
    widened = '{"issued_at":"2026-09-23",' + good[1:]
    for other in (widened, good[:-5], "", b"\xff\xfe"):
        assert equivalence.compare_encoded_records(good, other) is INDETERMINATE
        assert equivalence.compare_encoded_records(other, good) is INDETERMINATE


# --- Only within one RA-00 identity -----------------------------------------------


@pytest.mark.traces("EQ-5", "AP03-I04", "ST02-A2")
def test_cross_identity_comparison_is_refused_not_computed() -> None:
    """`EQ-5`: different identities are different authorizations, whatever their content.

    The predicate refuses rather than answering `NOT_EQUIVALENT` — an answer would be a
    computation of the meaningless relation — and that holds even for identical
    content, and for identities differing only in case.
    """
    base = st02_support.record()
    for other_identity in (
        fixtures.OTHER_AUTHORIZATION_ID,
        OwnerAuthorizationId(value=fixtures.AUTHORIZATION_ID.value.upper()),
    ):
        other = st02_support.record(authorization=other_identity)
        assert other.content == base.content
        with pytest.raises(CrossIdentityComparison):
            equivalence.compare_records(base, other)
        with pytest.raises(CrossIdentityComparison):
            equivalence.compare_encoded_records(base.model_dump_json(), other.model_dump_json())


@pytest.mark.traces("EQ-5", "EQ-10", "AP03-I04")
def test_no_public_comparison_takes_a_bare_projection() -> None:
    """A projection carries no `RA-00`, so comparing bare projections would compute
    cross-identity equivalence. Every public comparison takes records."""
    import inspect
    import typing

    public = {
        name: value
        for name, value in vars(equivalence).items()
        if inspect.isfunction(value)
        and value.__module__ == equivalence.__name__
        and not name.startswith("_")
    }
    assert set(public) == {"compare_records", "compare_encoded_records"}
    record_hints = typing.get_type_hints(equivalence.compare_records)
    assert record_hints == {
        "first": AuthorizationRecord,
        "second": AuthorizationRecord,
        "return": EquivalenceOutcome,
    }
    assert AuthorityBearingContent not in record_hints.values()


# --- The projection itself ----------------------------------------------------------


def _tuple_fields(root: type[DomainModel]) -> Iterator[tuple[type[DomainModel], str]]:
    import typing

    for cls in reachable_models(root):
        for name, info in cls.model_fields.items():
            if typing.get_origin(info.annotation) is tuple:
                yield cls, name


@pytest.mark.traces("EQ-2", "EQ-8", "AP03-I04", "ST02-D2")
def test_the_projection_is_exactly_the_closed_left_hand_column() -> None:
    """AP-03 §4.3: every class mapped to exactly one field, every field to one class.

    And nothing from the right-hand column is in it — no instance identity, no
    authorization identity, no format version, no time, order or storage location — and
    every tuple anywhere in it is one the normal form knows to be a set (`EQ-3`).
    """
    assert set(PROJECTION) == set(AuthorityBearingContentClass)
    assert set(PROJECTION.values()) == set(AuthorityBearingContent.model_fields)
    assert len(set(PROJECTION.values())) == len(PROJECTION)

    fields = set(AuthorityBearingContent.model_fields)
    for excluded in ("identity", "authorization_identity", "version", "format_version"):
        assert excluded not in fields
    assert set(_tuple_fields(AuthorityBearingContent)) == set(SET_VALUED_FIELDS)

    with pytest.raises(TypeError):
        PROJECTION[AuthorityBearingContentClass.PROJECT] = "stage"  # type: ignore[index]


@pytest.mark.traces("EQ-8", "VM-11", "ST02-N4")
def test_no_format_version_enters_the_normal_form() -> None:
    """`EQ-8`, `VM-11`: a format version is non-authority-bearing and orders nothing.

    The normal form is built from the projection alone, and no key or value anywhere in
    it names a version — so a version can neither break an equivalence nor rank one.
    """
    normal = equivalence._normal_form(st02_support.record().content)

    def keys(value: object) -> Iterator[str]:
        if isinstance(value, dict):
            for key, inner in value.items():
                yield key
                yield from keys(inner)
        elif isinstance(value, list):
            for inner in value:
                yield from keys(inner)

    assert set(normal) == {str(member) for member in AuthorityBearingContentClass}
    assert not [key for key in keys(normal) if "version" in key.lower()]


# --- Indeterminacy is enumerated, not an exception sink ---------------------------


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("ST02-A2")
def test_the_comparison_path_catches_no_broad_exception() -> None:
    """`EQ-6` is an architectural condition, not a place for failures to be absorbed.

    Read structurally, over the module's syntax tree, because this is a claim about what
    the code *cannot* do: a broad `except Exception`, a bare `except`, or a catch of
    `BaseException` on this path would turn a defect into an outcome the OWNER is then
    asked to resolve. Only the enumerated conditions are caught, and each is named.
    """
    tree = ast.parse(Path(equivalence.__file__ or "").read_text(encoding="utf-8"))
    caught: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if node.type is None:
            caught.append("<bare except>")
        else:
            caught.extend(
                atom.id
                for atom in ast.walk(node.type)
                if isinstance(atom, ast.Name)
            )
    assert caught == ["ValidationError", "_Indeterminate", "UnicodeEncodeError"]
    assert "Exception" not in caught
    assert "BaseException" not in caught


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("ST02-A2")
def test_the_unrepresentable_value_case_is_detected_by_name_not_by_catching_jcs() -> None:
    """The one legitimate value-level inability, raised where the value is normalized.

    A `str` Python holds but UTF-8 cannot encode has no canonical form and therefore no
    comparable normal form. The module recognizes that itself, so the answer does not
    depend on catching whatever the canonicalizer happens to raise — and the
    canonicalizer stays free to fail loudly if it ever fails for another reason.
    """
    with pytest.raises(equivalence._Indeterminate):
        equivalence._representable(
            st02_support.LONE_SURROGATE, AuthorityBearingContent, "project"
        )
    assert (
        equivalence._representable("ordinary", AuthorityBearingContent, "project") == "ordinary"
    )


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("ST02-A2")
def test_an_injected_runtime_error_surfaces_instead_of_becoming_indeterminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fault in the canonicalizer is a fault, not an inability to determine.

    This is the exact regression the narrowing exists to prevent: under a broad catch,
    every one of these would have been reported as `INDETERMINATE` — a software defect
    presenting as a governance condition.
    """
    base = st02_support.record()

    def _explode(_value: object) -> bytes:
        raise RuntimeError("a defect in the canonicalizer, not an inability to determine")

    monkeypatch.setattr(equivalence, "canonical_bytes", _explode)
    with pytest.raises(RuntimeError):
        equivalence.compare_records(base, base)


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("ST02-A2")
@pytest.mark.parametrize(
    "failure",
    [RuntimeError("bug"), AssertionError("programming error"), TypeError("unexpected shape")],
    ids=["RuntimeError", "AssertionError", "TypeError"],
)
def test_a_defect_in_normal_form_code_surfaces(
    failure: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever goes wrong inside the normal form, it is not indeterminacy."""

    def _explode(*_args: object, **_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(equivalence, "_normalize", _explode)
    base = st02_support.record()
    with pytest.raises(type(failure)):
        equivalence.compare_records(base, base)


@pytest.mark.supports("EQ-6")
@pytest.mark.traces("ST02-A2", "ST02-T3")
def test_narrowing_indeterminacy_left_the_relation_intact() -> None:
    """The three outcomes still mean what they meant, and the refusal still refuses."""
    base = st02_support.record()
    other = st02_support.record(st02_support.content(project=ProjectId(value="other-project")))
    broken = st02_support.record(
        st02_support.content(project=ProjectId(value=st02_support.LONE_SURROGATE))
    )

    assert equivalence.compare_records(base, base) is EQUIVALENT
    assert equivalence.compare_records(base, other) is NOT_EQUIVALENT
    assert equivalence.compare_records(broken, base) is INDETERMINATE

    foreign = st02_support.record(
        authorization=OwnerAuthorizationId(value="another-authorization")
    )
    with pytest.raises(CrossIdentityComparison):
        equivalence.compare_records(base, foreign)
