"""Builders for `GP-AUTO-ST-02`'s identity, codec and equivalence tests.

Design basis: AP-07 §5 (`ID-*`, `EQ-*`), §23.1 (`DC-1`…`DC-4`); AP-03 §4.3, §4.4;
AP-11 §16 (`GP-AUTO-ST-02` tests and negative tests).

Builders, not fixtures with behaviour, following `fixtures.py`. Two things here are
more than builders and are stated so they are not read as incidental:

* `DIFFERING_IN_ONE_CLASS` gives, for **every** `AuthorityBearingContentClass`, a
  record that differs from the base record in that class and no other. It is keyed by
  the closed vocabulary and `test_ga12` asserts it covers the vocabulary exactly, so
  *"differing authority-bearing content ⇒ not equivalent"* is demonstrated over the
  whole of `RA-01`…`RA-09` plus liveness rather than over the classes a reader
  remembered.
* Characters outside ASCII are built with `chr()` rather than written as escapes, so
  the code point under test is the one named, whatever tool last touched the file.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType

import fixtures
from gpauto.absence import Carried, NotApplicable
from gpauto.authorization import (
    AuthorityBearingContent,
    AuthorizationRecord,
    ConsumedDisposition,
)
from gpauto.bounds import (
    ActionClass,
    AuthoritativeInputDesignation,
    AuthorityCeilingMember,
    ReadBoundary,
    ToolCategory,
    WriteBoundary,
)
from gpauto.identity import (
    AuthorizationRecordId,
    BaselineIdentityId,
    GovernedStageId,
    OwnerAuthorizationId,
    ProjectId,
    RepositoryBoundaryId,
    StageContractId,
    StageOutcomeId,
)
from gpauto.preimage import StageContractContent
from gpauto.schema import DomainModel
from gpauto.vocabulary import (
    AuthorityBearingContentClass,
    BoundedPreflightPermission,
    ExternalActionClass,
    GitCapabilityClass,
    Role,
)

LONE_SURROGATE = chr(0xD800)
"""A `str` Python can hold and JSON text cannot carry — unrepresentable in JCS."""

E_ACUTE_COMPOSED = chr(0xE9)
E_ACUTE_DECOMPOSED = "e" + chr(0x301)
"""The same visible character as one code point (NFC) and as two (NFD)."""

ORDINARY_UTF8_BYTES = ("line one" + chr(10) + "line two " + chr(0xE9)).encode("utf-8")
"""Artifact bytes that happen to be text — a captured transcript, say."""

INVALID_UTF8_BYTES = bytes([0xFF, 0xFE, 0x80])
"""Bytes that are not valid UTF-8 at all: no decoding of them as text exists."""

EMBEDDED_ZERO_BYTES = bytes([0x74, 0x00, 0x78, 0x00])
"""Bytes carrying NUL, which text-shaped handling routinely truncates at."""

HIGH_VALUE_BYTES = bytes(range(0xF0, 0x100))
"""The top of the byte range, where a signed or 7-bit assumption shows up."""

ALL_BYTE_VALUES = bytes(range(256))
"""Every byte value once — the exhaustive round-trip case."""

ARBITRARY_BYTE_CASES: tuple[tuple[str, bytes], ...] = (
    ("empty", b""),
    ("ordinary utf-8", ORDINARY_UTF8_BYTES),
    ("invalid utf-8", INVALID_UTF8_BYTES),
    ("embedded zero", EMBEDDED_ZERO_BYTES),
    ("high byte values", HIGH_VALUE_BYTES),
    ("every byte value", ALL_BYTE_VALUES),
)
"""`RC-21`'s *"bytes as produced"*, as the cases a byte-exact scheme must handle."""


def rebuilt[M: DomainModel](model: M, **changes: object) -> M:
    """`model` with `changes` applied — constructed again, so validated again."""
    return type(model)(**{**fields_of(model), **changes})


def stage_contract_content(**overrides: object) -> StageContractContent:
    """The six named parts of a small contract, optionally overridden."""
    base = StageContractContent(
        objective="objective",
        deliverable_boundary=("deliverable-a", "deliverable-b"),
        explicit_out_of_stage=("out-of-stage",),
        implementation_instructions=("implement",),
        review_instructions=("review",),
        acceptance_criteria=("accepted when",),
    )
    return rebuilt(base, **overrides)


def rich_ceiling() -> tuple[AuthorityCeilingMember, ...]:
    """A two-member ceiling whose set-valued dimensions each hold more than one token.

    **`RA-07`-invalid on purpose**: the writer's `E-16` carries `EGRESS` and `INSTALL`,
    which S6G2-2(g) forbids in a member. Equivalence is validity-agnostic, and a
    multi-token `E-16` is what exercises that dimension's set normalization; `RA-07`
    validity is `GP-AUTO-ST-06`'s and no equivalence test asserts it.
    """
    writer = rebuilt(
        fixtures.implementer_ceiling_member(),
        action_classes=(ActionClass(name="edit"), ActionClass(name="run-tests")),
        read_boundary=ReadBoundary(scopes=("src/", "tests/")),
        write_boundary=Carried[WriteBoundary](value=WriteBoundary(scopes=("src/", "tests/"))),
        tool_categories=(ToolCategory(name="file-edit"), ToolCategory(name="shell")),
        external_action_classes=(ExternalActionClass.EGRESS, ExternalActionClass.INSTALL),
    )
    reviewer = rebuilt(
        fixtures.reviewer_ceiling_member(),
        action_classes=(ActionClass(name="read"), ActionClass(name="run-tests")),
        tool_categories=(ToolCategory(name="file-read"), ToolCategory(name="shell")),
        external_action_classes=(ExternalActionClass.BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA,),
        authoritative_input_designation=Carried[AuthoritativeInputDesignation](
            value=AuthoritativeInputDesignation(designated_scopes=("src/", "tests/"))
        ),
    )
    return (writer, reviewer)


def content(**overrides: object) -> AuthorityBearingContent:
    """An authority-bearing projection with multi-member sets, optionally overridden."""
    changes: dict[str, object] = {
        "authorized_roles": (Role.IMPLEMENTER, Role.DISCOVERY_REVIEWER),
        "authority_ceiling": rich_ceiling(),
    }
    changes.update(overrides)
    return rebuilt(fixtures.authority_bearing_content(), **changes)


def record(
    projection: AuthorityBearingContent | None = None,
    *,
    record_token: str = "record-token",
    authorization: OwnerAuthorizationId = fixtures.AUTHORIZATION_ID,
) -> AuthorizationRecord:
    """One visible assertion under `authorization`, carrying `projection`."""
    return AuthorizationRecord(
        identity=AuthorizationRecordId(value=record_token),
        authorization_identity=authorization,
        content=content() if projection is None else projection,
    )


def fields_of(model: DomainModel) -> dict[str, object]:
    """`{field: value}` for a model, to rebuild it with some fields changed."""
    return {name: getattr(model, name) for name in type(model).model_fields}


def _reversed[T](items: tuple[T, ...]) -> tuple[T, ...]:
    """`items` reversed, with its first item repeated at the end."""
    return (*reversed(items), items[0])


def permuted_member(member: AuthorityCeilingMember) -> AuthorityCeilingMember:
    """`member` with every set-valued dimension reversed and one token repeated."""
    write = member.write_boundary
    designation = member.authoritative_input_designation
    return rebuilt(
        member,
        action_classes=_reversed(member.action_classes),
        read_boundary=ReadBoundary(scopes=_reversed(member.read_boundary.scopes)),
        write_boundary=(
            Carried[WriteBoundary](value=WriteBoundary(scopes=_reversed(write.value.scopes)))
            if isinstance(write, Carried)
            else NotApplicable()
        ),
        tool_categories=_reversed(member.tool_categories),
        external_action_classes=_reversed(member.external_action_classes),
        authoritative_input_designation=(
            Carried[AuthoritativeInputDesignation](
                value=AuthoritativeInputDesignation(
                    designated_scopes=_reversed(designation.value.designated_scopes)
                )
            )
            if isinstance(designation, Carried)
            else NotApplicable()
        ),
    )


def permuted() -> AuthorizationRecord:
    """The base record with every set-valued list reversed and one member repeated.

    The role set, the ceiling's **member order**, and every set-valued dimension inside
    each member are reversed; one role, one member and one token per dimension are
    repeated. The repeated member is identical to one already present, so the ceiling
    denotes the same member set (SP6-17).
    """
    base = content()
    members = tuple(permuted_member(member) for member in reversed(base.authority_ceiling))
    return record(
        content(
            authorized_roles=tuple(reversed(base.authorized_roles)) + (Role.IMPLEMENTER,),
            authority_ceiling=(*members, members[0]),
        ),
        record_token="another-record-token",
    )


def ceiling_with_member(index: int, **changes: object) -> tuple[AuthorityCeilingMember, ...]:
    """`rich_ceiling()` with one member's dimensions changed and every other member kept."""
    ceiling = list(rich_ceiling())
    ceiling[index] = rebuilt(ceiling[index], **changes)
    return tuple(ceiling)


def _ceiling_changed() -> AuthorityBearingContent:
    """One of the ten dimensions of one member changed: the writer's Git capability."""
    return content(
        authority_ceiling=ceiling_with_member(
            0, git_capability_class=GitCapabilityClass.BOUNDED_READ
        )
    )


DIFFERING_IN_ONE_CLASS: Mapping[
    AuthorityBearingContentClass, Callable[[], AuthorityBearingContent]
] = MappingProxyType(
    {
        AuthorityBearingContentClass.PROJECT: lambda: content(
            project=ProjectId(value="other-project")
        ),
        AuthorityBearingContentClass.STAGE: lambda: content(
            stage=GovernedStageId(value="other-stage")
        ),
        AuthorityBearingContentClass.CONTRACT: lambda: content(
            contract=StageContractId(value="other-contract")
        ),
        AuthorityBearingContentClass.REPOSITORY_BOUNDARY: lambda: content(
            repository_boundary=RepositoryBoundaryId(value="other-repository")
        ),
        AuthorityBearingContentClass.BASELINE: lambda: content(
            baseline=BaselineIdentityId(value="other-baseline")
        ),
        AuthorityBearingContentClass.AUTHORIZED_ROLES: lambda: content(
            authorized_roles=(Role.IMPLEMENTER, Role.DISCOVERY_REVIEWER, Role.REMEDIATOR)
        ),
        AuthorityBearingContentClass.AUTHORITY_CEILING: _ceiling_changed,
        AuthorityBearingContentClass.OWNER_HUMAN_LABEL_PRESENCE: lambda: content(
            owner_human_label_present=False
        ),
        AuthorityBearingContentClass.PREFLIGHT_PERMISSION: lambda: content(
            preflight_permission=BoundedPreflightPermission.NOT_PERMITTED
        ),
        AuthorityBearingContentClass.LIVENESS_FACTS: lambda: content(
            liveness=ConsumedDisposition(
                established_by_outcome=StageOutcomeId(
                    parent_stage=fixtures.STAGE_ID, local_discriminator="outcome-token"
                )
            )
        ),
    }
)
"""For each projection class: a projection differing from `content()` in that class only."""
