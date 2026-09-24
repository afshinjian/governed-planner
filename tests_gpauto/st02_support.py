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
from gpauto.absence import Carried
from gpauto.authorization import (
    AuthorityBearingContent,
    AuthorizationRecord,
    ConsumedDisposition,
)
from gpauto.bounds import (
    ActionClass,
    AuthorityBounds,
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


def rich_bounds() -> AuthorityBounds:
    """Writing bounds whose set-valued dimensions each hold more than one member."""
    return rebuilt(
        fixtures.writing_bounds(),
        action_classes=(ActionClass(name="edit"), ActionClass(name="run-tests")),
        read_boundary=ReadBoundary(scopes=("src/", "tests/")),
        write_boundary=Carried[WriteBoundary](value=WriteBoundary(scopes=("src/", "tests/"))),
        tool_categories=(ToolCategory(name="file-edit"), ToolCategory(name="shell")),
        external_action_classes=(ExternalActionClass.EGRESS, ExternalActionClass.INSTALL),
    )


def content(**overrides: object) -> AuthorityBearingContent:
    """An authority-bearing projection with multi-member sets, optionally overridden."""
    changes: dict[str, object] = {
        "authorized_roles": (Role.IMPLEMENTER, Role.DISCOVERY_REVIEWER),
        "authority_ceiling": rich_bounds(),
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


def permuted() -> AuthorizationRecord:
    """The base record with every set-valued member list reversed and one repeated."""
    base = content()
    bounds = base.authority_ceiling
    reversed_bounds = rebuilt(
        bounds,
        action_classes=(*reversed(bounds.action_classes), bounds.action_classes[0]),
        read_boundary=ReadBoundary(scopes=tuple(reversed(bounds.read_boundary.scopes))),
        write_boundary=Carried[WriteBoundary](
            value=WriteBoundary(scopes=("tests/", "src/", "tests/"))
        ),
        tool_categories=tuple(reversed(bounds.tool_categories)),
        external_action_classes=tuple(reversed(bounds.external_action_classes)),
    )
    return record(
        content(
            authorized_roles=tuple(reversed(base.authorized_roles)) + (Role.IMPLEMENTER,),
            authority_ceiling=reversed_bounds,
        ),
        record_token="another-record-token",
    )


def _ceiling_changed() -> AuthorityBearingContent:
    return content(
        authority_ceiling=rebuilt(
            rich_bounds(), git_capability_class=GitCapabilityClass.BOUNDED_READ
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
                established_by_outcome=StageOutcomeId(parent_stage=fixtures.STAGE_ID)
            )
        ),
    }
)
"""For each projection class: a projection differing from `content()` in that class only."""
