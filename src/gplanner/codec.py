"""The single JSON → domain boundary.

Design basis: design/GP-SPK-001-governance-kernel.md §7.

Domain models are `strict=True` with `tuple[...]` fields. Strict validation refuses a
`list`, and `json.loads` produces lists, so the natural-looking two-step --
`json.loads(...)` then `model_validate(...)` -- fails at run time on a *valid* artifact.
It is forbidden package-wide and appears nowhere outside the GP-03 test that proves it
broken. Every JSON → domain conversion goes through Pydantic's JSON-aware validation,
and all of it lives here.

Artifact recovery is **one parse of the authoritative bytes** through a validated
envelope, not an extract-and-re-serialize. Re-emitting the extracted payload as JSON
would put a second, plausible-looking serialization path right beside the identity path,
and sooner or later something would hash it -- which is how the sibling
`governed-runtime` came to run two mutually incompatible canonicalizers.

This module imports no serializer, computes no digest, and holds no policy about what a
digest means. Artifact recovery is decode-only: there is no `encode_scope`, because the
authoritative bytes already exist and re-emitting them is the drift described above.

**Approval transport is the one thing this module also encodes, and it is not an
identity path (§7).** `encode_approval` emits Pydantic's JSON so an `ApprovalStatement`
can cross a workflow boundary as JSON *text* rather than as a `dict` or a pickle. Those
bytes are transport: they carry no `preimage_version`, no `payload_profile` and no
`media_type`, they are not RFC 8785, and nothing may hash them. An approval's identity,
when §10 needs it, is computed by `digest.py` from the model through §5's one pipeline —
which is why this module still imports no serializer and no hash.

**The envelope's `model_config` is load-bearing and is not optional.** Pydantic
configuration is per-class: the nested `ScopeSpec`'s strictness says nothing about the
envelope, and an envelope declared without it has `model_config == {}`, accepts an
unknown top-level field and silently discards it, and is mutable (measured on pydantic
2.13.5).

What `extra="forbid"` does and does not establish, stated so no stronger claim is read
into it. It **enforces the approved envelope schema**: a preimage carrying a field this
design never defined is refused outright rather than accepted and dropped. It does
**not** establish that every distinct accepted byte string decodes to a distinct domain
object -- two inputs differing only in insignificant JSON whitespace hash differently
yet decode to equal `ScopeSpec` objects. Decode is not injective over arbitrary accepted
JSON, and `GK-INV-1` does not say it is: that invariant speaks about the authoritative
canonical bytes and their digest. **Canonical production and schema validation are
separate contracts**, and neither substitutes for the other.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from gplanner.approvals import ApprovalStatement
from gplanner.artifacts import ScopeSpec
from gplanner.digest import PreimageVersion, ScopeMediaType

# `profile.PAYLOAD_PROFILE` is typed `Final[str]`, and a type checker rejects
# `Literal[SOME_CONSTANT]`, so the accepted profile is spelled as a literal here. GP-03
# pins this alias against `profile.PAYLOAD_PROFILE` by equality so the two cannot drift.
PayloadProfile = Literal["gplanner.payload-profile/1"]


class ScopePreimage(BaseModel):
    """The envelope a stored `ScopeSpec` preimage must satisfy to be read back.

    The three envelope members are `Literal`s, so a blob written under a different
    scheme, profile or media type is **refused rather than decoded**. That is the
    read-side counterpart to recording the scheme inside the hashed preimage at all: a
    reader that silently decoded a foreign preimage would be interpreting bytes under
    rules that did not produce them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    preimage_version: PreimageVersion
    payload_profile: PayloadProfile
    media_type: ScopeMediaType
    payload: ScopeSpec


def decode_scope_from_preimage(blob: bytes) -> ScopeSpec:
    """THE ONLY way to turn stored preimage bytes back into a `ScopeSpec`.

    One JSON-aware parse of the authoritative bytes. JSON arrays become tuples with
    strict member checking preserved end to end, through the envelope and into the
    nested model; nothing is re-serialized, and no second parse exists to drift from
    this one.
    """
    return ScopePreimage.model_validate_json(blob).payload  # guard:gp_preimage_envelope


def encode_approval(statement: ApprovalStatement) -> str:
    """An `ApprovalStatement` -> the JSON **text** that crosses the transport boundary.

    `by_alias=True` is what makes the output an in-toto statement rather than a
    Pydantic rendering of one: the wire spellings are `_type` and `predicateType`, and
    the Python field names exist only because Pydantic reserves leading underscores.
    Omitting it would emit a document no in-toto reader accepts, and which this
    package's own decoder would then refuse.

    Text, not a `dict` and not a pickle. A `dict` crossing the boundary would be a
    second ingestion path beside `decode_approval`, and pickle would make the approval
    channel a code-execution channel.

    Transport only. These bytes are not the approval's identity -- see this module's
    docstring -- and no caller may hash them.
    """
    return statement.model_dump_json(by_alias=True)


def decode_approval(payload: str | bytes) -> ApprovalStatement:
    """THE ONLY way to turn transport JSON back into an `ApprovalStatement`.

    One JSON-aware parse, so `subject` arrives as a `tuple` with strict member checking
    intact -- the property `json.loads` + `model_validate` destroys (§7). `str` and
    `bytes` are both accepted because Pydantic accepts both and the transport may hand
    over either; neither is decoded differently.

    Every structural constraint is on the model, so this line performs no check of its
    own. That is why the frozen `gp_transport_decode` guard is model-enforced rather
    than a deletable line: deleting the call removes decoding altogether instead of
    weakening a check, so GP-SPK-002's harness mutates the schema here (CLAUDE.md).
    """
    return ApprovalStatement.model_validate_json(payload)  # guard:gp_transport_decode
