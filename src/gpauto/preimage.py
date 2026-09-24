"""The canonical-preimage schema for GP-AUTO's two content identities.

Design basis: AP-07 §5.1 (`ID-1`, `ID-2`), §5.2 (`ID-9`…`ID-13`), §23 (`VM-11`),
§23.1 (`DC-3`, `DC-4`); AP-03 §2.1, §2.5, §3, §3.1 rows 4 and 7; AP-11 §14
(`SD11-1`, `SD11-2`, `SD11-16`), §16 (`GP-AUTO-ST-02`).

**What a content identity is computed over.** `ID-9` fixes content identity as
`sha256(canonical_preimage)`, reusing GP-SPK-001's `GK-INV-1` pattern as a primitive
(`PA-12`): the preimage is one RFC 8785 encoding of a small, named envelope, and those
exact bytes are the single authoritative representation. The envelope has three
members and no more:

* `preimage_version` — **names the scheme**, so a reader of the bytes knows which
  envelope and which canonicalizer produced them. Byte-stability is claimed only for
  the pinned canonicalizer (`ID-12`), which is why the tag carries `jcs-rfc8785`.
  It is a **format tag and nothing else** (`VM-11`): it is a single-member `Literal`,
  so there is no second value to be "newer" than, and a preimage written under any
  other tag is refused on decode rather than preferred, ranked or read as recency.
* `content_class` — **domain separation** between the two content identities `ID-2`
  permits, so a stage contract and an artifact can never share an identity through
  identical payload bytes.
* `content_encoding` — **how the payload represents what it denotes**, so the envelope
  says how to recover the thing it names rather than leaving a reader to infer it from
  our source. Like `preimage_version` it is a single-member `Literal`: there is no
  second value to be newer than, and it is format information only, never recency,
  precedence or freshness (`VM-11`).
* `content` — the content itself, in that encoding.

**GP-AUTO's envelope is its own, deliberately.** The spike's `digest.preimage()`
embeds GP-SPK-001's `payload_profile` and applies `profile.py`'s content policy — a
component `SD11-9` retains untouched and `SD11-16` forbids GP-AUTO behaviour from
depending on. GP-AUTO therefore reuses the two pure primitives only — JCS bytes from
`canonical`, SHA-256 of bytes from `digest` — and names its own scheme here, rather
than stamping GP-AUTO content with a `gplanner` scheme tag it was not produced under.

**Exactly two content classes** (`ID-2`, `AP03-I03`). Content identity extended to an
authorization would make same-identity conflict impossible by construction; to an
envelope, it would collapse an equivalent re-derivation onto a consumed identity; to
a production, it would merge two occurrences; to a frozen set, every empty set would
be one. `ContentClass` is closed at `StageContract` and `ArtifactContent`.

**Artifact content is bytes, including bytes that are not text.** AP-03 §2.5 and §8.1
say an `ArtifactContent` is *"the bytes themselves, and nothing else"*, and AP-07
`RC-21` names its content column *"the bytes as produced"*. A test transcript, a
measured diff and a captured tool output are whatever the producing path emitted: they
may be invalid UTF-8, carry an embedded zero byte, or be wholly binary. **The JSON
codec boundary does not narrow the artifact-content identity domain** — it is the
boundary GP-AUTO decodes *through*, not a statement about what artifact content may be.

So the payload is **lowercase base-16 of the exact bytes**, and the envelope says so.
Four properties are what make this a representation rather than a reinterpretation:

* **Deterministic** — one byte string has exactly one base-16 spelling, because the
  alphabet is fixed, the case is fixed, and the length is fixed at two characters per
  byte. No padding, no line breaks, no alternatives.
* **Reversible** — the exact bytes come back, and `tests_gpauto` recovers them for
  invalid UTF-8, an embedded zero byte and high-byte values, not only for text.
* **Unambiguous** — `content` is constrained to `^(?:[0-9a-f]{2})*$` on the model, so a
  payload that is not an even-length lowercase base-16 string is **refused on decode**
  rather than half-recovered. Mixed case, whitespace and odd length are all refused,
  which is what makes the mapping single-valued in both directions.
* **Domain-separated** — `content_class` already keeps the two content identities
  apart, and `content_encoding` additionally keeps the artifact payload from being read
  as the text it is a spelling of.

**This is not a binary codec subsystem, a second canonicalizer or a second digest.**
There is still one JCS site and one SHA-256 site, both in `content_identity.py`, both
imported primitives. Base-16 is a spelling of bytes inside the one JCS envelope, not a
serialization format of its own: it has no framing, no types, no versions of its own
and no second identity path.

**And it is still only the bytes.** The envelope carries no provenance, no producer, no
occurrence and no standing, so an `ArtifactProduction`'s minted occurrence identity
stays a different question from the content identity of the bytes it binds (`ID-14`,
`AP03-I19`). Nor is the payload a decoded GP-AUTO domain value: these bytes are content
GP-AUTO names, not JSON GP-AUTO reads.

This module is schema only: no function, no canonicalization, no digest. The
derivation is `content_identity.py`'s and the decode is `codec.py`'s, so the schema
the decode-path guard depends on has exactly one definition (`MU11-5`).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import Field

from gpauto.schema import DomainValue

PreimageVersion = Literal["gpauto.content-preimage/1+jcs-rfc8785"]
"""The scheme tag as a type. A type checker rejects `Literal[SOME_CONSTANT]`, so the
alias is the literal and the constant below is annotated with it — a drift between the
two lines is a type error, not a surprise at run time (the spike's `digest.py` idiom)."""

PREIMAGE_VERSION: Final[PreimageVersion] = "gpauto.content-preimage/1+jcs-rfc8785"


class ContentClass(StrEnum):
    """The only two content-identified classes (`ID-2`, `S-11`). Closed."""

    STAGE_CONTRACT = "STAGE_CONTRACT"
    ARTIFACT_CONTENT = "ARTIFACT_CONTENT"


class ContentEncoding(StrEnum):
    """How a preimage payload represents what it denotes. Closed at two.

    `TEXT` is a stage contract's parts, carried as the strings they are. `BASE16_LOWER`
    is an artifact's exact bytes, spelled two lowercase hex digits per byte — the only
    member that exists for bytes, so there is no second spelling to disagree with it.
    """

    TEXT = "TEXT"
    BASE16_LOWER = "BASE16_LOWER"


Base16Payload = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})*$")]
"""An even-length lowercase base-16 string, and nothing else.

The constraint is on the model, so a malformed payload is refused where bytes are
decoded rather than guessed at afterwards: `bytes.fromhex` would accept whitespace and
mixed case and would therefore admit several spellings of one byte string, which is
exactly the ambiguity this pattern removes.
"""


class StageContractContent(DomainValue):
    """The six named parts of one `StageContract`, without its identity (AP-03 §2.1).

    The identity is *derived from* these parts, so it cannot also be one of them. The
    field set is `StageContract`'s minus `identity`, and `tests_gpauto` pins that
    equality structurally so the two cannot drift. Part order within each tuple is
    content as authored: content identity names bytes, never denotation (`ID-13`).
    """

    objective: str
    deliverable_boundary: tuple[str, ...]
    explicit_out_of_stage: tuple[str, ...]
    implementation_instructions: tuple[str, ...]
    review_instructions: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]


class StageContractPreimage(DomainValue):
    """The envelope a stage-contract preimage must satisfy to be produced or read back.

    Strict, closed and frozen through `DomainValue`. The two tag members are
    `Literal`s, so a preimage written under another scheme or labelled as another
    content class is **refused rather than decoded** — a reader that decoded foreign
    bytes would be interpreting them under rules that did not produce them.
    """

    preimage_version: PreimageVersion
    content_class: Literal[ContentClass.STAGE_CONTRACT]
    content_encoding: Literal[ContentEncoding.TEXT]
    content: StageContractContent


class ArtifactContentPreimage(DomainValue):
    """The envelope an artifact-content preimage must satisfy (AP-03 §8.1, `RC-21`).

    Carries the bytes as produced, and nothing else: no provenance, no standing, no
    producer — those belong to an `ArtifactProduction` occurrence and never to the
    bytes (`AP03-I19`, `ID-14`).

    `content` is base-16 of the exact bytes, constrained on the model so that recovery
    is single-valued. Any byte string is representable, text or not.
    """

    preimage_version: PreimageVersion
    content_class: Literal[ContentClass.ARTIFACT_CONTENT]
    content_encoding: Literal[ContentEncoding.BASE16_LOWER]
    content: Base16Payload
