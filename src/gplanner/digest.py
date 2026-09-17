"""Content-addressed identity — the sole SHA-256 site.

Design basis: design/GP-SPK-001-governance-kernel.md §6.

```
digest = "sha256:" + sha256(canonical_preimage).hexdigest()
```

where `canonical_preimage` is the exact RFC 8785 encoding of
`{preimage_version, payload_profile, media_type, payload}`. Those bytes are **the**
authoritative representation: they are what gets stored, and hashing them again
reproduces the digest directly. Nothing on the read path re-serializes a model, so a
"compute the hash" path and a "verify the hash" path cannot come to disagree about what
was hashed -- the divergence that exists in the sibling `governed-runtime`
(`authority.py:154` versus `:168`).

Three properties, each recorded inside the preimage rather than inferred from this
source:

* **domain separation** -- `media_type` is hashed, so a `ScopeSpec` digest can never
  equal an approval digest carrying the same payload;
* **the scheme is named** -- a reader of the artifact knows which version and which
  payload subset produced the digest;
* **externally reproducible** -- the preimage is plain JSON, so a third party can
  rebuild it and run `sha256sum`. No opaque byte prefix.

The §5 order is fixed here and nowhere else: Pydantic validation → `model_dump(mode=
"json")` → profile guard → JCS → UTF-8 bytes → SHA-256. The profile guard runs *before*
canonicalization, so a value governed-planner declines to content-address is refused
rather than hashed.

This module holds the frozen identity vocabulary -- `PREIMAGE_VERSION` and the media
types -- because `media_type` is a term of the hashed preimage and its meaning is fixed
by this scheme. It deliberately does not live in `artifacts.py`: identity depends on
content, so the dependency runs `digest` → `artifacts` and never back.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Final, Literal

from pydantic import BaseModel

from gplanner.canonical import canonical_bytes
from gplanner.profile import PAYLOAD_PROFILE, refuse_outside_profile
from gplanner.require import require

# The aliases exist so `codec.py` can spell these as `Literal[...]` field types. Type
# checkers reject `Literal[SOME_CONSTANT]`, so the alias is the literal and the constant
# is annotated with it -- a drift between the two lines is a type error, not a surprise
# at run time.
PreimageVersion = Literal["gplanner.preimage/1+jcs-rfc8785"]
ScopeMediaType = Literal["application/vnd.gplanner.scope+json"]

PREIMAGE_VERSION: Final[PreimageVersion] = "gplanner.preimage/1+jcs-rfc8785"

# The media type names the artifact's domain; it carries no version of its own. The
# payload states its own `schema_version` *inside* the hashed preimage, so a schema
# change already changes identity. Repeating the version here would create a second
# version statement that could disagree with the first.
SCOPE_MEDIA_TYPE: Final[ScopeMediaType] = "application/vnd.gplanner.scope+json"

# The approval statement's domain, added at ST-8 because §10 step 2 computes an approval
# digest and this module owns every `media_type` term of a hashed preimage -- putting the
# constant in `kernel.py` would place an identity-bearing value outside the identity
# module. The plan of record names `APPROVAL_MEDIA_TYPE` (revision 5 §12 step 2) without
# fixing its string, so the value follows `SCOPE_MEDIA_TYPE`'s form exactly: the domain,
# no version of its own, with the record stating its own `predicate_version` inside the
# hashed preimage. Its only load-bearing property is that it **differs** from
# `SCOPE_MEDIA_TYPE`, which is what makes §6's domain separation hold -- an approval
# digest can never equal a scope digest carrying the same payload. No `Literal` alias:
# unlike a scope preimage, an approval has no envelope model to pin (`codec.py`).
APPROVAL_MEDIA_TYPE: Final[str] = "application/vnd.gplanner.scope-approval+json"

DIGEST_PREFIX: Final[str] = "sha256:"

# `fullmatch` rather than an anchored `^...$`: in Python `$` also matches before a
# trailing newline, so `"sha256:<hex>\n"` would pass an otherwise identical pattern.
_DIGEST_PATTERN: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}")
_BARE_HEX_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")


def preimage(model: BaseModel, media_type: str) -> dict[str, Any]:
    """Build the structure that identity is computed over.

    `mode="json"` is what makes the payload a JSON value rather than a graph of Python
    objects -- tuples become arrays here, which is why the decode path has to map them
    back (see `codec.py`).

    The profile guard is applied to the payload only. The three envelope members are
    fixed strings written by this module, so the value under scrutiny is the one that
    came from outside it.
    """
    payload = model.model_dump(mode="json")
    refuse_outside_profile(payload)
    return {
        "preimage_version": PREIMAGE_VERSION,
        "payload_profile": PAYLOAD_PROFILE,
        "media_type": media_type,
        "payload": payload,
    }


def canonical_preimage(model: BaseModel, media_type: str) -> bytes:
    """THE authoritative bytes: stored verbatim, hashed verbatim.

    Every other representation of an artifact is a convenience. This one is identity.
    """
    return canonical_bytes(preimage(model, media_type))


def digest_of_preimage_bytes(blob: bytes) -> str:
    """Hash stored bytes exactly as they are.

    Bytes in, digest out -- no parsing, no normalization, no re-encoding. That is what
    lets a verifier confirm identity with `hashlib` alone, holding no model and no
    serializer, and it is the read-path half of GK-INV-1.
    """
    return DIGEST_PREFIX + hashlib.sha256(blob).hexdigest()


def compute_digest(model: BaseModel, media_type: str) -> str:
    """Identity for a model under a media type, via the one canonical byte form."""
    return digest_of_preimage_bytes(canonical_preimage(model, media_type))


def is_digest(value: str) -> bool:
    """Is `value` in the `sha256:<64 lowercase hex>` wire format?

    Lowercase only: hex is case-insensitive as an encoding, so accepting both cases
    would give one artifact two spellings of its identity, and therefore two primary
    keys for one row.
    """
    return _DIGEST_PATTERN.fullmatch(value) is not None


def to_intoto_hex(digest: str) -> str:
    """`sha256:<hex>` → the bare `<hex>` that in-toto's `subject[].digest` carries.

    in-toto omits the algorithm prefix inside the digest map, where we keep it. The
    mismatch is a genuine footgun -- a prefixed value silently stored in an in-toto
    subject is a malformed statement -- so both directions live here, in one place, and
    each validates rather than assuming its input.

    The refusal is not a mutation-harness guard site: the frozen guard-ID registry
    names no guard in this module, and ST-4 is not authorized to extend it.
    """
    require(is_digest(digest), f"not a {DIGEST_PREFIX}<64 lowercase hex> digest: {digest!r}")
    return digest.removeprefix(DIGEST_PREFIX)


def from_intoto_hex(hex_digest: str) -> str:
    """The bare in-toto `<hex>` → our `sha256:<hex>` wire format.

    Validated through the same predicate as the outbound direction, so the two can
    never come to disagree about what a digest is.
    """
    require(
        _BARE_HEX_PATTERN.fullmatch(hex_digest) is not None,
        f"not 64 lowercase hex characters: {hex_digest!r}",
    )
    return DIGEST_PREFIX + hex_digest
