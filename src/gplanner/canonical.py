"""RFC 8785 / JCS canonicalization.

Design basis: design/GP-SPK-001-governance-kernel.md §5 layer 1.

This module is **policy-free**. It accepts every valid JSON value -- objects with
string keys, arrays, strings, finite numbers including floats, booleans and `null` --
and refuses only values that are not JSON. It holds no opinion about what
governed-planner is willing to content-address; that is `profile.py`, deliberately a
separate layer (§5 layer 2).

The separation matters because a subset described as "RFC 8785" is not RFC 8785. An
external verifier reading `preimage_version` must be able to reproduce our bytes using
any conforming JCS implementation, so the canonicalizer here has to behave like the
published specification and nothing narrower.

`rfc8785` is the sole canonicalization implementation. governed-planner does not carry
a hand-rolled serializer, and no second path to canonical bytes may exist: the sibling
`governed-runtime` runs two mutually incompatible canonicalizers side by side
(`canonical.py:55` versus `contracts.py:51`), which disagree on integral floats and on
non-BMP key ordering. One implementation is the correction.
"""

from __future__ import annotations

from typing import Any

import rfc8785

from gplanner.errors import CanonicalizationError


def canonical_bytes(value: Any) -> bytes:
    """Serialize `value` to its RFC 8785 canonical UTF-8 bytes.

    Refusal is delegated to `rfc8785` rather than pre-screened here, so this layer
    cannot drift from the specification it claims to implement: whatever JCS deems
    unrepresentable is what gets refused. The library's exception is translated into
    this package's vocabulary -- a caller catches `gplanner.errors` without importing
    the serializer or knowing which one is in use -- and chained, so the original
    reason survives for diagnosis.

    Note the name collision: `rfc8785.CanonicalizationError` is a `ValueError` and is
    a different class from ours. The translation below is what keeps that detail from
    leaking to callers.

    `UnicodeEncodeError` is caught alongside it because the library does not raise its
    own error for every refusal. JCS orders keys by UTF-16 code unit, so `rfc8785`
    encodes each key to `utf-16-be` in order to sort it
    (`rfc8785/_impl.py:238`), and that encode sits outside its error handling: a lone
    surrogate key raised `UnicodeEncodeError` straight through this function. It is a
    `ValueError` but not an `rfc8785.CanonicalizationError`, so the clause below
    missed it. The same surrogate in a *value* was already translated correctly, which
    is exactly why the gap was easy to miss.

    The two caught classes are named explicitly rather than widened to `ValueError`:
    the public contract should cover the serializer's failures, not every value error
    that might arise from a future change here.
    """
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeEncodeError) as exc:
        raise CanonicalizationError(f"value is not representable in JCS: {exc}") from exc
