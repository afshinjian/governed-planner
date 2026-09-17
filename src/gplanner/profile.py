"""`gplanner.payload-profile/1` — what may appear in a content-addressed payload.

Design basis: design/GP-SPK-001-governance-kernel.md §5 layer 2.

This is **governed-planner policy, not RFC 8785**, and the distinction is deliberate.
The profile refuses two values that JCS accepts perfectly well, so describing it as
canonicalization would misrepresent both: an external verifier reading
`preimage_version` needs to reproduce our bytes with a conforming JCS implementation,
while a *payload* we are willing to give a permanent identity is a narrower thing.

The profile is named and versioned so that `PAYLOAD_PROFILE` can be recorded inside
every hashed preimage. A reader then knows which subset produced a digest, rather than
having to infer it from our source.

Permitted: objects with string keys, arrays, strings, booleans, integers.

Refused, with the reason each is a hazard to identity rather than merely untidy:

* **floats** -- JCS normalizes `1.0` to `1`, so two distinct Python values would map
  onto a single identity. Rejecting is the only way to keep "different content,
  different digest" true.
* **null** -- an absent key and a `null` key produce different bytes, so permitting
  `null` would make identity depend on whether a serializer emitted or omitted an
  empty field. That is a configuration detail, not content.

This module performs no serialization. It inspects a value and refuses; turning a
value into bytes is `canonical.py`'s single responsibility, and a second path to
canonical bytes here would be the beginning of exactly the drift §5 exists to prevent.
"""

from __future__ import annotations

from typing import Any, Final

from gplanner.errors import PayloadProfileViolation

PAYLOAD_PROFILE: Final[str] = "gplanner.payload-profile/1"


def _describe(path: str) -> str:
    return path or "<root>"


def _walk(value: Any, path: str) -> None:
    # bool first: it subclasses int, and both are permitted, but the order makes the
    # intent explicit rather than relying on the subclass relationship.
    if isinstance(value, bool):
        return
    if value is None:
        raise PayloadProfileViolation(
            f"{_describe(path)}: null is outside {PAYLOAD_PROFILE} "
            "(an absent key and a null key hash differently)"
        )
    if isinstance(value, float):
        raise PayloadProfileViolation(
            f"{_describe(path)}: float {value!r} is outside {PAYLOAD_PROFILE} "
            "(JCS normalizes 1.0 to 1, collapsing two values onto one identity)"
        )
    if isinstance(value, int):
        return
    if isinstance(value, str):
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PayloadProfileViolation(
                    f"{_describe(path)}: object key {key!r} is not a string"
                )
            _walk(item, f"{path}.{key}" if path else key)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _walk(item, f"{path}[{index}]")
        return
    raise PayloadProfileViolation(
        f"{_describe(path)}: {type(value).__name__} is outside {PAYLOAD_PROFILE}"
    )


def refuse_outside_profile(payload: Any) -> None:
    """Raise `PayloadProfileViolation` unless `payload` lies within the profile.

    The whole value is walked, not just its surface: a float buried in a nested array
    is exactly as damaging to identity as one at the root, and is harder to notice.

    The refusal names the offending path, because a violation found at hashing time
    is otherwise a hunt through an arbitrarily deep structure.
    """
    _walk(payload, "")  # guard:gp_payload_profile
