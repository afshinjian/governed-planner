"""The universal refusal primitive.

Design basis: design/GP-SPK-001-governance-kernel.md §9.

Every guard site in this package reads the same way::

    require(condition, "why this is refused", error=SomeError)  # guard:gp_<name>

Two reasons for a primitive rather than a bare ``if ... raise`` at each site.

It keeps a guard to **one deletable line**. GP-SPK-002 will port governed-runtime's
mutation harness, which proves a guard is tested by deleting it and requiring the
suite to go red. A multi-line guard deletes into a syntax error, which is reported as
an error rather than a kill and proves nothing about whether the guard was tested. Any
multi-step check therefore belongs in a helper, leaving one deletable call here.

And it makes the refusal's *reason* a required argument. A refusal that cannot say why
it fired is a debugging problem the first time it fires in anger.
"""

from __future__ import annotations

from gplanner.errors import GovernedPlannerError


def require(
    condition: bool,
    reason: str,
    error: type[GovernedPlannerError] = GovernedPlannerError,
) -> None:
    """Raise ``error(reason)`` unless ``condition`` holds.

    The error class is chosen per site rather than inferred, because the same failed
    predicate can mean different things in different places -- the caller knows
    whether a mismatch is a policy refusal or an integrity violation.
    """
    if not condition:
        raise error(reason)
