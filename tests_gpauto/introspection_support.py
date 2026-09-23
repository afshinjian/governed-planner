"""A one-field holder model, for testing what a strict field will and will not accept.

Design basis: AP-11 §2 (`VP11-4`), §16 (`GP-AUTO-ST-01` negative tests).

Non-interchangeability is a property of *a field annotated with a type*, so testing
it needs a field. This builds the smallest one: a strict model with a single slot of
the requested type, under the same configuration every domain structure uses.
"""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, create_model

from gpauto.schema import DomainValue


def holder_for(annotation: type) -> Callable[..., BaseModel]:
    """A strict model whose only field `slot` is annotated with `annotation`.

    Returned as a callable rather than a model class because the caller's whole
    purpose is to pass it a value the annotation should refuse — which a checked
    signature would reject before the model ever saw it.
    """
    return create_model("Holder", __base__=DomainValue, slot=(annotation, ...))
