"""Structural inspection of the GP-AUTO package, for absence-based evidence.

Design basis: AP-11 §2 (`VP11-4` — structural impossibility outranks tested refusal;
`VP11-5` — absence of a record is never evidence of compliance), §3.2 (an invariant
asserting an impossibility takes **structural absence** as its primary evidence).

Several AP-03 invariants are negative guarantees: a named thing that must be
impossible. `VP11-4` is explicit that for those the verification target is that **no
operation exists**, and that a test merely showing an attempt is refused is weaker
evidence than the absence of the operation. This module gives the tests a way to
assert absence over the package itself — every model class, every field, every
annotation — rather than over one instance that happens to have been built.

It reads the package by import and by syntax tree. It imports no spike module, and
`SD11-16` allows it none: the only GP-SPK-001 modules GP-AUTO may ever import are
`canonical` and `digest`, and those are `GP-AUTO-ST-02`'s, not this stage's.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any, get_args, get_origin

import gpauto
from gpauto.schema import DomainEntity, DomainModel, DomainValue

PACKAGE_ROOT = Path(gpauto.__file__).parent

BASE_CLASSES: tuple[type[DomainModel], ...] = (DomainModel, DomainValue, DomainEntity)


def module_names() -> tuple[str, ...]:
    """Every module in the GP-AUTO package, `gpauto` itself included."""
    found = [info.name for info in pkgutil.iter_modules([str(PACKAGE_ROOT)])]
    return tuple(sorted(f"gpauto.{name}" for name in found) + ["gpauto"])


def source_files() -> tuple[Path, ...]:
    """Every `.py` file in the GP-AUTO package, sorted."""
    return tuple(sorted(PACKAGE_ROOT.rglob("*.py")))


def model_classes() -> tuple[type[DomainModel], ...]:
    """Every `DomainModel` subclass declared in the package, bases included.

    A **parametrization** of a generic entity is not a separate class here: pydantic
    materializes one concrete subclass per parametrization, and counting those would
    report `ArtifactProduction[...]` as extra entities when AP-03 §18.4 is explicit
    that there is one production entity, not two artifact types. The generic origin is
    kept; its parametrizations are skipped.
    """
    seen: dict[str, type[DomainModel]] = {}
    for name in module_names():
        module = importlib.import_module(name)
        for attribute in vars(module).values():
            if (
                isinstance(attribute, type)
                and issubclass(attribute, DomainModel)
                and attribute.__module__.startswith("gpauto")
                and attribute.__pydantic_generic_metadata__["origin"] is None
            ):
                seen[f"{attribute.__module__}.{attribute.__qualname__}"] = attribute
    return tuple(seen[key] for key in sorted(seen))


def entity_classes() -> tuple[type[DomainEntity], ...]:
    """Every concrete `DomainEntity` subclass — the AP-03 entities themselves."""
    return tuple(
        cls
        for cls in model_classes()
        if isinstance(cls, type) and issubclass(cls, DomainEntity) and cls is not DomainEntity
    )


def annotation_atoms(annotation: Any) -> Iterator[Any]:
    """Every leaf of a type annotation: unions, generics and aliases unwrapped.

    A field annotated `Present[ProjectId] | KnownAbsent` must be inspectable as the
    three things it mentions, or an absence assertion over annotations would miss
    anything nested inside a union, a type alias, or a generic parameter — including
    the parametrization of a generic *model*, which pydantic materializes as a
    concrete class rather than leaving as a subscripted generic.
    """
    yield annotation
    origin = get_origin(annotation)
    if origin is not None:
        yield origin
    for argument in get_args(annotation):
        yield from annotation_atoms(argument)
    value = getattr(annotation, "__value__", None)
    if value is not None:
        yield from annotation_atoms(value)
    # A pydantic parametrization of a generic model is a concrete class, so its type
    # arguments are not reachable through `get_args`; they live in the model's own
    # generic metadata. Without this branch an annotation naming
    # `ArtifactProduction[Literal[Provenance.OBJECTIVE]]` would look like a bare class,
    # and every absence assertion about the provenance it admits would read as vacuous.
    metadata = getattr(annotation, "__pydantic_generic_metadata__", None)
    if isinstance(metadata, dict) and metadata.get("origin") is not None:
        yield metadata["origin"]
        for argument in metadata.get("args", ()):
            yield from annotation_atoms(argument)


def declared_fields() -> Iterator[tuple[type[DomainModel], str, Any]]:
    """`(class, field name, annotation)` for every field of every model class."""
    for cls in model_classes():
        for field_name, field_info in cls.model_fields.items():
            yield cls, field_name, field_info.annotation


def class_names() -> frozenset[str]:
    """Every name bound to a class anywhere in the package's syntax trees."""
    names: set[str] = set()
    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                names.add(node.name)
    return frozenset(names)


def imported_modules() -> Iterator[tuple[Path, str]]:
    """`(file, imported module name)` for every import in the package."""
    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield path, alias.name
            elif isinstance(node, ast.ImportFrom):
                yield path, node.module or ""


def reachable_models(root: type[DomainModel]) -> frozenset[type[DomainModel]]:
    """Every model class reachable from `root` by following field annotations.

    An absence assertion about "every bounds structure" has to mean the closure, not
    the one class: a provider field hidden two levels down inside a dimension would
    satisfy a shallow check and defeat the guarantee (`NV11-6`).
    """
    seen: set[type[DomainModel]] = set()
    pending: list[type[DomainModel]] = [root]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for field_info in current.model_fields.values():
            for atom in annotation_atoms(field_info.annotation):
                if isinstance(atom, type) and issubclass(atom, DomainModel):
                    pending.append(atom)
    return frozenset(seen)


def fields_of(models: frozenset[type[DomainModel]]) -> Iterator[tuple[type[DomainModel], str]]:
    """`(class, field name)` over a set of model classes."""
    for cls in sorted(models, key=lambda c: c.__qualname__):
        for field_name in cls.model_fields:
            yield cls, field_name
