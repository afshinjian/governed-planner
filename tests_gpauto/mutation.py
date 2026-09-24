"""`GP-AUTO-ST-02`'s mutation obligations: per guard, per mutant, killing test named.

Design basis: AP-11 §8 (`MU11-1`…`MU11-8`), §13 (`EV11-1`(c), `EV11-3`, `EV11-6`),
§16 (`GP-AUTO-ST-02` mutation row), §18 (`PG11-2`).

**Two guards, both named by the frozen stage contract, and no others.**

* `ga_equivalence_compare` — fixed on every guarded line of
  `src/gpauto/equivalence.py` (`MU11-3`); a **line** guard; frozen guarantees
  (`MU11-2b`) `EQ-0`, `EQ-3`…`EQ-6`, `AP03-I04`.
* `ga_codec_decode` — fixed on each decode line of `src/gpauto/codec.py`; a
  **model-enforced** guard; frozen guarantees `DC-1`, `DC-3` (which carries `VM-3`), `VM-11`,
  `ID-2`, `EQ-2`.

**No harness is installed** (`PG11-2` is undischarged, and a tool install would be a
halt). This module is test code that performs exactly the two kinds of mutation the
obligation needs, and nothing more:

* **Line mutation** (`ga_equivalence_compare`). The guarded module's source is read,
  one fragment on a line carrying the guard's identifier is replaced, and the mutated
  source is compiled. Each mutated function is rebuilt over the **real module's own
  globals** and substituted into the module for the duration of one killing test. The
  mutant therefore sees the real module's classes and constants — including anything
  the killing test itself patches — and differs from the original in the one fragment
  and nowhere else.
* **Schema mutation** (`ga_codec_decode`, `MU11-5`). The decode lines check nothing
  themselves; the guard *is* the models. So a mutant is a model whose schema differs
  in one respect — `extra="forbid"` loosened, a `Literal` tag widened to `str` — built
  as a subclass and substituted for the name the codec resolves at the decode line.
  Deleting the line would remove decoding rather than weaken a check, which is why
  line deletion is the wrong mutation here.

**A mutant is killed only by an assertion.** The killing test is run against the
mutant; `AssertionError` or a `pytest.raises` that saw nothing is a kill, a pass is a
survival, and any other exception propagates as an error — a crash is not counted as
detection. **Every mutant is paired with a control**: the same substitution with the
mutation removed, which must *not* be killed, so a kill cannot be an artefact of the
substitution itself.

**What a result means, and no more** (`MU11-2a`). A kill establishes that *that one
mutation was detected by that one test*. There is no score, no percentage and no
completeness claim over the guard set or the codebase, and no guard outside the two
above is claimed verified by anything here. A mutant not run is **not run**, never
passed (`EV11-6`); `main` reports each mutant's own result.

Runnable on its own: `python tests_gpauto/mutation.py`.
"""

from __future__ import annotations

import importlib
import inspect
import re
import sys
import types
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

if __package__ in (None, ""):  # pragma: no cover - only when run as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest
from pydantic import BaseModel, ConfigDict, create_model

from gpauto import codec, equivalence
from gpauto.authorization import AuthorizationRecord
from gpauto.preimage import ArtifactContentPreimage, StageContractContent, StageContractPreimage

GUARD_TAG: Final[re.Pattern[str]] = re.compile(r"# guard:([a-z_]+)")

KILLED = "KILLED"
SURVIVED = "SURVIVED"


@dataclass(frozen=True)
class Guard:
    """A mandatory guard, its location, its kind, and the frozen text behind it."""

    identifier: str
    module: types.ModuleType
    kind: str
    guarantees: tuple[str, ...]


GUARDS: Final[dict[str, Guard]] = {
    "ga_equivalence_compare": Guard(
        identifier="ga_equivalence_compare",
        module=equivalence,
        kind="line",
        guarantees=("EQ-0", "EQ-3", "EQ-4", "EQ-5", "EQ-6", "AP03-I04"),
    ),
    "ga_codec_decode": Guard(
        identifier="ga_codec_decode",
        module=codec,
        kind="schema",
        guarantees=("DC-1", "DC-3", "VM-11", "ID-2", "EQ-2"),
    ),
}


@dataclass(frozen=True)
class LineMutant:
    """Replace `original` — found once, on a line carrying the guard — with `replacement`."""

    guard: str
    identifier: str
    description: str
    original: str
    replacement: str
    killer: str


@dataclass(frozen=True)
class SchemaMutant:
    """Substitute `build()` for the model the codec names `target` at its decode line."""

    guard: str
    identifier: str
    description: str
    target: str
    build: Callable[[], type[BaseModel]]
    killer: str


type Mutant = LineMutant | SchemaMutant

EQUIVALENCE_TESTS = "tests_gpauto/test_ga12_equivalence.py"
CODEC_TESTS = "tests_gpauto/test_ga11_codec.py"


def _envelope_accepting_undeclared_fields() -> type[BaseModel]:
    class Mutant(StageContractPreimage):
        model_config = ConfigDict(extra="ignore")

    return Mutant


def _envelope_accepting_any_version() -> type[BaseModel]:
    return create_model("Mutant", __base__=StageContractPreimage, preimage_version=(str, ...))


def _envelope_accepting_any_class() -> type[BaseModel]:
    return create_model("Mutant", __base__=StageContractPreimage, content_class=(str, ...))


def _content_accepting_undeclared_fields() -> type[BaseModel]:
    class OpenContent(StageContractContent):
        model_config = ConfigDict(extra="ignore")

    return create_model("Mutant", __base__=StageContractPreimage, content=(OpenContent, ...))


def _record_accepting_undeclared_fields() -> type[BaseModel]:
    class Mutant(AuthorizationRecord):
        model_config = ConfigDict(extra="ignore")

    return Mutant


def _artifact_envelope_accepting_any_class() -> type[BaseModel]:
    return create_model("Mutant", __base__=ArtifactContentPreimage, content_class=(str, ...))


def _artifact_envelope_accepting_any_encoding() -> type[BaseModel]:
    return create_model("Mutant", __base__=ArtifactContentPreimage, content_encoding=(str, ...))


MUTANTS: Final[tuple[Mutant, ...]] = (
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-01-negated-equality",
        description="`first_form == second_form` -> `first_form != second_form`",
        original="if first_form == second_form:",
        replacement="if first_form != second_form:",
        killer=f"{EQUIVALENCE_TESTS}::test_a_record_is_equivalent_to_itself",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-02-representational-comparison",
        description="compare the projections as objects (`first == second`), not normal forms",
        original="if first_form == second_form:",
        replacement="if first == second:",
        killer=f"{EQUIVALENCE_TESTS}::test_permuted_and_repeated_set_members_are_equivalent",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-03-always-equivalent",
        description="`first_form == second_form` -> `True`",
        original="if first_form == second_form:",
        replacement="if True:",
        killer=f"{EQUIVALENCE_TESTS}::test_differing_content_in_any_projection_class_is_not_equivalent",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-04-indeterminate-read-as-equivalent",
        description="a normal form that cannot be produced returns EQUIVALENT",
        original="return EquivalenceOutcome.INDETERMINATE  # guard:ga_equivalence_compare",
        replacement="return EquivalenceOutcome.EQUIVALENT  # guard:ga_equivalence_compare",
        killer=f"{EQUIVALENCE_TESTS}::test_an_unrepresentable_value_makes_the_comparison_indeterminate",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-05-cross-identity-computed",
        description="the single-identity refusal is skipped, so two identities are compared",
        original="if not same_identity:",
        replacement="if False:",
        killer=f"{EQUIVALENCE_TESTS}::test_cross_identity_comparison_is_refused_not_computed",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-06-totality-check-dropped",
        description="a projection mapping that is not total is compared anyway",
        original="if not (classes_total and fields_total):",
        replacement="if False:",
        killer=f"{EQUIVALENCE_TESTS}::test_a_projection_mapping_that_is_not_total_is_indeterminate",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-07-set-order-kept",
        description="set members keep their given order instead of the canonical order",
        original="return [members[key] for key in sorted(members)]",
        replacement="return list(members.values())",
        killer=f"{EQUIVALENCE_TESTS}::test_permuted_and_repeated_set_members_are_equivalent",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-01-envelope-extra-ignored",
        description='StageContractPreimage: extra="forbid" -> extra="ignore"',
        target="StageContractPreimage",
        build=_envelope_accepting_undeclared_fields,
        killer=f"{CODEC_TESTS}::test_an_undeclared_envelope_field_is_refused_never_dropped",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-02-version-tag-widened",
        description="StageContractPreimage.preimage_version: Literal[...] -> str",
        target="StageContractPreimage",
        build=_envelope_accepting_any_version,
        killer=f"{CODEC_TESTS}::test_a_higher_format_version_is_refused_not_preferred",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-03-content-class-tag-widened",
        description="StageContractPreimage.content_class: Literal[STAGE_CONTRACT] -> str",
        target="StageContractPreimage",
        build=_envelope_accepting_any_class,
        killer=f"{CODEC_TESTS}::test_a_stage_contract_preimage_labelled_as_another_class_is_refused",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-04-content-extra-ignored",
        description='StageContractContent (inside the envelope): extra="forbid" -> "ignore"',
        target="StageContractPreimage",
        build=_content_accepting_undeclared_fields,
        killer=f"{CODEC_TESTS}::test_an_undeclared_content_field_is_refused_never_dropped",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-05-record-extra-ignored",
        description='AuthorizationRecord: extra="forbid" -> extra="ignore"',
        target="AuthorizationRecord",
        build=_record_accepting_undeclared_fields,
        killer=f"{CODEC_TESTS}::test_an_undeclared_authorization_record_field_is_refused_never_dropped",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-06-artifact-class-tag-widened",
        description="ArtifactContentPreimage.content_class: Literal[ARTIFACT_CONTENT] -> str",
        target="ArtifactContentPreimage",
        build=_artifact_envelope_accepting_any_class,
        killer=f"{CODEC_TESTS}::test_an_artifact_preimage_labelled_as_another_class_is_refused",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-07-artifact-encoding-tag-widened",
        description="ArtifactContentPreimage.content_encoding: Literal[BASE16_LOWER] -> str",
        target="ArtifactContentPreimage",
        build=_artifact_envelope_accepting_any_encoding,
        killer=f"{CODEC_TESTS}::test_an_artifact_preimage_under_another_content_encoding_is_refused",
    ),
)


def source_path(module: types.ModuleType) -> Path:
    assert module.__file__ is not None
    return Path(module.__file__)


def guard_tags() -> dict[str, list[str]]:
    """`guard identifier -> ["file:line", ...]` over the GP-AUTO production package."""
    package = source_path(equivalence).parent
    tags: dict[str, list[str]] = {}
    for path in sorted(package.glob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for identifier in GUARD_TAG.findall(line):
                tags.setdefault(identifier, []).append(f"{path.name}:{number}")
    return tags


def resolve_killer(node_id: str) -> Callable[..., None]:
    """The killing test function a node id names, imported from the test tree."""
    relative, name = node_id.split("::")
    module = importlib.import_module(Path(relative).stem)
    killer = getattr(module, name)
    assert callable(killer)
    return killer  # type: ignore[no-any-return]


def mutated_source(mutant: LineMutant, *, control: bool = False) -> str:
    """The guarded module's source with the mutation applied — or, as a control, not.

    The fragment must occur exactly once, on a line carrying the guard's identifier: a
    mutation that silently matched nothing, or matched an unguarded line, would be a
    mutant of something other than the guard.
    """
    guard = GUARDS[mutant.guard]
    source = source_path(guard.module).read_text(encoding="utf-8")
    assert source.count(mutant.original) == 1, mutant.identifier
    (line,) = [line for line in source.splitlines() if mutant.original in line]
    assert f"# guard:{mutant.guard}" in line, mutant.identifier
    if control:
        return source
    mutated = source.replace(mutant.original, mutant.replacement, 1)
    assert mutated != source, mutant.identifier
    return mutated


@contextmanager
def _line_substituted(
    mutant: LineMutant, monkeypatch: pytest.MonkeyPatch, *, control: bool
) -> Iterator[None]:
    module = GUARDS[mutant.guard].module
    code = compile(mutated_source(mutant, control=control), f"<{mutant.identifier}>", "exec")
    scratch: dict[str, object] = {"__name__": f"{module.__name__}__mutant"}
    exec(code, scratch)
    for name, original in vars(module).items():
        if inspect.isfunction(original) and original.__module__ == module.__name__:
            compiled = scratch[name]
            assert isinstance(compiled, types.FunctionType)
            rebuilt = types.FunctionType(
                compiled.__code__, vars(module), name, compiled.__defaults__, None
            )
            rebuilt.__kwdefaults__ = compiled.__kwdefaults__
            rebuilt.__annotations__ = compiled.__annotations__
            monkeypatch.setattr(module, name, rebuilt)
    yield


@contextmanager
def _schema_substituted(
    mutant: SchemaMutant, monkeypatch: pytest.MonkeyPatch, *, control: bool
) -> Iterator[None]:
    module = GUARDS[mutant.guard].module
    original = getattr(module, mutant.target)
    assert isinstance(original, type) and issubclass(original, BaseModel)
    if control:
        replacement: type[BaseModel] = create_model("Control", __base__=original)
    else:
        replacement = mutant.build()
        assert issubclass(replacement, original), mutant.identifier
        assert _schema(replacement) != _schema(original), mutant.identifier
    monkeypatch.setattr(module, mutant.target, replacement)
    yield


def _schema(model: type[BaseModel]) -> tuple[object, ...]:
    """What a schema mutation must change: configuration, or a field's annotation."""
    nested = model.model_fields.get("content")
    inner = nested.annotation if nested is not None else None
    inner_config = inner.model_config.get("extra") if isinstance(inner, type) and issubclass(
        inner, BaseModel
    ) else None
    return (
        model.model_config.get("extra"),
        tuple((name, info.annotation) for name, info in model.model_fields.items()),
        inner_config,
    )


def run(mutant: Mutant, *, control: bool = False) -> str:
    """Run the named killing test against the mutant (or its control): KILLED or SURVIVED."""
    killer = resolve_killer(mutant.killer)
    with pytest.MonkeyPatch.context() as monkeypatch:
        substitute = (
            _line_substituted(mutant, monkeypatch, control=control)
            if isinstance(mutant, LineMutant)
            else _schema_substituted(mutant, monkeypatch, control=control)
        )
        with substitute:
            wants_monkeypatch = "monkeypatch" in inspect.signature(killer).parameters
            try:
                if wants_monkeypatch:
                    with pytest.MonkeyPatch.context() as killer_patch:
                        killer(monkeypatch=killer_patch)
                else:
                    killer()
            except (AssertionError, pytest.fail.Exception):
                return KILLED
    return SURVIVED


def main() -> int:
    print("GP-AUTO-ST-02 mutation obligations (MU11-7): per guard, per mutant.")
    print("No aggregate score, percentage or completeness claim is made (MU11-2a).\n")
    tags = guard_tags()
    status = 0
    for identifier, guard in GUARDS.items():
        print(f"guard {identifier}  [{guard.kind}]  guarantees: {', '.join(guard.guarantees)}")
        print(f"  fixed at: {', '.join(tags.get(identifier, ['<NOT FOUND>']))}")
        for mutant in (m for m in MUTANTS if m.guard == identifier):
            result = run(mutant)
            control = run(mutant, control=True)
            print(f"  {mutant.identifier:<40} {result:<9} control: {control}")
            print(f"      mutation : {mutant.description}")
            print(f"      killed by: {mutant.killer}")
            if result != KILLED or control != SURVIVED:
                status = 1
        print()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
