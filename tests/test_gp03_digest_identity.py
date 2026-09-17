"""GP-03 — content-addressed identity and the single decode boundary.

Design basis: design/GP-SPK-001-governance-kernel.md §6, §7, §13.1 requirement 3.

Four sections, separated because they are four different contracts:

* **Section A — identity** (`digest.py`). `digest == "sha256:" + sha256(bytes)` where
  *bytes* are the exact JCS encoding of
  `{preimage_version, payload_profile, media_type, payload}`. There is one
  authoritative byte representation and no second path to it.
* **Section B — `ArtifactRef`** (`artifacts.py`). The reference shape only: what an
  artifact is, which bytes it is, how many. No state, no workflow, no store.
* **Section C — the decode boundary** (`codec.py`). One JSON-aware parse of those same
  authoritative bytes through a validated envelope. Nothing is re-serialized.
* **Section D — why that single path exists.** `json.loads(...)` +
  `model_validate(...)` is asserted to *fail*, so the reason the boundary has its shape
  is recorded in the suite and cannot be "simplified" away later.

The golden digest in Section A was computed by an independent script
(`rfc8785.dumps` + `hashlib.sha256`, no gplanner module involved) before being asserted
here, and every test that checks it recomputes it in-test rather than trusting the
production function. Serialization drift must break the build loudly (plan R-5).

Two properties are asserted here and are *not* the same claim (§7, ST1-R06):

* canonical production — the stored bytes are canonical because §5's fixed pipeline
  produced them;
* schema validation — the envelope governs what may be accepted when reading them
  back.

Neither substitutes for the other, and `extra="forbid"` is not a claim that decode is
injective over arbitrary accepted JSON.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from types import ModuleType
from typing import Any, get_args

import pytest
import rfc8785
from pydantic import BaseModel, ConfigDict, ValidationError

from gplanner.artifacts import ArtifactRef, ScopeSpec
from gplanner.codec import ScopePreimage, decode_scope_from_preimage
from gplanner.digest import (
    PREIMAGE_VERSION,
    SCOPE_MEDIA_TYPE,
    canonical_preimage,
    compute_digest,
    digest_of_preimage_bytes,
    from_intoto_hex,
    is_digest,
    preimage,
    to_intoto_hex,
)
from gplanner.errors import GovernedPlannerError, PayloadProfileViolation
from gplanner.profile import PAYLOAD_PROFILE

# The GP-03 fixture. Frozen alongside the golden digest below: changing any field here
# changes the digest, which is the point of the golden constant.
GOLDEN_SPEC = ScopeSpec(
    title="Governance kernel feasibility",
    problem_statement="Prove the authority model with no LLM in the loop.",
    in_scope=("scope drafting", "human approval"),
    out_of_scope=("signing", "LLM planning"),
    acceptance_criteria=("an approval binds exactly one digest",),
    assumptions=("the approver is who they claim to be",),
)

# Measured once, outside this package, from the bytes below. A serialization change
# anywhere in the pipeline breaks this constant rather than silently reassigning
# identity to every artifact governed-planner has ever issued.
GOLDEN_DIGEST = "sha256:b33872d93a58014a33d53376783fa984abe3e7c17cbdae12e18b5dc9f027179e"
GOLDEN_BYTE_LEN = 521


def independent_digest(spec: ScopeSpec, media_type: str) -> str:
    """Recompute identity without calling any part of `digest.py`.

    Requirement 3 asks for the digest to be recomputed *in-test*: a production
    function compared against itself proves only that it is deterministic.
    """
    blob = rfc8785.dumps(
        {
            "preimage_version": "gplanner.preimage/1+jcs-rfc8785",
            "payload_profile": "gplanner.payload-profile/1",
            "media_type": media_type,
            "payload": spec.model_dump(mode="json"),
        }
    )
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def imported_modules(module: ModuleType) -> set[str]:
    """Every module name `module` imports, by either import form.

    Keyed on *imports* rather than on call shape, exactly as the package-wide decode
    gate is: `import json as j` and `from json import loads` are both caught, while a
    docstring that merely names the forbidden pattern is not.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


def attribute_names(module: ModuleType) -> list[str]:
    """Every attribute accessed in `module`'s code -- prose in docstrings excluded."""
    return [
        node.attr
        for node in ast.walk(ast.parse(inspect.getsource(module)))
        if isinstance(node, ast.Attribute)
    ]


# --- Section A: identity ---------------------------------------------------------


def test_the_preimage_version_is_the_frozen_constant() -> None:
    assert PREIMAGE_VERSION == "gplanner.preimage/1+jcs-rfc8785"


def test_the_digest_wire_format_is_sha256_colon_64_lowercase_hex() -> None:
    digest = compute_digest(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    prefix, _, hexpart = digest.partition(":")
    assert prefix == "sha256"
    assert len(hexpart) == 64
    assert hexpart == hexpart.lower()
    assert set(hexpart) <= set("0123456789abcdef")
    assert is_digest(digest)


def test_the_golden_digest_is_stable() -> None:
    """The loud-failure constant (plan R-5). Drift breaks the build here first."""
    assert compute_digest(GOLDEN_SPEC, SCOPE_MEDIA_TYPE) == GOLDEN_DIGEST


def test_the_digest_is_reproduced_by_an_independent_in_test_recomputation() -> None:
    """Computed from the specification, not by calling the production function."""
    assert independent_digest(GOLDEN_SPEC, SCOPE_MEDIA_TYPE) == GOLDEN_DIGEST
    assert compute_digest(GOLDEN_SPEC, SCOPE_MEDIA_TYPE) == independent_digest(
        GOLDEN_SPEC, SCOPE_MEDIA_TYPE
    )


def test_equal_content_yields_an_equal_digest() -> None:
    """Identity is a function of content, not of object identity or construction."""
    twin = ScopeSpec(**GOLDEN_SPEC.model_dump())
    assert twin is not GOLDEN_SPEC
    assert twin == GOLDEN_SPEC
    assert compute_digest(twin, SCOPE_MEDIA_TYPE) == compute_digest(
        GOLDEN_SPEC, SCOPE_MEDIA_TYPE
    )


def test_a_one_character_content_change_changes_the_digest() -> None:
    changed = GOLDEN_SPEC.model_copy(update={"title": "Governance kernel feasibilitY"})
    assert changed.title != GOLDEN_SPEC.title
    assert compute_digest(changed, SCOPE_MEDIA_TYPE) != GOLDEN_DIGEST


def test_reordering_a_sequence_changes_the_digest() -> None:
    """Order is content. Sorting would silently merge two different specs (§6)."""
    reordered = GOLDEN_SPEC.model_copy(update={"in_scope": ("human approval", "scope drafting")})
    assert sorted(reordered.in_scope) == sorted(GOLDEN_SPEC.in_scope)
    assert compute_digest(reordered, SCOPE_MEDIA_TYPE) != GOLDEN_DIGEST


def test_a_different_media_type_changes_the_digest() -> None:
    """Domain separation (§6.1): the same payload under two media types is two
    artifacts, so a `ScopeSpec` digest can never collide with an approval's."""
    other = compute_digest(GOLDEN_SPEC, "application/vnd.gplanner.other+json")
    assert other != GOLDEN_DIGEST
    assert is_digest(other)


def test_the_preimage_carries_its_version_and_profile() -> None:
    """Recorded *inside* the hashed preimage, so a verifier reading the artifact knows
    which scheme and which payload subset produced the digest (§6.2)."""
    built = preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    assert built["preimage_version"] == PREIMAGE_VERSION
    assert built["payload_profile"] == PAYLOAD_PROFILE
    assert built["media_type"] == SCOPE_MEDIA_TYPE
    assert built["payload"] == GOLDEN_SPEC.model_dump(mode="json")
    assert set(built) == {"preimage_version", "payload_profile", "media_type", "payload"}


def test_the_version_and_profile_are_present_in_the_hashed_bytes() -> None:
    """Not merely in the dict: in the bytes that SHA-256 actually consumed."""
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    assert b'"preimage_version":"gplanner.preimage/1+jcs-rfc8785"' in blob
    assert b'"payload_profile":"gplanner.payload-profile/1"' in blob
    assert b'"media_type":"application/vnd.gplanner.scope+json"' in blob
    assert digest_of_preimage_bytes(blob) == GOLDEN_DIGEST


def test_the_stored_preimage_bytes_rehash_to_the_digest_with_no_reserialization() -> None:
    """GK-INV-1 stated as an operation a verifier can actually perform.

    `canonical_preimage` is the single authoritative representation. Verifying it takes
    `hashlib` and nothing else -- no model, no serializer, no re-encode. That is what
    rules out a mint-path/verify-path divergence, rather than guarding against one.
    """
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    assert len(blob) == GOLDEN_BYTE_LEN
    assert "sha256:" + hashlib.sha256(blob).hexdigest() == GOLDEN_DIGEST
    assert digest_of_preimage_bytes(blob) == compute_digest(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)


def test_the_authoritative_bytes_are_externally_reproducible_plain_json() -> None:
    """A third party reconstructs the preimage and runs sha256sum (§6.3)."""
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    assert json.loads(blob.decode("utf-8")) == preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    assert blob == rfc8785.dumps(preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE))


def test_canonical_preimage_is_byte_identical_on_repetition() -> None:
    first = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    assert all(canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE) == first for _ in range(20))


def test_digest_of_preimage_bytes_hashes_the_bytes_it_is_given() -> None:
    """The primitive is bytes-in, digest-out: no parsing, no normalization."""
    assert digest_of_preimage_bytes(b"") == "sha256:" + hashlib.sha256(b"").hexdigest()
    assert digest_of_preimage_bytes(b"{}") != digest_of_preimage_bytes(b"{ }")


@pytest.mark.parametrize(
    "value",
    [
        "sha256:" + "0" * 64,
        "sha256:" + "abcdef0123456789" * 4,
    ],
    ids=["zeros", "mixed"],
)
def test_is_digest_accepts_the_wire_format(value: str) -> None:
    assert is_digest(value)


@pytest.mark.parametrize(
    "value",
    [
        "a" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "sha256:" + "A" * 64,
        "SHA256:" + "a" * 64,
        "sha512:" + "a" * 64,
        "sha256:" + "a" * 64 + "\n",
        " sha256:" + "a" * 64,
        "",
    ],
    ids=[
        "bare-hex", "too-short", "too-long", "uppercase-hex", "uppercase-prefix",
        "wrong-algorithm", "trailing-newline", "leading-space", "empty",
    ],
)
def test_is_digest_refuses_everything_else(value: str) -> None:
    """The trailing-newline case is deliberate: an anchored `$` would accept it."""
    assert not is_digest(value)


def test_the_intoto_bare_hex_round_trip() -> None:
    """in-toto's `subject[].digest` is `{"sha256": "<bare hex>"}`, with no prefix.

    The mismatch between that and our wire format is a real footgun, so the conversion
    lives in exactly one place and is asserted in both directions (§6).
    """
    bare = to_intoto_hex(GOLDEN_DIGEST)
    assert bare == GOLDEN_DIGEST.removeprefix("sha256:")
    assert ":" not in bare
    assert len(bare) == 64
    assert from_intoto_hex(bare) == GOLDEN_DIGEST
    assert to_intoto_hex(from_intoto_hex(bare)) == bare


@pytest.mark.parametrize(
    "value",
    ["a" * 64, "sha256:sha256:" + "a" * 64, "sha256:" + "a" * 63, "", "not a digest"],
    ids=["already-bare", "double-prefix", "short", "empty", "prose"],
)
def test_to_intoto_hex_refuses_a_value_that_is_not_a_digest(value: str) -> None:
    with pytest.raises(GovernedPlannerError):
        to_intoto_hex(value)


@pytest.mark.parametrize(
    "value",
    ["sha256:" + "a" * 64, "a" * 63, "A" * 64, "", "zz" + "a" * 62],
    ids=["already-prefixed", "short", "uppercase", "empty", "non-hex"],
)
def test_from_intoto_hex_refuses_a_value_that_is_not_bare_hex(value: str) -> None:
    with pytest.raises(GovernedPlannerError):
        from_intoto_hex(value)


def test_the_payload_profile_guard_runs_before_anything_is_hashed() -> None:
    """§5's fixed order: validate -> dump -> profile -> JCS -> bytes -> SHA-256.

    `ScopeSpec` cannot produce a float, so the guard is proved with a model that can.
    The refusal is a `PayloadProfileViolation`, not a canonicalization failure: the
    value is perfectly good JSON that governed-planner declines to content-address.
    """

    class Floaty(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
        ratio: float

    with pytest.raises(PayloadProfileViolation):
        preimage(Floaty(ratio=0.25), SCOPE_MEDIA_TYPE)
    with pytest.raises(PayloadProfileViolation):
        compute_digest(Floaty(ratio=0.25), SCOPE_MEDIA_TYPE)


def test_digest_is_the_only_sha256_site_and_does_not_decode_json() -> None:
    """One hashing site, and no second serializer or decoder beside it (§4, §5)."""
    import gplanner.digest as digest_module

    imports = imported_modules(digest_module)
    assert "json" not in imports
    assert "rfc8785" not in imports, "canonicalization has exactly one importer"

    attributes = attribute_names(digest_module)
    assert attributes.count("sha256") == 1, "SHA-256 is computed in exactly one place"
    assert "model_validate" not in attributes
    assert "model_dump_json" not in attributes
    assert "loads" not in attributes


# --- Section B: ArtifactRef ------------------------------------------------------


def test_artifact_ref_carries_only_the_reference_shape() -> None:
    """Content-addressed reference: what it is, which bytes, how many. Nothing else.

    Asserted as an exact field set for the same reason GP-01 does it for `ScopeSpec`:
    a state, workflow id or timestamp appearing here would make a *reference* carry
    case semantics, which belongs to the store and the kernel, not to identity.
    """
    assert set(ArtifactRef.model_fields) == {"media_type", "digest", "byte_len"}


def test_an_artifact_ref_describes_a_real_artifact() -> None:
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    ref = ArtifactRef(
        media_type=SCOPE_MEDIA_TYPE,
        digest=digest_of_preimage_bytes(blob),
        byte_len=len(blob),
    )
    assert ref.digest == GOLDEN_DIGEST
    assert ref.byte_len == GOLDEN_BYTE_LEN
    assert ref.media_type == SCOPE_MEDIA_TYPE


def test_an_artifact_ref_is_frozen() -> None:
    ref = ArtifactRef(media_type=SCOPE_MEDIA_TYPE, digest=GOLDEN_DIGEST, byte_len=GOLDEN_BYTE_LEN)
    with pytest.raises(ValidationError):
        ref.digest = "sha256:" + "0" * 64


def test_an_artifact_ref_refuses_an_extra_field() -> None:
    with pytest.raises(ValidationError) as excinfo:
        ArtifactRef(
            media_type=SCOPE_MEDIA_TYPE,
            digest=GOLDEN_DIGEST,
            byte_len=GOLDEN_BYTE_LEN,
            state="SCOPE_APPROVED",  # type: ignore[call-arg]
        )
    assert excinfo.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.parametrize(
    "value",
    [
        "a" * 64,
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 64 + "\n",
        "",
    ],
    ids=["bare-hex", "uppercase", "too-short", "trailing-newline", "empty"],
)
def test_the_artifact_ref_digest_constraint_agrees_with_is_digest(value: str) -> None:
    """`artifacts.py` cannot import `digest.py` -- identity depends on content, so the
    dependency runs the other way (§4). The pattern is therefore stated twice, and this
    test is what keeps the two statements from drifting apart."""
    assert not is_digest(value)
    with pytest.raises(ValidationError):
        ArtifactRef(media_type=SCOPE_MEDIA_TYPE, digest=value, byte_len=1)


def test_artifacts_holds_no_identity_computation() -> None:
    """Content only (§4): the module that defines artifacts never hashes one."""
    import gplanner.artifacts as artifacts_module

    source = inspect.getsource(artifacts_module)
    assert "hashlib" not in source
    assert "rfc8785" not in source
    assert "gplanner.digest" not in source


# --- Section C: the decode boundary ----------------------------------------------


def test_decode_returns_a_scope_spec_equal_to_the_original() -> None:
    """The full chain: ScopeSpec -> authoritative bytes -> ScopeSpec."""
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    decoded = decode_scope_from_preimage(blob)
    assert isinstance(decoded, ScopeSpec)
    assert decoded == GOLDEN_SPEC


def test_tuple_fields_survive_the_json_aware_decode_as_tuples() -> None:
    """JSON has arrays; the domain model has tuples. The decode path must bridge that
    without coercion being switched off anywhere."""
    decoded = decode_scope_from_preimage(canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE))
    for field in ("in_scope", "out_of_scope", "acceptance_criteria", "assumptions"):
        value = getattr(decoded, field)
        assert isinstance(value, tuple), f"{field} decoded as {type(value).__name__}"
        assert all(isinstance(member, str) for member in value)
    assert decoded.in_scope == ("scope drafting", "human approval")


def test_the_decoded_spec_recomputes_the_same_identity() -> None:
    """Round-trip stability. Note what this is *not*: verification does not need it.

    Identity is checked by hashing the stored bytes (Section A). This asserts the
    weaker, separate property that decoding loses nothing.
    """
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    decoded = decode_scope_from_preimage(blob)
    assert canonical_preimage(decoded, SCOPE_MEDIA_TYPE) == blob
    assert compute_digest(decoded, SCOPE_MEDIA_TYPE) == GOLDEN_DIGEST


def test_the_envelope_configuration_is_declared_on_the_envelope_itself() -> None:
    """Pydantic configuration is per-class: the nested `ScopeSpec`'s strictness says
    nothing about the envelope, and an envelope with no `model_config` accepts and
    silently discards unknown top-level fields (§7, measured on pydantic 2.13.5)."""
    assert ScopePreimage.model_config["frozen"] is True
    assert ScopePreimage.model_config["extra"] == "forbid"
    assert ScopePreimage.model_config["strict"] is True


def test_the_envelope_literals_are_the_package_constants() -> None:
    """The envelope's accepted vocabulary is exactly the vocabulary the preimage
    writes. Pinned as an equality so the two cannot drift apart silently."""
    fields = ScopePreimage.model_fields
    assert get_args(fields["preimage_version"].annotation) == (PREIMAGE_VERSION,)
    assert get_args(fields["payload_profile"].annotation) == (PAYLOAD_PROFILE,)
    assert get_args(fields["media_type"].annotation) == (SCOPE_MEDIA_TYPE,)
    assert fields["payload"].annotation is ScopeSpec


def test_a_decoded_envelope_cannot_be_mutated() -> None:
    """Frozen: nothing can be edited into the envelope after its digest was checked."""
    envelope = ScopePreimage.model_validate_json(canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE))
    with pytest.raises(ValidationError) as excinfo:
        envelope.media_type = SCOPE_MEDIA_TYPE  # the *same* value: frozen is frozen
    assert excinfo.value.errors()[0]["type"] == "frozen_instance"


def _tampered(**overrides: Any) -> bytes:
    """Authoritative bytes with one envelope field replaced. Still valid JSON."""
    built = preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    built.update(overrides)
    return rfc8785.dumps(built)


def test_a_foreign_preimage_version_is_refused_not_decoded() -> None:
    """A blob written under another scheme is refused outright. Decoding it would mean
    interpreting bytes under rules that did not produce them (§7)."""
    with pytest.raises(ValidationError) as excinfo:
        decode_scope_from_preimage(_tampered(preimage_version="gplanner.preimage/2+cbor"))
    assert excinfo.value.errors()[0]["type"] == "literal_error"


def test_a_foreign_payload_profile_is_refused_not_decoded() -> None:
    with pytest.raises(ValidationError) as excinfo:
        decode_scope_from_preimage(_tampered(payload_profile="gplanner.payload-profile/2"))
    assert excinfo.value.errors()[0]["type"] == "literal_error"


def test_a_foreign_media_type_is_refused_not_decoded() -> None:
    """Domain separation on the read path: an approval preimage must not decode into a
    `ScopeSpec` merely because its payload happens to fit."""
    with pytest.raises(ValidationError) as excinfo:
        decode_scope_from_preimage(_tampered(media_type="application/vnd.gplanner.approval+json"))
    assert excinfo.value.errors()[0]["type"] == "literal_error"


def test_an_extra_envelope_field_is_refused_never_silently_dropped() -> None:
    """`extra="forbid"` enforces the approved envelope schema: undeclared data is
    refused rather than accepted and dropped on the floor.

    It does **not** establish that every distinct accepted byte string decodes to a
    distinct object, and no such claim is read into it here (§7)."""
    with pytest.raises(ValidationError) as excinfo:
        decode_scope_from_preimage(_tampered(signature="not-yet-a-thing"))
    assert excinfo.value.errors()[0]["type"] == "extra_forbidden"


def test_insignificant_whitespace_decodes_equally_and_is_not_claimed_otherwise() -> None:
    """The limiting claim, asserted rather than left implicit (§7, ST1-R06).

    Two byte strings differing only in JSON whitespace have different SHA-256 values
    yet decode to equal objects. Decode is not injective, canonical production and
    schema validation are separate contracts, and `GK-INV-1` speaks only about the
    authoritative canonical bytes.
    """
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    spaced = b" " + blob + b" "
    assert spaced != blob
    assert digest_of_preimage_bytes(spaced) != digest_of_preimage_bytes(blob)
    assert decode_scope_from_preimage(spaced) == decode_scope_from_preimage(blob)


def test_a_missing_envelope_field_is_refused() -> None:
    built = preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    del built["media_type"]
    with pytest.raises(ValidationError) as excinfo:
        decode_scope_from_preimage(rfc8785.dumps(built))
    assert excinfo.value.errors()[0]["type"] == "missing"


def test_a_non_string_member_inside_the_payload_is_refused_not_coerced() -> None:
    """Strictness holds end to end, through the envelope into the nested model."""
    built = preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    built["payload"]["in_scope"] = ["scope drafting", 7]
    with pytest.raises(ValidationError) as excinfo:
        decode_scope_from_preimage(rfc8785.dumps(built))
    assert excinfo.value.errors()[0]["type"] == "string_type"


def test_an_extra_payload_field_is_refused() -> None:
    built = preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    built["payload"]["digest"] = GOLDEN_DIGEST
    with pytest.raises(ValidationError) as excinfo:
        decode_scope_from_preimage(rfc8785.dumps(built))
    assert excinfo.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.parametrize(
    "blob",
    [b"", b"not json", b"{", b"[]", b'"a string"', b"null"],
    ids=["empty", "prose", "truncated", "array", "string", "null"],
)
def test_a_blob_that_is_not_an_envelope_is_refused(blob: bytes) -> None:
    with pytest.raises(ValidationError):
        decode_scope_from_preimage(blob)


def test_the_decode_boundary_holds_no_second_identity_serializer() -> None:
    """One parse of the authoritative bytes, and no second serializer beside the
    identity path -- which is the drift that produced governed-runtime's two
    incompatible canonicalizers (§7).

    Read from the syntax tree, not the source text: this module's docstring has to be
    free to *name* the forbidden pattern in order to explain why it is forbidden.

    Widened at ST-6, and only where ST-6's authorized scope made it necessary. `codec`
    gained the approval **transport** pair (§7's last paragraph), so it now imports
    `approvals`, parses twice -- once per decoder -- and emits JSON text from
    `encode_approval`. What the test protects is unchanged and is the reason it was
    written: `codec` still reaches no serializer that could produce *identity* bytes.
    No `rfc8785`, no `json`, no `hashlib`, no `model_validate`. `model_dump_json` is
    Pydantic's rendering, is not the RFC 8785 canonical preimage, and is never hashed;
    GP-05 asserts that separately.
    """
    import gplanner.codec as codec_module

    assert imported_modules(codec_module) == {
        "__future__",
        "typing",
        "pydantic",
        "gplanner.approvals",
        "gplanner.artifacts",
        "gplanner.digest",
    }

    attributes = attribute_names(codec_module)
    assert attributes.count("model_validate_json") == 2, "one parse per decoder"
    assert "model_validate" not in attributes
    assert [name for name in attributes if name.startswith("model_dump")] == ["model_dump_json"]
    assert "dumps" not in attributes and "loads" not in attributes
    assert "sha256" not in attributes


# --- Section D: why the single decode path exists --------------------------------


def test_json_loads_plus_model_validate_fails_on_strict_tuple_fields() -> None:
    """The reason the boundary has the shape it has, recorded as an executable fact.

    `json.loads` produces `list`; `ConfigDict(strict=True)` refuses a `list` for a
    `tuple[...]` field. The natural-looking two-step therefore fails at *runtime*, on
    the decode path, which is exercised far less than the encode path. Asserting it
    here means the single path cannot be "simplified" back later without this test
    going red first.

    This is the one place in the repository where the forbidden pattern appears, and
    it appears in order to prove it is broken.
    """
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    payload = json.loads(blob.decode("utf-8"))["payload"]
    assert isinstance(payload["in_scope"], list)

    with pytest.raises(ValidationError) as excinfo:
        ScopeSpec.model_validate(payload)

    types = [error["type"] for error in excinfo.value.errors()]
    assert types and set(types) == {"tuple_type"}
    assert {str(error["loc"][0]) for error in excinfo.value.errors()} == {
        "in_scope",
        "out_of_scope",
        "acceptance_criteria",
        "assumptions",
    }


def test_the_same_bytes_go_through_the_json_aware_path_cleanly() -> None:
    """Same input, same model, different entry point: the JSON-aware parse maps arrays
    to tuples while keeping strict member checking."""
    blob = canonical_preimage(GOLDEN_SPEC, SCOPE_MEDIA_TYPE)
    assert decode_scope_from_preimage(blob) == GOLDEN_SPEC


def test_the_forbidden_pattern_is_absent_from_the_package() -> None:
    """`json.loads(...)` + `model_validate(...)` appears in no production module.

    The gate keys on *imports* rather than call shape, so `import json as j` and
    `from json import loads` are caught too, and it reads the syntax tree rather than
    the source text, so a docstring naming the pattern is not mistaken for using it.

    `codec.py` is the only module permitted to touch JSON at all, and it does so only
    through Pydantic -- so the expected number of `json` importers is zero, not one.
    """
    import pathlib

    import gplanner

    package_root = pathlib.Path(gplanner.__file__).parent
    offenders: list[str] = []
    for path in sorted(package_root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "json" or alias.name.startswith("json."):
                        offenders.append(f"{path.name}:{node.lineno}: imports json")
            elif isinstance(node, ast.ImportFrom) and (node.module or "") == "json":
                offenders.append(f"{path.name}:{node.lineno}: from json import")
            elif isinstance(node, ast.Attribute) and node.attr == "model_validate":
                offenders.append(f"{path.name}:{node.lineno}: model_validate")
    assert offenders == []
