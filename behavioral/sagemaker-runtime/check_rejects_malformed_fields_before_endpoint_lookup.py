"""rejects-malformed-fields-before-endpoint-lookup."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rejects-malformed-fields-before-endpoint-lookup"
GROUP = 'rejection'
SERVICES = ['sagemaker-runtime']

_BODY = b'{"instances": [[1.0, 2.0]]}'
# 6 MiB + 1 byte: one byte past com.amazonaws.sagemakerruntime#BodyBlob's declared
# length {max: 6291456}. Deliberately minimal — the point is to cross the modelled
# ceiling, not to upload a large payload.
_OVER_MODELLED_BODY_CEILING = b'x' * 6291457


def _refusal(fn):
    """The ClientError fn() raised. Raises AssertionError if the call SUCCEEDED.

    Never returns a falsy sentinel on success: an emulator accepting input real AWS refuses
    is the strongest signal this check can produce, and returning "" for it would read as a
    mere error-code mismatch.
    """
    try:
        resp = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(
        f"the call was ACCEPTED and returned {resp.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}"
        f" — sagemaker-runtime must refuse it"
    )


def _code_and_message(exc) -> tuple[str, str]:
    err = exc.response.get("Error", {})
    return err.get("Code", ""), err.get("Message", "")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeEndpoint validates its fields before the endpoint lookup: a malformed name, length or
    TargetVariant gets a ValidationError naming each violated field (both fields when two are wrong)
    without the not-found text, while a well-formed absent endpoint gets the account-scoped message."""
    smr = ctx.client("sagemaker-runtime")

    absent = ctx.unique_name("sim2real-behav-smr-absent-")
    assert len(absent) <= 63 and "_" not in absent, (
        f"the control endpoint name must itself satisfy EndpointName's pattern and 63-char "
        f"ceiling, or the control proves nothing; got {absent!r} ({len(absent)} chars)"
    )
    underscore = absent.replace("-", "_")
    overlong = (absent + "-" + "x" * 64)[:64]

    def _invoke(name, body=_BODY, **kw):
        """A thunk firing one InvokeEndpoint; every call below differs from the control by
        exactly one argument."""
        return lambda: smr.invoke_endpoint(
            EndpointName=name, Body=body, ContentType="application/json", **kw
        )

    # --- (1) The POSITIVE CONTROL, first, because everything below is defined relative to it:
    # a well-formed name that names nothing passes the constraint layer and reaches the
    # account-scoped endpoint lookup.
    control = _refusal(_invoke(absent))
    code, lookup_msg = _code_and_message(control)
    assert code == "ValidationError", (
        f"an absent-but-well-formed endpoint name must be refused with ValidationError "
        f"(not ValidationException); got {code!r}: {lookup_msg!r}"
    )
    assert control.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 400, (
        f"ValidationError is modelled @httpError(400); got "
        f"{control.response.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}"
    )
    assert lookup_msg.startswith(f"Endpoint {absent} of account ") and lookup_msg.endswith(
        " not found."
    ), (
        f"reaching the endpoint lookup must report the name AND the account that was searched "
        f"— the lookup is account-scoped, which is the whole content of this stage; got "
        f"{lookup_msg!r}"
    )
    assert "validation error" not in lookup_msg, (
        f"a well-formed request must NOT be reported as a constraint violation; got {lookup_msg!r}"
    )

    # --- (2) One malformed field: the constraint layer answers, and says nothing about
    # existence. This is the precedence claim in the direction that matters for information
    # disclosure.
    pattern_code, pattern_msg = _code_and_message(_refusal(_invoke(underscore)))
    assert pattern_code == "ValidationError", (
        f"a name violating EndpointName's pattern must be refused with ValidationError; "
        f"got {pattern_code!r}: {pattern_msg!r}"
    )
    assert pattern_msg.startswith("1 validation error detected:"), (
        f"a single violation must be reported as exactly one, with a count; got {pattern_msg!r}"
    )
    assert f"Value '{underscore}' at 'endpointName'" in pattern_msg, (
        f"the violation must be attributed to the endpointName field and quote the offending "
        f"value; got {pattern_msg!r}"
    )
    assert "not found" not in pattern_msg, (
        f"the endpoint lookup must NOT have run: a malformed name that also names nothing must "
        f"not disclose non-existence, or the constraint layer is being applied after the "
        f"lookup; got {pattern_msg!r}"
    )

    # --- (3) A different constraint on the same field: length, not pattern. The two must be
    # distinguishable, or an emulator can answer one canned message for any bad name.
    length_code, length_msg = _code_and_message(_refusal(_invoke(overlong)))
    assert length_code == "ValidationError", (
        f"a name past EndpointName's 63-char ceiling must be refused with ValidationError; "
        f"got {length_code!r}: {length_msg!r}"
    )
    assert "Member must have length less than or equal to 63" in length_msg, (
        f"the length violation must name the modelled ceiling rather than reusing the pattern "
        f"message; got {length_msg!r}"
    )
    assert "regular expression pattern" not in length_msg, (
        f"a length violation and a pattern violation must not collapse to the same message; "
        f"got {length_msg!r}"
    )

    # --- (4) Per-field attribution: the same class of violation on a DIFFERENT field must name
    # that field, with the endpoint name left well-formed so nothing else can be blamed.
    variant_code, variant_msg = _code_and_message(
        _refusal(_invoke(absent, TargetVariant="sim2real_behav_variant"))
    )
    assert variant_code == "ValidationError", (
        f"a TargetVariant violating its pattern must be refused with ValidationError; "
        f"got {variant_code!r}: {variant_msg!r}"
    )
    assert "at 'targetVariant'" in variant_msg and "at 'endpointName'" not in variant_msg, (
        f"the violation must be attributed to targetVariant alone — the endpoint name in this "
        f"call is well-formed; got {variant_msg!r}"
    )
    assert "not found" not in variant_msg, (
        f"a malformed TargetVariant must also pre-empt the endpoint lookup; got {variant_msg!r}"
    )

    # --- (5) TWO simultaneous violations: real AWS ACCUMULATES them. A first-fail validator
    # reports one; this reports both, with a count of 2.
    both_code, both_msg = _code_and_message(
        _refusal(_invoke(underscore, TargetVariant="sim2real_behav_variant"))
    )
    assert both_code == "ValidationError", (
        f"two simultaneous violations must still be one ValidationError; got {both_code!r}: "
        f"{both_msg!r}"
    )
    assert both_msg.startswith("2 validation errors detected:"), (
        f"the constraint layer must report ALL violations with their count, not stop at the "
        f"first: expected a '2 validation errors detected:' prefix, got {both_msg!r}"
    )
    assert "at 'endpointName'" in both_msg and "at 'targetVariant'" in both_msg, (
        f"both offending fields must be named in the accumulated message; got {both_msg!r}"
    )

    # --- (6) BodyBlob's modelled 6291456-byte maximum is not enforced in that layer: one byte past it
    # still reaches the endpoint lookup, so a validator that enforces the model's ceiling refuses a
    # request the service accepts.
    over_code, over_msg = _code_and_message(
        _refusal(_invoke(absent, body=_OVER_MODELLED_BODY_CEILING))
    )
    assert over_code == "ValidationError", (
        f"the oversize-body call must still be refused for the endpoint, with ValidationError; "
        f"got {over_code!r}: {over_msg!r}"
    )
    assert over_msg == lookup_msg, (
        f"a Body one byte past the modelled 6291456 ceiling must reach the ENDPOINT LOOKUP "
        f"unchanged, i.e. produce exactly the control's message — the ceiling is declared in "
        f"the Smithy model but is not part of the request-validation layer. Expected "
        f"{lookup_msg!r}, got {over_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
