"""async-invoke-rejects-neither-and-both-input-sources."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-rejects-neither-and-both-input-sources"
GROUP = 'rejection'
SERVICES = ['sagemaker-runtime']

# One byte past com.amazonaws.sagemakerruntime#AsyncBodyBlob's length {max: 128000}.
_OVER_ASYNC_BODY_CEILING = b'x' * 128001


def _refusal(fn):
    """The ClientError fn() raised. Raises AssertionError if the call SUCCEEDED.

    A success here would mean an inference request was ENQUEUED, which is both the wrong answer and
    a side effect.
    """
    try:
        resp = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(
        f"InvokeEndpointAsync was ACCEPTED and enqueued a request: "
        f"{ {k: v for k, v in resp.items() if k != 'ResponseMetadata'} !r}"
    )


def _code_and_message(exc) -> tuple[str, str]:
    err = exc.response.get("Error", {})
    return err.get("Code", ""), err.get("Message", "")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeEndpointAsync refuses neither Body nor InputLocation and both with two distinct exact
    ValidationError messages, either source alone reaches the endpoint-not-found answer, and a Body
    over 128000 bytes is refused before the lookup; no refusal carries an InferenceId or OutputLocation."""
    smr = ctx.client("sagemaker-runtime")

    absent = ctx.unique_name("sim2real-behav-smr-async-")
    bucket = ctx.unique_name("sim2real-behav-smr-in-")
    location = f"s3://{bucket}/input.json"

    def _async(**kw):
        return lambda: smr.invoke_endpoint_async(
            EndpointName=absent, ContentType="application/json", **kw
        )

    def _no_request_was_enqueued(exc, label):
        payload = {k: v for k, v in exc.response.items()
                   if k not in ("Error", "ResponseMetadata")}
        assert "InferenceId" not in payload and "OutputLocation" not in payload, (
            f"{label}: the refusal must carry no InferenceId and no OutputLocation — those are "
            f"the only evidence a request reached the queue, and a refused request must not "
            f"have reached it; got {payload!r}"
        )

    # --- (1) NEITHER source: refused with a message naming the disjunction. This rule is
    # nowhere in the model.
    neither = _refusal(_async())
    neither_code, neither_msg = _code_and_message(neither)
    assert neither_code == "ValidationError", (
        f"InvokeEndpointAsync with neither Body nor InputLocation must be refused with "
        f"ValidationError; got {neither_code!r}: {neither_msg!r}"
    )
    assert neither_msg == "One of Body or InputLocation is required", (
        f"the missing-source refusal must name the disjunction exactly; got {neither_msg!r}"
    )
    assert "not found" not in neither_msg, (
        f"the missing-source rule must pre-empt the endpoint lookup; got {neither_msg!r}"
    )
    _no_request_was_enqueued(neither, "neither source")

    # --- (2) BOTH sources: refused too, and with a DIFFERENT message. An emulator that treats
    # the rule as "at least one" accepts this.
    both = _refusal(_async(InputLocation=location, Body=b'{"inputs": "sim2real"}'))
    both_code, both_msg = _code_and_message(both)
    assert both_code == "ValidationError", (
        f"InvokeEndpointAsync with BOTH Body and InputLocation must be refused with "
        f"ValidationError; got {both_code!r}: {both_msg!r}"
    )
    assert both_msg == "Both Body and InputLocation were provided. Provide exactly one.", (
        f"the two-source refusal must be its own message, not the missing-source one; got "
        f"{both_msg!r}"
    )
    assert both_msg != neither_msg, (
        f"supplying neither source and supplying both must not collapse to one message: both "
        f"returned {neither_msg!r}"
    )
    _no_request_was_enqueued(both, "both sources")

    # --- (3) The two positive controls: EITHER source alone passes validation and reaches the
    # endpoint lookup. Without these the check would pass against an emulator that refuses
    # every async invocation.
    loc_only = _refusal(_async(InputLocation=location))
    loc_code, loc_msg = _code_and_message(loc_only)
    assert loc_code == "ValidationError", (
        f"InputLocation alone against an absent endpoint must be refused with ValidationError; "
        f"got {loc_code!r}: {loc_msg!r}"
    )
    assert loc_msg.startswith(f"Endpoint {absent} of account ") and loc_msg.endswith(
        " not found."
    ), (
        f"InputLocation alone must be a VALID request that fails only on the endpoint lookup; "
        f"got {loc_msg!r}"
    )

    body_code, body_msg = _code_and_message(_refusal(_async(Body=b'{"inputs": "sim2real"}')))
    assert body_code == "ValidationError", (
        f"Body alone against an absent endpoint must be refused with ValidationError; got "
        f"{body_code!r}: {body_msg!r}"
    )
    assert body_msg == loc_msg, (
        f"Body alone and InputLocation alone are equally valid input sources, so both must "
        f"reach the endpoint lookup and report the same message: expected {loc_msg!r}, got "
        f"{body_msg!r}"
    )

    # --- (4) The async body ceiling IS enforced in the validation layer, unlike the sync one.
    over_code, over_msg = _code_and_message(
        _refusal(_async(Body=_OVER_ASYNC_BODY_CEILING))
    )
    assert over_code == "ValidationError", (
        f"an async Body past AsyncBodyBlob's 128000-byte ceiling must be refused with "
        f"ValidationError; got {over_code!r}: {over_msg!r}"
    )
    assert "Member must have length less than or equal to 128000" in over_msg, (
        f"the async body ceiling must be enforced BEFORE the endpoint lookup and must name the "
        f"modelled 128000 maximum; got {over_msg!r}"
    )
    assert "not found" not in over_msg, (
        f"the async body ceiling must pre-empt the endpoint lookup — this is exactly where the "
        f"async operation differs from the synchronous one, whose 6291456 ceiling does not; got "
        f"{over_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
