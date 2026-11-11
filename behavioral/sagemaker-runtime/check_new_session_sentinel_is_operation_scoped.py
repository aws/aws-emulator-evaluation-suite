"""new-session-sentinel-is-operation-scoped."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "new-session-sentinel-is-operation-scoped"
GROUP = 'rejection'
SERVICES = ['sagemaker-runtime']

_BODY = b'{"inputs": "sim2real"}'
_SENTINEL = "NEW_SESSION"


# ===== helpers =====


def _refusal(fn):
    """The ClientError fn() raised. Raises AssertionError if the call SUCCEEDED."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(
        f"the call was ACCEPTED and returned "
        f"{resp.get('ResponseMetadata', {}).get('HTTPStatusCode')!r} — sagemaker-runtime must "
        f"refuse an invocation of an endpoint that does not exist"
    )


def _code_and_message(exc) -> tuple[str, str]:
    err = exc.response.get("Error", {})
    return err.get("Code", ""), err.get("Message", "")
# ===== end helpers =====


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The session sentinel NEW_SESSION is legal on InvokeEndpoint and ILLEGAL on
    InvokeEndpointWithResponseStream, while a well-formed session id is accepted on both: the two
    operations' SessionId members carry different patterns, so the difference is the operation's.
    """
    smr = ctx.client("sagemaker-runtime")

    absent = ctx.unique_name("sim2real-behav-smr-sess-")
    # SessionIdHeader's pattern forbids the separator, so the well-formed control id cannot
    # carry the hyphenated name prefix. Nothing is created, so nothing needs cleanup.
    ordinary = "sim2realbehavsess" + absent[-8:]
    assert "_" not in ordinary and len(ordinary) <= 256, (
        f"the control session id must itself satisfy SessionIdHeader; got {ordinary!r}"
    )

    # --- (1) InvokeEndpoint ACCEPTS the sentinel: the request passes validation and is refused
    # by the endpoint lookup instead. This is the positive control for the sentinel's legality.
    sync_code, sync_msg = _code_and_message(_refusal(
        lambda: smr.invoke_endpoint(
            EndpointName=absent, Body=_BODY, ContentType="application/json",
            SessionId=_SENTINEL,
        )
    ))
    assert sync_code == "ValidationError", (
        f"InvokeEndpoint with SessionId={_SENTINEL!r} against an absent endpoint must be "
        f"refused with ValidationError; got {sync_code!r}: {sync_msg!r}"
    )
    assert sync_msg.startswith(f"Endpoint {absent} of account ") and sync_msg.endswith(
        " not found."
    ), (
        f"InvokeEndpoint must ACCEPT {_SENTINEL!r} as a session id and fail on the endpoint "
        f"lookup instead — the sentinel is how a stateful session is opened on this operation. "
        f"Got {sync_msg!r}"
    )
    assert "sessionId" not in sync_msg, (
        f"InvokeEndpoint must not report sessionId at all for {_SENTINEL!r}; got {sync_msg!r}"
    )

    # --- (2) InvokeEndpointWithResponseStream REFUSES the same value, naming the field. This
    # operation cannot open a stateful session, so the sentinel is a plain pattern violation.
    stream_code, stream_msg = _code_and_message(_refusal(
        lambda: smr.invoke_endpoint_with_response_stream(
            EndpointName=absent, Body=_BODY, ContentType="application/json",
            SessionId=_SENTINEL,
        )
    ))
    assert stream_code == "ValidationError", (
        f"InvokeEndpointWithResponseStream with SessionId={_SENTINEL!r} must be refused with "
        f"ValidationError; got {stream_code!r}: {stream_msg!r}"
    )
    assert f"Value '{_SENTINEL}' at 'sessionId'" in stream_msg, (
        f"the streaming operation must refuse {_SENTINEL!r} and attribute the violation to "
        f"sessionId — it cannot create a stateful session; got {stream_msg!r}"
    )
    assert "not found" not in stream_msg, (
        f"the sentinel must be refused BEFORE the endpoint lookup on the streaming operation, "
        f"so the same absent endpoint is never reported here; got {stream_msg!r}"
    )
    assert stream_msg != sync_msg, (
        f"the two operations must not collapse to the same answer for the same session header: "
        f"both returned {sync_msg!r}"
    )

    # --- (3) The streaming operation DOES accept an ordinary session id: the refusal above is
    # about the sentinel, not about stateful sessions. This is the second positive control, and
    # it is what stops the check passing against an emulator that rejects every session id.
    ord_code, ord_msg = _code_and_message(_refusal(
        lambda: smr.invoke_endpoint_with_response_stream(
            EndpointName=absent, Body=_BODY, ContentType="application/json",
            SessionId=ordinary,
        )
    ))
    assert ord_code == "ValidationError", (
        f"InvokeEndpointWithResponseStream with a well-formed session id against an absent "
        f"endpoint must be refused with ValidationError; got {ord_code!r}: {ord_msg!r}"
    )
    assert ord_msg == sync_msg, (
        f"a well-formed session id must pass the streaming operation's validation and reach the "
        f"endpoint lookup, producing the same message the sync operation gave: expected "
        f"{sync_msg!r}, got {ord_msg!r} — the streaming operation refuses only the "
        f"{_SENTINEL!r} sentinel, not session ids as such"
    )

    # --- (4) And the sentinel is not merely 'any uppercase value': a name that differs from it
    # by one character is refused by BOTH operations' patterns, so the acceptance in (1) is the
    # modelled special case rather than a lax validator.
    near_code, near_msg = _code_and_message(_refusal(
        lambda: smr.invoke_endpoint(
            EndpointName=absent, Body=_BODY, ContentType="application/json",
            SessionId="NEW_SESSIONS",
        )
    ))
    assert near_code == "ValidationError", (
        f"'NEW_SESSIONS' must be refused with ValidationError; got {near_code!r}: {near_msg!r}"
    )
    assert "Value 'NEW_SESSIONS' at 'sessionId'" in near_msg, (
        f"InvokeEndpoint's SessionId pattern anchors the sentinel exactly ('^(NEW_SESSION)$'), "
        f"so 'NEW_SESSIONS' must be a sessionId violation rather than another accepted "
        f"sentinel; got {near_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
