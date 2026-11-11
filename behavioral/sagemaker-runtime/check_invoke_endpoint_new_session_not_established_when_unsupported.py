"""invoke-endpoint-new-session-not-established-when-unsupported."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invoke-endpoint-new-session-not-established-when-unsupported"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeEndpointWithResponseStream refuses SessionId=NEW_SESSION with ValidationError and the exact
    sessionId message before the endpoint lookup, while the same call without SessionId gets the
    exact endpoint-not-found message."""
    from botocore.exceptions import ClientError

    smr = ctx.client("sagemaker-runtime")
    bogus_endpoint = ctx.unique_name("sim2real-smrt-stream-never-created-")

    def _stream_error(**kwargs):
        """The rejection's (code, message). Raises if the call and its stream SUCCEEDED."""
        try:
            resp = smr.invoke_endpoint_with_response_stream(
                EndpointName=bogus_endpoint, Body=b"x", **kwargs
            )
            # Errors can also surface once the event stream is iterated.
            for _ in resp["Body"]:
                pass
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message", "")
        raise AssertionError(f"expected a ValidationError but the streaming call SUCCEEDED ({kwargs!r})")

    # Baseline: no SessionId at all against a nonexistent endpoint -> ValidationError
    # (endpoint-existence boundary).
    baseline_code, baseline_msg = _stream_error()
    assert baseline_code == "ValidationError", f"expected ValidationError, got {baseline_code}: {baseline_msg}"
    expected_baseline = f"Endpoint {bogus_endpoint} of account {ctx.account} not found."
    assert baseline_msg == expected_baseline, (
        f"the no-SessionId baseline must be refused on the endpoint lookup, naming the endpoint; "
        f"expected {expected_baseline!r}, got {baseline_msg!r}"
    )

    # SessionId=NEW_SESSION on the streaming operation is refused by the constraint layer before
    # the endpoint lookup, so the ValidationError message names the sessionId field, not the endpoint.
    session_code, session_msg = _stream_error(SessionId="NEW_SESSION")
    assert session_code == "ValidationError", (
        f"expected ValidationError for SessionId=NEW_SESSION on the streaming op, got {session_code}: {session_msg}"
    )
    expected_session = (
        "1 validation error detected: Value 'NEW_SESSION' at 'sessionId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9](-*[a-zA-Z0-9])*$"
    )
    assert session_msg == expected_session, (
        "the streaming op must refuse SessionId=NEW_SESSION on the sessionId field itself, BEFORE "
        f"the endpoint lookup; expected {expected_session!r}, got {session_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

