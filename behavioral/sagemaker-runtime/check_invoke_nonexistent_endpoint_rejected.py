"""invoke-nonexistent-endpoint-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invoke-nonexistent-endpoint-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeEndpoint on two never-created endpoint names fails with ValidationError/400 and an exact
    message naming each searched endpoint, so one canned refusal for every request does not pass."""
    smr = ctx.client("sagemaker-runtime")

    first = ctx.unique_name("sim2real-smrt-never-created-a-")
    second = ctx.unique_name("sim2real-smrt-never-created-b-")

    for name in (first, second):
        code, status, msg = _error_response(lambda: smr.invoke_endpoint(EndpointName=name, Body=b"x"))
        assert (code, status) == ("ValidationError", 400), (
            f"expected ValidationError/400 for a never-created endpoint, got {code}/{status}: {msg!r}"
        )
        expected_message = f"Endpoint {name} of account {ctx.account} not found."
        assert msg == expected_message, f"expected the message {expected_message!r}, got {msg!r}"


def _error_response(fn):
    """The (code, HTTP status, message) of the ClientError fn() raised. Raises AssertionError if the
    call SUCCEEDED -- never returns a falsy sentinel."""
    from botocore.exceptions import ClientError
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err["Code"], status, err.get("Message", "")
    raise AssertionError(
        f"the call was ACCEPTED and returned {resp!r} -- sagemaker-runtime must refuse an "
        f"InvokeEndpoint against an endpoint that was never created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

