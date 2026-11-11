"""put-method-response-invalid-status-code-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-method-response-invalid-status-code-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMethodResponse rejects a statusCode that is not a 3-digit HTTP status with
    ValidationException and creates nothing under that key, while statusCode "200" on the same
    method succeeds."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")

    bad_status = "not-a-status"
    code, message = _error(
        lambda: apigw.put_method_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode=bad_status,
        )
    )
    assert code == "ValidationException", f"malformed statusCode was not rejected: {code}"
    assert message == (
        f"1 validation error detected: Value '{bad_status}' at 'statusCode' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: [1-5]\d\d"
    ), f"unexpected message: {message!r}"

    # Effect absent: no MethodResponse was created under the malformed statusCode.
    # (GetMethodResponse itself validates statusCode's format before doing a lookup, so
    # the independent read has to be GetMethod's own methodResponses map instead.)
    method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert bad_status not in method.get("methodResponses", {}), (
        f"a MethodResponse for the rejected statusCode {bad_status!r} unexpectedly exists: "
        f"{method.get('methodResponses')}"
    )

    # Positive control: a well-formed statusCode on the same method still succeeds.
    control = apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert control["statusCode"] == "200"


def _error(fn):
    from botocore.exceptions import ClientError

    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

