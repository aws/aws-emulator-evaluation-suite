"""put-gateway-response-malformed-statuscode-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-gateway-response-malformed-statuscode-rejected"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutGatewayResponse rejects a statusCode that is not a 3-digit HTTP status with
    ValidationException and keeps the default response; a valid statusCode is persisted."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    response_type = "RESOURCE_NOT_FOUND"

    code, message = _error(
        lambda: ag.put_gateway_response(
            restApiId=api_id, responseType=response_type, statusCode="not-a-status-code"
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed statusCode, got {code}"
    )
    assert message == (
        "1 validation error detected: Value 'not-a-status-code' at 'putGatewayResponseInput.statusCode' "
        r"failed to satisfy constraint: Member must satisfy regular expression pattern: [1-5]\d\d"
    ), f"unexpected {code} message: {message!r}"

    got = ag.get_gateway_response(restApiId=api_id, responseType=response_type)
    assert got.get("defaultResponse") is True, (
        "a rejected PutGatewayResponse must not create a partial override"
    )

    # Positive control: the same call with a valid statusCode succeeds.
    fixed = ag.put_gateway_response(restApiId=api_id, responseType=response_type, statusCode="419")
    assert fixed.get("statusCode") == "419", (
        f"expected the valid statusCode to be persisted, got {fixed.get('statusCode')!r}"
    )
    assert fixed.get("defaultResponse") is False, (
        "a successful PutGatewayResponse must no longer read as the untouched default"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
