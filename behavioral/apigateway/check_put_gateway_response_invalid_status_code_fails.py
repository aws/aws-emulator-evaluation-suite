"""put-gateway-response-invalid-status-code-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-gateway-response-invalid-status-code-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutGatewayResponse with a statusCode that isn't a valid numeric HTTP status
    code must fail with ValidationException, not silently persist an
    invalid gateway response customization."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    baseline = apigw.get_gateway_response(restApiId=api_id, responseType="ACCESS_DENIED")
    assert baseline["defaultResponse"] is True, f"expected an untouched default response, got {baseline}"

    # Positive control: a syntactically valid statusCode for the same response type is accepted
    # and persists -- proving the account isn't simply refusing every PutGatewayResponse, which
    # would otherwise make the negative below indistinguishable from a blanket rejection.
    control = apigw.put_gateway_response(restApiId=api_id, responseType="ACCESS_DENIED", statusCode="404")
    assert control["statusCode"] == "404", f"expected the valid control statusCode to persist, got {control}"
    assert control["defaultResponse"] is False, f"expected a customization to clear defaultResponse, got {control}"

    # On real AWS, a non-numeric statusCode is rejected with ValidationException (not
    # BadRequestException) -- the request never reaches the service's business-logic layer,
    # it fails input-shape validation first.
    code, message = _error(
        lambda: apigw.put_gateway_response(
            restApiId=api_id, responseType="ACCESS_DENIED", statusCode="not-a-status-code"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'not-a-status-code' at 'putGatewayResponseInput.statusCode' "
        r"failed to satisfy constraint: Member must satisfy regular expression pattern: [1-5]\d\d"
    ), f"unexpected {code} message: {message!r}"

    # the rejected call must not have touched the existing (control) customization
    after = apigw.get_gateway_response(restApiId=api_id, responseType="ACCESS_DENIED")
    assert after["statusCode"] == "404", f"a rejected PutGatewayResponse must not alter an existing customization, got {after}"
    assert after["defaultResponse"] is False, "a rejected PutGatewayResponse must not revert an existing customization to default"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
