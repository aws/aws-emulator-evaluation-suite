"""put-gateway-response-invalid-status-code-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-gateway-response-invalid-status-code-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGatewayResponse rejects a statusCode outside the 3-digit pattern with ValidationException
    and leaves the response type at its default; a valid statusCode for the same type then
    persists, as an independent read shows."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _ignore_errors(lambda: apigw.delete_rest_api(restApiId=api_id)))

    baseline = apigw.get_gateway_response(restApiId=api_id, responseType="UNAUTHORIZED")
    assert baseline["defaultResponse"] is True, f"expected an untouched default, got {baseline!r}"

    err, err_message = _error(
        lambda: apigw.put_gateway_response(restApiId=api_id, responseType="UNAUTHORIZED", statusCode="abc")
    )
    # A non-numeric statusCode fails API Gateway's request-shape validation and never reaches
    # its business-logic layer.
    assert err == "ValidationException", f"expected ValidationException, got {err!r}"
    assert err_message == (
        "1 validation error detected: Value 'abc' at 'putGatewayResponseInput.statusCode' "
        r"failed to satisfy constraint: Member must satisfy regular expression pattern: [1-5]\d\d"
    ), f"unexpected {err} message: {err_message!r}"

    # The forbidden mutation did not happen: the response type is still the untouched default.
    unchanged = apigw.get_gateway_response(restApiId=api_id, responseType="UNAUTHORIZED")
    assert unchanged["defaultResponse"] is True, f"expected the default to survive, got {unchanged!r}"
    assert unchanged["statusCode"] == baseline["statusCode"], (
        f"expected statusCode to stay {baseline['statusCode']!r}, got {unchanged['statusCode']!r}"
    )

    # Positive control: a valid statusCode for the same response type succeeds, read back
    # independently, not only from the mutating call's own echo.
    put_result = apigw.put_gateway_response(restApiId=api_id, responseType="UNAUTHORIZED", statusCode="419")
    assert put_result["statusCode"] == "419", f"expected the put response to echo 419, got {put_result!r}"
    fixed = apigw.get_gateway_response(restApiId=api_id, responseType="UNAUTHORIZED")
    assert fixed["statusCode"] == "419", f"expected the persisted statusCode to be 419, got {fixed!r}"
    assert fixed["defaultResponse"] is False, f"expected defaultResponse False once customized, got {fixed!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_errors(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
