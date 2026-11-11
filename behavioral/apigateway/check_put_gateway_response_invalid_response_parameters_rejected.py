"""put-gateway-response-invalid-response-parameters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-gateway-response-invalid-response-parameters-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGatewayResponse with a responseParameters key not matching gatewayresponse.header.* is rejected."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-apigw-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    code, message = _error(
        lambda: apigw.put_gateway_response(
            restApiId=api_id,
            responseType="DEFAULT_4XX",
            responseParameters={"invalid.param.name": "'foo'"},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        'Invalid mapping expression specified: Validation Result: warnings : [], errors : [Invalid mapping expression specified: invalid.param.name]'
    ), f"unexpected {code} message: {message!r}"

    # (b) effect absent: the DEFAULT_4XX response is still the unmodified default (no override applied).
    response = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert response["defaultResponse"] is True, "a customized gateway response override was applied"

    # (c) positive control: a correctly-prefixed gatewayresponse.header.* key is accepted.
    updated = apigw.put_gateway_response(
        restApiId=api_id,
        responseType="DEFAULT_4XX",
        responseParameters={"gatewayresponse.header.Foo": "'bar'"},
    )
    assert updated["responseParameters"] == {"gatewayresponse.header.Foo": "'bar'"}, (
        f"expected responseParameters={{'gatewayresponse.header.Foo': \"'bar'\"}} in the "
        f"PutGatewayResponse response, got {updated['responseParameters']!r}"
    )
    assert updated["defaultResponse"] is False, (
        f"expected defaultResponse=False after a valid override, got {updated['defaultResponse']!r}"
    )

    # terminal read: an independent GetGatewayResponse call, not the mutating call's own
    # response, confirms the override actually landed server-side.
    confirmed = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert confirmed["responseParameters"] == {"gatewayresponse.header.Foo": "'bar'"}, (
        f"expected an independent read to see the accepted override, got {confirmed['responseParameters']!r}"
    )
    assert confirmed["defaultResponse"] is False, (
        f"expected an independent read to show defaultResponse=False, got {confirmed['defaultResponse']!r}"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
