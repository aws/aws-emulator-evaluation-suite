"""delete-nonexistent-gateway-response-returns-notfound."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-nonexistent-gateway-response-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGatewayResponse on an uncustomized response type returns NotFoundException; once
    DEFAULT_4XX is customized the delete succeeds and resets it, and a re-delete 404s again."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-gwresp-api-"), tags={"sim2real": CHECK}
    )
    rest_api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    code1, message1 = _client_error(
        lambda: apigw.delete_gateway_response(restApiId=rest_api_id, responseType="DEFAULT_4XX")
    )
    assert code1 == "NotFoundException", f"expected NotFoundException, got {code1}"
    assert message1 == "Gateway response type not defined on api", message1

    # positive control: customize it, then the delete succeeds
    put = apigw.put_gateway_response(
        restApiId=rest_api_id,
        responseType="DEFAULT_4XX",
        statusCode="404",
        responseTemplates={"application/json": '{"message":$context.error.messageString}'},
    )
    assert put["defaultResponse"] is False, f"expected customized response, got {put!r}"

    apigw.delete_gateway_response(restApiId=rest_api_id, responseType="DEFAULT_4XX")

    # confirms it reverted to the (uncustomized) default response
    reverted = apigw.get_gateway_response(restApiId=rest_api_id, responseType="DEFAULT_4XX")
    assert reverted["defaultResponse"] is True, f"expected reset to default, got {reverted!r}"

    # negative again: deleting the now-uncustomized type is NotFoundException
    code2, message2 = _client_error(
        lambda: apigw.delete_gateway_response(restApiId=rest_api_id, responseType="DEFAULT_4XX")
    )
    assert code2 == "NotFoundException", f"expected NotFoundException, got {code2}"
    assert message2 == "Gateway response type not defined on api", message2


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
