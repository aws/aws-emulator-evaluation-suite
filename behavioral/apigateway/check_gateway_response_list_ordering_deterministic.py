"""gateway-response-list-ordering-deterministic."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "gateway-response-list-ordering-deterministic"
GROUP = "ordering"
SERVICES = ["apigateway"]

# com.amazonaws.apigateway#GatewayResponseType — a fixed enum in the Smithy model, identical
# across every account (not a per-account quota), so pinning the full set is part of the contract.
GATEWAY_RESPONSE_TYPES = {
    "DEFAULT_4XX", "DEFAULT_5XX", "RESOURCE_NOT_FOUND", "UNAUTHORIZED", "INVALID_API_KEY",
    "ACCESS_DENIED", "AUTHORIZER_FAILURE", "AUTHORIZER_CONFIGURATION_ERROR", "INVALID_SIGNATURE",
    "EXPIRED_TOKEN", "MISSING_AUTHENTICATION_TOKEN", "INTEGRATION_FAILURE", "INTEGRATION_TIMEOUT",
    "API_CONFIGURATION_ERROR", "UNSUPPORTED_MEDIA_TYPE", "BAD_REQUEST_PARAMETERS",
    "BAD_REQUEST_BODY", "REQUEST_TOO_LARGE", "THROTTLED", "QUOTA_EXCEEDED", "WAF_FILTERED",
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGatewayResponses returns the full set of default + customized gateway responses in a
    deterministic order that is reproduced identically across repeated calls after mixed puts."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-gwresp-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # Put custom overrides in a deliberately non-alphabetical order to make sure any observed
    # ordering is not simply "insertion order" or "alphabetical" by coincidence.
    apigw.put_gateway_response(
        restApiId=api_id, responseType="UNAUTHORIZED", statusCode="401",
        responseTemplates={"application/json": '{"message": "unauthorized"}'},
    )
    apigw.put_gateway_response(
        restApiId=api_id, responseType="DEFAULT_5XX", statusCode="500",
        responseTemplates={"application/json": '{"message": "server-error"}'},
    )
    apigw.put_gateway_response(
        restApiId=api_id, responseType="ACCESS_DENIED", statusCode="403",
        responseTemplates={"application/json": '{"message": "denied"}'},
    )
    apigw.put_gateway_response(
        restApiId=api_id, responseType="DEFAULT_4XX", statusCode="400",
        responseTemplates={"application/json": '{"message": "bad-request"}'},
    )

    order_one = [item["responseType"] for item in apigw.get_gateway_responses(restApiId=api_id)["items"]]
    order_two = [item["responseType"] for item in apigw.get_gateway_responses(restApiId=api_id)["items"]]
    order_three = [
        item["responseType"] for item in apigw.get_gateway_responses(restApiId=api_id)["items"]
    ]

    assert order_one == order_two == order_three, (
        f"GetGatewayResponses order is not deterministic across repeated calls: "
        f"{order_one} vs {order_two} vs {order_three}"
    )
    assert set(order_one) == GATEWAY_RESPONSE_TYPES, (
        f"GetGatewayResponses did not return the full modelled set of gateway response types: "
        f"missing={GATEWAY_RESPONSE_TYPES - set(order_one)} "
        f"extra={set(order_one) - GATEWAY_RESPONSE_TYPES}"
    )
    assert len(order_one) == len(GATEWAY_RESPONSE_TYPES), (
        f"GetGatewayResponses returned {len(order_one)} items, "
        f"expected exactly {len(GATEWAY_RESPONSE_TYPES)} (no duplicates)"
    )
    for expected_type in ("UNAUTHORIZED", "DEFAULT_5XX", "ACCESS_DENIED", "DEFAULT_4XX"):
        assert expected_type in order_one, f"{expected_type} missing from gateway response list"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
