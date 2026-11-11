"""get-gateway-responses-lists-defaults-and-custom."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-gateway-responses-lists-defaults-and-custom"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGatewayResponse overrides one response type; GetGatewayResponses lists it
    alongside the still-default responses for all other types."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-gwresp-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # Before any customization, all gateway responses are default.
    before = apigw.get_gateway_responses(restApiId=api_id)["items"]
    assert len(before) > 0, "expected default gateway responses to be enumerated"
    assert all(item["defaultResponse"] is True for item in before), (
        f"expected every response to be defaultResponse=True before customization: {before}"
    )
    before_types = {item["responseType"] for item in before}
    assert "DEFAULT_4XX" in before_types, f"DEFAULT_4XX missing from default response types: {before_types}"

    apigw.put_gateway_response(
        restApiId=api_id,
        responseType="DEFAULT_4XX",
        statusCode="404",
        responseTemplates={"application/json": '{"message":"custom-4xx"}'},
    )

    after = apigw.get_gateway_responses(restApiId=api_id)["items"]
    by_type = {item["responseType"]: item for item in after}
    assert "DEFAULT_4XX" in by_type, f"DEFAULT_4XX missing from post-put response types: {sorted(by_type)}"
    custom = by_type["DEFAULT_4XX"]
    assert custom["defaultResponse"] is False, "customized response must not report defaultResponse=True"
    assert custom["statusCode"] == "404", f"expected statusCode '404', got {custom['statusCode']!r}"
    assert custom["responseTemplates"]["application/json"] == '{"message":"custom-4xx"}', (
        f"expected the put responseTemplates to be echoed back, got {custom['responseTemplates']!r}"
    )

    # Every other response type must remain untouched/default.
    other_types = before_types - {"DEFAULT_4XX"}
    for rtype in other_types:
        assert by_type[rtype]["defaultResponse"] is True, f"{rtype} should still be default"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
