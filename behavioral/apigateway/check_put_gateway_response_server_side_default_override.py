"""put-gateway-response-server-side-default-override."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-gateway-response-server-side-default-override"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGatewayResponse for DEFAULT_4XX merges into the existing entry instead of appending a duplicate."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-gwresponse-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    before = apigw.get_gateway_responses(restApiId=api_id)["items"]
    count_before = len(before)
    default_4xx_before = next(i for i in before if i["responseType"] == "DEFAULT_4XX")
    assert default_4xx_before["defaultResponse"] is True, "uncustomized DEFAULT_4XX should report defaultResponse=True"

    apigw.put_gateway_response(
        restApiId=api_id,
        responseType="DEFAULT_4XX",
        statusCode="404",
        responseParameters={"gatewayresponse.header.Access-Control-Allow-Origin": "'*'"},
        responseTemplates={"application/json": '{"message":$context.error.messageString,"custom":true}'},
    )

    after = apigw.get_gateway_responses(restApiId=api_id)["items"]
    assert len(after) == count_before, (
        f"PutGatewayResponse must merge in place, not append: {count_before} items before, {len(after)} after"
    )

    default_4xx_entries = [i for i in after if i["responseType"] == "DEFAULT_4XX"]
    assert len(default_4xx_entries) == 1, f"expected exactly one DEFAULT_4XX entry, got {default_4xx_entries}"
    updated = default_4xx_entries[0]
    assert updated["defaultResponse"] is False, "customized DEFAULT_4XX must report defaultResponse=False"
    assert updated["statusCode"] == "404", f"expected statusCode '404', got {updated.get('statusCode')!r}"
    assert updated["responseParameters"]["gatewayresponse.header.Access-Control-Allow-Origin"] == "'*'", (
        f"expected the CORS header override to round-trip, got {updated.get('responseParameters')!r}"
    )
    assert updated["responseTemplates"]["application/json"] == (
        '{"message":$context.error.messageString,"custom":true}'
    ), f"expected the response template to round-trip, got {updated.get('responseTemplates')!r}"

    other_types_before = {i["responseType"]: i for i in before if i["responseType"] != "DEFAULT_4XX"}
    other_types_after = {i["responseType"]: i for i in after if i["responseType"] != "DEFAULT_4XX"}
    assert other_types_before.keys() == other_types_after.keys(), "no unrelated gateway response types should appear/disappear"
    for rtype, item in other_types_after.items():
        assert item["defaultResponse"] is True, f"untouched response type {rtype} must remain defaultResponse=True"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
