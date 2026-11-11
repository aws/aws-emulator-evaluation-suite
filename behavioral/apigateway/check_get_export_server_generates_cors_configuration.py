"""get-export-server-generates-cors-configuration."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-export-server-generates-cors-configuration"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport's OpenAPI output embeds the live gateway-response CORS config only when requested."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseModels={"application/json": "Empty"},
    )
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    cors_origin = "'https://example.com'"
    apigw.put_gateway_response(
        restApiId=api_id, responseType="DEFAULT_4XX", statusCode="400",
        responseParameters={"gatewayresponse.header.Access-Control-Allow-Origin": cors_origin},
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "test"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)

    exported = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="oas30",
        parameters={"extensions": "apigateway"}, accepts="application/json",
    )
    doc = json.loads(exported["body"].read())

    responses = doc.get("x-amazon-apigateway-gateway-responses", {})
    assert "DEFAULT_4XX" in responses, f"expected DEFAULT_4XX gateway response in export, got keys={list(responses)}"
    params = responses["DEFAULT_4XX"].get("responseParameters", {})
    assert params.get("gatewayresponse.header.Access-Control-Allow-Origin") == cors_origin, (
        f"exported CORS header value did not match live gateway-response config: {params}"
    )

    # Without the "apigateway" extensions parameter, the block must not leak
    # by default -- proving export content is derived from BOTH live state
    # AND the requested export parameters, not always emitted.
    exported_plain = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json",
    )
    doc_plain = json.loads(exported_plain["body"].read())
    assert "x-amazon-apigateway-gateway-responses" not in doc_plain, (
        "gateway responses extension leaked into export without extensions=apigateway"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
