"""import-rest-api-parses-openapi-server-side."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "import-rest-api-parses-openapi-server-side"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportRestApi parses a Swagger 2.0 document into a matching resource tree (GetResources,
    GetMethod, GetIntegration), including the run-unique request and integration-response
    templates the integration extension carries, so a canned tree cannot pass."""
    apigw = ctx.client("apigateway")

    api_name = ctx.unique_name("sim2real-import-api-")
    request_template = json.dumps({"statusCode": 200, "marker": api_name})
    response_template = json.dumps({"marker": api_name})
    spec = {
        "swagger": "2.0",
        "info": {"title": api_name, "version": "1.0"},
        "basePath": "/",
        "schemes": ["https"],
        "paths": {
            "/items": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "mock",
                        "requestTemplates": {"application/json": request_template},
                        "responses": {
                            "default": {
                                "statusCode": "200",
                                "responseTemplates": {"application/json": response_template},
                            }
                        },
                    },
                }
            }
        },
    }
    body = json.dumps(spec).encode("utf-8")

    resp = apigw.import_rest_api(body=body)
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    api_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"
    apigw.tag_resource(resourceArn=api_arn, tags={"sim2real-check": CHECK})

    assert resp["name"] == api_name, resp["name"]

    resources = apigw.get_resources(restApiId=api_id)["items"]
    item = next((r for r in resources if r.get("path") == "/items"), None)
    assert item is not None, f"expected a /items resource, got paths={[r.get('path') for r in resources]}"
    assert "GET" in item.get("resourceMethods", {}), item

    method = apigw.get_method(restApiId=api_id, resourceId=item["id"], httpMethod="GET")
    assert method["httpMethod"] == "GET"
    method_response = method.get("methodResponses", {}).get("200")
    assert method_response is not None, (
        f"expected the spec's responses.200 to materialize a 200 MethodResponse, got {method.get('methodResponses')}"
    )

    integration = apigw.get_integration(restApiId=api_id, resourceId=item["id"], httpMethod="GET")
    assert integration["type"] == "MOCK", integration
    assert integration["requestTemplates"]["application/json"] == request_template, (
        "expected the imported requestTemplate to carry this run's unique marker verbatim, "
        f"got {integration.get('requestTemplates')}"
    )
    integration_responses = integration.get("integrationResponses", {})
    assert integration_responses, f"expected the spec's integration responses to survive import, got {integration!r}"
    default_resp = integration_responses.get("200")
    assert default_resp is not None, (
        f"expected the 'default' selection pattern to key the integration response by its statusCode 200, "
        f"got keys={list(integration_responses)!r}"
    )
    assert default_resp["responseTemplates"]["application/json"] == response_template, (
        "expected the imported responseTemplate to carry this run's unique marker verbatim, "
        f"got {default_resp.get('responseTemplates')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
