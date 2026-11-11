"""import-rest-api-from-openapi."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "import-rest-api-from-openapi"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportRestApi from an OpenAPI/Swagger document synchronously creates a fully-formed
    RestApi whose GetRestApi (and resource tree) reflects the imported metadata."""
    apigw = ctx.client("apigateway")
    api_title = ctx.unique_name("sim2real-import-")
    doc = {
        "swagger": "2.0",
        "info": {"title": api_title, "version": "2.1"},
        "paths": {
            "/hello": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }

    created = apigw.import_rest_api(body=json.dumps(doc).encode())
    api_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    apigw.tag_resource(
        resourceArn=f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}",
        tags={"sim2real-check": CHECK},
    )

    assert created["name"] == api_title, f"expected ImportRestApi to echo name {api_title!r}, got {created['name']!r}"
    assert created["version"] == "2.1", f"expected ImportRestApi to echo version '2.1', got {created['version']!r}"

    fetched = apigw.get_rest_api(restApiId=api_id)
    assert fetched["name"] == api_title, f"GetRestApi name diverged from the import: {fetched['name']!r}"
    assert fetched["version"] == "2.1", f"GetRestApi version diverged from the import: {fetched['version']!r}"
    assert fetched["id"] == api_id, f"GetRestApi returned a different id: {fetched['id']!r}"

    resources = apigw.get_resources(restApiId=api_id)["items"]
    paths = {r["path"] for r in resources}
    assert paths == {"/", "/hello"}, f"expected imported /hello path, got {paths}"
    hello = next(r for r in resources if r["path"] == "/hello")
    assert "GET" in hello["resourceMethods"], "imported GET method must be present"

    method = apigw.get_method(restApiId=api_id, resourceId=hello["id"], httpMethod="GET")
    assert method["httpMethod"] == "GET", f"GetMethod returned {method['httpMethod']!r} for the imported GET"

    integration = apigw.get_integration(restApiId=api_id, resourceId=hello["id"], httpMethod="GET")
    assert integration["type"] == "MOCK", (
        f"expected the imported MOCK integration to survive server-side parsing, got {integration.get('type')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
