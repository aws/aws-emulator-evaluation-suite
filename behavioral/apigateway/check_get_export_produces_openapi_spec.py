"""get-export-produces-openapi-spec."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-export-produces-openapi-spec"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport for a deployed stage server-side-renders a valid OpenAPI 3.0 document that
    reflects the current resource tree, not a generic stub."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-export-api-"),
        tags={"sim2real-check": "get-export-produces-openapi-spec"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="gadgets")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": "{}"},
    )

    stage_name = "exporttest"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    export = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json"
    )
    # GetExport always serves the document as a file download: the transport
    # contentType is "application/octet-stream" regardless of 'accepts', which only
    # selects the body's own serialization (json vs yaml).
    assert export["contentType"] == "application/octet-stream", (
        f"expected the export to be served as application/octet-stream, got {export['contentType']}"
    )
    spec = json.loads(export["body"].read())

    assert spec.get("openapi", "").startswith("3."), f"expected an OpenAPI 3.x document, got {spec.get('openapi')}"
    assert "/gadgets" in spec.get("paths", {}), f"expected /gadgets in exported paths, got {list(spec.get('paths', {}))}"
    assert "get" in spec["paths"]["/gadgets"], "exported GET method missing under /gadgets"
    # the export must describe the API actually configured, not a generic stub
    responses = spec["paths"]["/gadgets"]["get"].get("responses", {})
    assert "200" in responses, f"expected a 200 response entry for GET /gadgets, got {responses}"
    assert "/not-a-configured-resource" not in spec.get("paths", {}), (
        f"exported doc must not describe a resource this check never created, got {list(spec.get('paths', {}))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
