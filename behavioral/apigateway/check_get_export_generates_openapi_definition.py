"""get-export-generates-openapi-definition."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-export-generates-openapi-definition"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport server-side-renders the deployed stage as a valid OpenAPI 3.0 document reflecting its resources."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-getexport-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    items_resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    apigw.put_method(restApiId=api_id, resourceId=items_resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=items_resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=items_resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=items_resource_id, httpMethod="GET", statusCode="200"
    )

    stage_name = "prod"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    # 'accepts' selects the exported representation's media *format* (JSON vs YAML) that gets
    # rendered into the body, but GetExport always serves the export as a downloadable binary blob:
    # the response's contentType header is "application/octet-stream" regardless of 'accepts', even
    # though the body itself is still JSON-formatted OAS30 when accepts="application/json".
    resp = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json"
    )
    assert resp["contentType"] == "application/octet-stream", resp["contentType"]
    body = _read_body(resp["body"])
    doc = json.loads(body)

    assert doc["openapi"].startswith("3.0"), f"expected OpenAPI 3.0.x document, got {doc.get('openapi')}"
    assert "/items" in doc["paths"], f"expected '/items' path in exported document, got {list(doc['paths'])}"
    assert "get" in doc["paths"]["/items"], "expected the GET method to be present on the exported /items path"
    responses = doc["paths"]["/items"]["get"]["responses"]
    assert responses["200"] is not None, f"expected a 200 response entry for GET /items, got {responses}"

    # a resource this check never created must NOT show up in the render, proving the
    # document is derived from live resources rather than a generic/cached stub
    assert "/does-not-exist" not in doc["paths"], (
        f"exported document contains a path this check never created: {list(doc['paths'])}"
    )


def _read_body(raw):
    return raw.read() if hasattr(raw, "read") else raw


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
