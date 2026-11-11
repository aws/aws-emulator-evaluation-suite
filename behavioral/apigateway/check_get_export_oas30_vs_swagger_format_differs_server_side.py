"""get-export-oas30-vs-swagger-format-differs-server-side."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-export-oas30-vs-swagger-format-differs-server-side"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport produces structurally different, format-correct documents for exportType
    'swagger' (OpenAPI 2.0) vs 'oas30' (OpenAPI 3.0) for the very same deployed stage."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-export-api-"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    stage_name = "sim2realexport"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    swagger_doc = json.loads(
        apigw.get_export(
            restApiId=api_id, stageName=stage_name, exportType="swagger", accepts="application/json"
        )["body"].read()
    )
    oas30_doc = json.loads(
        apigw.get_export(
            restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json"
        )["body"].read()
    )

    assert swagger_doc.get("swagger") == "2.0", f"unexpected swagger export top-level: {swagger_doc}"
    assert "openapi" not in swagger_doc, "swagger export should not carry an 'openapi' version key"

    assert str(oas30_doc.get("openapi", "")).startswith("3.0"), (
        f"unexpected oas30 export top-level: {oas30_doc}"
    )
    assert "swagger" not in oas30_doc, "oas30 export should not carry a 'swagger' version key"

    # Both documents describe the SAME deployed stage, so the format markers above must not be the
    # only difference the check would catch: each must also carry the real deployed method, not a
    # static/empty stub of its own version.
    assert "get" in swagger_doc.get("paths", {}).get("/", {}), (
        f"swagger export missing the deployed GET method on '/': {swagger_doc.get('paths')}"
    )
    assert "get" in oas30_doc.get("paths", {}).get("/", {}), (
        f"oas30 export missing the deployed GET method on '/': {oas30_doc.get('paths')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
