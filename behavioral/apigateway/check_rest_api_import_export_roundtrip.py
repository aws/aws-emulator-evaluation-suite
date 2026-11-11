"""rest-api-import-export-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "rest-api-import-export-roundtrip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportRestApi builds resources/methods from an OpenAPI doc, PutRestApi(overwrite)
    updates them, and GetExport reproduces the resulting spec."""
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-importexport-")

    initial_doc = _swagger_doc(api_name, paths=["/pets"])
    imported = apigw.import_rest_api(body=json.dumps(initial_doc).encode("utf-8"), failOnWarnings=False)
    api_id = imported["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    apigw.tag_resource(
        resourceArn=f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}",
        tags={"sim2real-check": CHECK},
    )

    resources = apigw.get_resources(restApiId=api_id)["items"]
    paths = {r["path"] for r in resources}
    assert "/pets" in paths, f"expected /pets from import, got {paths}"
    assert "/items" not in paths, f"expected /items absent before overwrite, got {paths}"

    overwrite_doc = _swagger_doc(api_name, paths=["/pets", "/items"])
    apigw.put_rest_api(restApiId=api_id, mode="overwrite", body=json.dumps(overwrite_doc).encode("utf-8"))

    resources_after = apigw.get_resources(restApiId=api_id)["items"]
    paths_after = {r["path"] for r in resources_after}
    assert "/pets" in paths_after and "/items" in paths_after, f"expected both paths after overwrite, got {paths_after}"

    stage_name = "sim2realtest"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    export = apigw.get_export(restApiId=api_id, stageName=stage_name, exportType="swagger", accepts="application/json")
    body = json.loads(export["body"].read())
    exported_paths = set(body.get("paths", {}).keys())
    assert "/pets" in exported_paths and "/items" in exported_paths, (
        f"exported spec missing paths, got {exported_paths}"
    )


def _swagger_doc(title: str, paths: list[str]) -> dict:
    path_items = {}
    for p in paths:
        path_items[p] = {
            "get": {
                "responses": {"200": {"description": "OK"}},
                "x-amazon-apigateway-integration": {
                    "type": "mock",
                    "requestTemplates": {"application/json": '{"statusCode": 200}'},
                    "responses": {"default": {"statusCode": "200"}},
                },
            }
        }
    return {
        "swagger": "2.0",
        "info": {"title": title, "version": "1.0"},
        "basePath": "/",
        "schemes": ["https"],
        "paths": path_items,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
