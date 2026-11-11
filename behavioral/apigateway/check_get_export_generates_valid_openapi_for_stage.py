"""get-export-generates-valid-openapi-for-stage."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-export-generates-valid-openapi-for-stage"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport renders an OpenAPI 3 document of the resources deployed to the given stage only.
    Two stages pinned to different deployments each export just their own deployment snapshot."""
    apigw = ctx.client("apigateway")
    path_part = "widgets"
    api_id, stage_name = _deploy_minimal_api(ctx, path_part=path_part)

    doc_1 = _get_export_doc(apigw, api_id, stage_name)
    _assert_octet_stream_openapi3(doc_1)
    paths_1 = doc_1["doc"].get("paths", {})
    assert f"/{path_part}" in paths_1, f"exported doc missing deployed path /{path_part}: {list(paths_1)}"
    methods_1 = paths_1[f"/{path_part}"]
    assert "get" in methods_1, f"exported doc missing deployed GET method: {list(methods_1)}"
    responses_1 = methods_1["get"].get("responses", {})
    assert "200" in responses_1, f"exported doc missing deployed 200 response: {list(responses_1)}"

    # A resource added after this stage's deployment must not appear in its export.
    second_path_part = "gadgets"
    second_stage = _add_second_stage(ctx, apigw, api_id, second_path_part)

    doc_1_again = _get_export_doc(apigw, api_id, stage_name)
    paths_1_again = doc_1_again["doc"].get("paths", {})
    assert f"/{second_path_part}" not in paths_1_again, (
        f"'{stage_name}' is pinned to the FIRST deployment, predating '/{second_path_part}'; "
        f"its export must not include it, got paths={list(paths_1_again)}"
    )
    assert f"/{path_part}" in paths_1_again, (
        f"'{stage_name}' export regressed after an unrelated second stage was added, "
        f"lost /{path_part}: got paths={list(paths_1_again)}"
    )

    doc_2 = _get_export_doc(apigw, api_id, second_stage)
    _assert_octet_stream_openapi3(doc_2)
    paths_2 = doc_2["doc"].get("paths", {})
    assert f"/{path_part}" in paths_2, (
        f"'{second_stage}' is pinned to the SECOND deployment, which snapshots the whole API "
        f"including the pre-existing /{path_part}; got paths={list(paths_2)}"
    )
    assert f"/{second_path_part}" in paths_2, (
        f"'{second_stage}' export missing its own deployed path /{second_path_part}: {list(paths_2)}"
    )
    methods_2 = paths_2[f"/{second_path_part}"]
    assert "post" in methods_2, f"exported doc missing deployed POST method: {list(methods_2)}"
    responses_2 = methods_2["post"].get("responses", {})
    assert "200" in responses_2, f"exported doc missing deployed 200 response: {list(responses_2)}"


def _deploy_minimal_api(ctx, path_part: str, stage_name: str = "teststage"):
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=path_part)["id"]

    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    return api_id, stage_name


def _add_second_stage(ctx, apigw, api_id: str, path_part: str, stage_name: str = "teststage2") -> str:
    """Add a POST resource to the same API, deploy it, and pin a second stage to that deployment."""
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=path_part)["id"]

    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="POST", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    return stage_name


def _get_export_doc(apigw, api_id: str, stage_name: str) -> dict:
    export = apigw.get_export(
        restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json"
    )
    raw = export["body"].read()
    return {"contentType": export["contentType"], "doc": json.loads(raw)}


def _assert_octet_stream_openapi3(export_doc: dict) -> None:
    # GetExport returns application/octet-stream regardless of `accepts`, which only
    # selects the body serialization (json vs yaml).
    content_type = export_doc["contentType"]
    assert content_type == "application/octet-stream", content_type
    openapi_version = export_doc["doc"].get("openapi", "")
    assert openapi_version.startswith("3."), f"unexpected openapi version: {openapi_version}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
