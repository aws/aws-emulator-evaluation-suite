"""get-sdk-generates-downloadable-artifact."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-sdk-generates-downloadable-artifact"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSdk generates a real downloadable artifact for a supported sdkType: a non-trivial zip
    (PK header, .zip filename), with the required configuration parameters read from that
    type's own GetSdkType response."""
    apigw = ctx.client("apigateway")

    sdk_types = apigw.get_sdk_types().get("items", [])
    assert sdk_types, "GetSdkTypes returned no supported SDK types"
    sdk_type_id, detail, required_params = _pick_sdk_type_and_required_params(apigw, sdk_types)

    assert detail["id"] == sdk_type_id, (
        f"expected GetSdkType to describe {sdk_type_id!r}, got id={detail.get('id')!r}"
    )
    assert "friendlyName" in detail, f"expected GetSdkType({sdk_type_id!r}) to carry a friendlyName, got {detail!r}"

    api_id, stage_name = _deploy_minimal_api(ctx)

    sdk_kwargs = {"restApiId": api_id, "stageName": stage_name, "sdkType": sdk_type_id}
    if required_params:
        sdk_kwargs["parameters"] = required_params
    sdk = apigw.get_sdk(**sdk_kwargs)
    body = sdk["body"].read()

    assert len(body) > 200, f"SDK artifact suspiciously small ({len(body)} bytes) for {sdk_type_id}"
    assert body[:2] == b"PK", (
        f"expected a real zip archive (PK magic bytes) for sdkType={sdk_type_id}, got {body[:8]!r}"
    )
    disposition = sdk.get("contentDisposition", "")
    assert ".zip" in disposition, f"expected a .zip filename in contentDisposition, got {disposition!r}"


def _pick_sdk_type_and_required_params(apigw, sdk_types: list[dict]) -> tuple[str, dict, dict[str, str]]:
    """Deterministically pick an enumerated sdkType and fill whatever
    configuration parameters GetSdkType reports as required for it, using each
    property's own defaultValue where the target supplies one."""
    sdk_type_id = sorted(t["id"] for t in sdk_types)[0]
    detail = apigw.get_sdk_type(id=sdk_type_id)
    required_params = {
        prop["name"]: (prop.get("defaultValue") or "sim2real-behav-value")
        for prop in detail.get("configurationProperties", [])
        if prop.get("required")
    }
    return sdk_type_id, detail, required_params


def _deploy_minimal_api(ctx, stage_name: str = "teststage"):
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": "get-sdk-generates-downloadable-artifact"}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]

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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
