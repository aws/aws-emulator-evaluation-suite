"""sdk-generation-lists-types."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "sdk-generation-lists-types"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSdkTypes/GetSdkType enumerate supported SDKs, and GetSdk generates a real
    artifact for a deployed stage."""
    apigw = ctx.client("apigateway")

    types = apigw.get_sdk_types()["items"]
    assert len(types) > 0, "expected at least one supported SDK type"

    first = types[0]
    got_type = apigw.get_sdk_type(id=first["id"])
    assert got_type["id"] == first["id"], (
        f"GetSdkType({first['id']!r}) returned id={got_type['id']!r}, expected it to echo the "
        f"requested id"
    )
    assert got_type["friendlyName"] == first["friendlyName"], (
        f"GetSdkType({first['id']!r}) friendlyName={got_type['friendlyName']!r} disagrees with "
        f"the friendlyName GetSdkTypes reported for the same id ({first['friendlyName']!r})"
    )

    sdk_type = first["id"]
    required_params = {
        prop["name"]: (prop.get("defaultValue") or "sim2real-behav-value")
        for prop in got_type.get("configurationProperties", [])
        if prop.get("required")
    }

    api_id, stage_name = _create_deployed_mock_api(ctx, apigw)

    sdk_kwargs = {"restApiId": api_id, "stageName": stage_name, "sdkType": sdk_type}
    if required_params:
        sdk_kwargs["parameters"] = required_params
    sdk = apigw.get_sdk(**sdk_kwargs)
    assert sdk.get("contentType"), f"expected a contentType on the generated SDK, got {sdk!r}"
    body = sdk["body"].read()
    assert len(body) > 200, f"generated SDK artifact suspiciously small ({len(body)} bytes)"
    assert body[:2] == b"PK", (
        f"expected the generated SDK to be a real zip archive (PK magic bytes), got header {body[:4]!r}"
    )


def _create_deployed_mock_api(ctx: Any, apigw: Any) -> tuple[str, str]:
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-sdk-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200", responseTemplates={}
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    stage_name = "sim2realtest"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    return api_id, stage_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
