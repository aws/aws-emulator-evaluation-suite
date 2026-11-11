"""canary-deployment-promote-flow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "canary-deployment-promote-flow"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Promoting a canary release copies the canary's deploymentId onto the stage's deploymentId
    and zeroes percentTraffic, without disturbing the base deployment until promotion happens."""
    apigw = ctx.client("apigateway")

    rest_api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-canary-api-"),
        tags={"sim2real": "canary-deployment-promote-flow"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(
        restApiId=rest_api_id, parentId=root_id, pathPart="canary-test"
    )["id"]
    _wire_mock_get(apigw, rest_api_id, resource_id)

    deployment_a = apigw.create_deployment(restApiId=rest_api_id, description="base")["id"]
    apigw.create_stage(restApiId=rest_api_id, stageName="prod", deploymentId=deployment_a)

    deployment_b = apigw.create_deployment(
        restApiId=rest_api_id, description="canary-candidate"
    )["id"]

    apigw.update_stage(
        restApiId=rest_api_id,
        stageName="prod",
        patchOperations=[
            {"op": "replace", "path": "/canarySettings/deploymentId", "value": deployment_b},
            {"op": "replace", "path": "/canarySettings/percentTraffic", "value": "10.0"},
        ],
    )
    stage = apigw.get_stage(restApiId=rest_api_id, stageName="prod")
    assert stage["deploymentId"] == deployment_a, "adding a canary must not move the base deploymentId"
    assert stage["canarySettings"]["deploymentId"] == deployment_b, (
        f"expected canarySettings.deploymentId={deployment_b!r}, got {stage['canarySettings']!r}"
    )
    assert stage["canarySettings"]["percentTraffic"] == 10.0, (
        f"expected canarySettings.percentTraffic=10.0, got {stage['canarySettings']!r}"
    )

    # Promote: copy the canary's deploymentId onto the stage and reset canary traffic to 0%.
    apigw.update_stage(
        restApiId=rest_api_id,
        stageName="prod",
        patchOperations=[
            {"op": "replace", "path": "/canarySettings/percentTraffic", "value": "0.0"},
            {"op": "copy", "from": "/canarySettings/deploymentId", "path": "/deploymentId"},
        ],
    )
    promoted = apigw.get_stage(restApiId=rest_api_id, stageName="prod")
    assert promoted["deploymentId"] == deployment_b, "promotion must move the stage onto the canary deployment"
    assert promoted["canarySettings"]["percentTraffic"] == 0.0, (
        f"expected canarySettings.percentTraffic=0.0 after promotion, got {promoted['canarySettings']!r}"
    )


def _wire_mock_get(apigw, rest_api_id, resource_id) -> None:
    apigw.put_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
