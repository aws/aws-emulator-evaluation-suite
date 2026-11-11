"""update-deployment-description."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-deployment-description"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patching a deployment's description persists the change without minting a new
    deployment id."""
    apigw = ctx.client("apigateway")
    api_id, deployment_id = _create_deployed_api(ctx, apigw, "prod")

    before = apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert before["description"] == "v1", f"expected initial description 'v1', got {before['description']!r}"

    apigw.update_deployment(
        restApiId=api_id,
        deploymentId=deployment_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "v2-patched"}],
    )

    after = apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert after["id"] == deployment_id, "deploymentId must not change on description patch"
    assert after["description"] == "v2-patched", f"expected patched description 'v2-patched', got {after['description']!r}"

    deployments = apigw.get_deployments(restApiId=api_id)["items"]
    assert len(deployments) == 1, f"patching description must not create a new deployment, got {len(deployments)}"
    assert deployments[0]["id"] == deployment_id, f"expected only deployment to be {deployment_id}, got {deployments[0]['id']}"


def _create_deployed_api(ctx, apigw, stage_name):
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
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
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )
    deployment = apigw.create_deployment(restApiId=api_id, stageName=stage_name, description="v1")
    return api_id, deployment["id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
