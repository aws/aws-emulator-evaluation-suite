"""update-deployment-patch-description."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-deployment-patch-description"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeployment patches description without altering associated stages."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)
    _put_mock_method(ctx, api_id, root_id, "GET")

    stage_name = ctx.unique_name("stg").replace("-", "")[:20]
    created = apigw.create_deployment(restApiId=api_id, stageName=stage_name, description="v1")
    deployment_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))
    assert created["description"] == "v1", f"expected description 'v1', got {created['description']!r}"

    stage_before = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage_before["deploymentId"] == deployment_id, (
        f"expected stage to point at {deployment_id}, got {stage_before['deploymentId']!r}"
    )

    updated = apigw.update_deployment(
        restApiId=api_id,
        deploymentId=deployment_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "v2"}],
    )
    assert updated["id"] == deployment_id, f"expected id {deployment_id}, got {updated['id']!r}"
    assert updated["description"] == "v2", f"expected description 'v2', got {updated['description']!r}"

    fetched = apigw.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert fetched["description"] == "v2", f"expected description 'v2', got {fetched['description']!r}"

    stage_after = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage_after["deploymentId"] == deployment_id, "patching deployment description must not move stage's deployment pointer"


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-bh-api-"), tags={"sim2real": CHECK})
    api_id = resp["id"]
    root_id = resp["rootResourceId"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id, root_id


def _put_mock_method(ctx, api_id, resource_id, http_method):
    apigw = ctx.client("apigateway")
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
