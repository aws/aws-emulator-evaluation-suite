"""update-stage-patch-variables."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-stage-patch-variables"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStage patches stage variables map without resetting deploymentId."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)
    _put_mock_method(ctx, api_id, root_id, "GET")

    deployment_id = apigw.create_deployment(restApiId=api_id, description="initial")["id"]

    stage_name = ctx.unique_name("stg").replace("-", "")[:20]
    created = apigw.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        variables={"env": "dev"},
    )
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))
    assert created["deploymentId"] == deployment_id, (
        f"CreateStage must echo deploymentId={deployment_id}, got {created.get('deploymentId')}"
    )
    assert created["variables"] == {"env": "dev"}, (
        f"CreateStage must echo variables={{'env': 'dev'}}, got {created.get('variables')}"
    )

    updated = apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/variables/env", "value": "prod"},
            {"op": "replace", "path": "/variables/region", "value": "us-east-1"},
        ],
    )
    assert updated["deploymentId"] == deployment_id, "UpdateStage must not reset deploymentId"
    assert updated["variables"] == {"env": "prod", "region": "us-east-1"}, (
        f"UpdateStage response must reflect both patched variables, got {updated.get('variables')}"
    )

    fetched = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert fetched["deploymentId"] == deployment_id, (
        f"independent GetStage must still report deploymentId={deployment_id}, "
        f"got {fetched.get('deploymentId')}"
    )
    assert fetched["variables"] == {"env": "prod", "region": "us-east-1"}, (
        f"independent GetStage must persist the patched variables, got {fetched.get('variables')}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-bh-api-"))
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
