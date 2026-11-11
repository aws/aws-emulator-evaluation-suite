"""update-stage-settings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-stage-settings"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patching stage variables/tracing settings on a deployed stage is reflected when
    listing all stages for the API via GetStages."""
    apigw = ctx.client("apigateway")
    stage_name = "prod"
    api_id, _deployment_id = _create_deployed_api(ctx, apigw, stage_name)

    before = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert before["tracingEnabled"] is False, (
        f"expected a freshly deployed stage to start with tracingEnabled False, got {before['tracingEnabled']!r}"
    )
    assert before.get("variables", {}) == {}, (
        f"expected a freshly deployed stage to start with no variables, got {before.get('variables')!r}"
    )

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/tracingEnabled", "value": "true"},
            {"op": "replace", "path": "/variables/greeting", "value": "hello"},
        ],
    )

    stages = apigw.get_stages(restApiId=api_id)["item"]
    match = next(s for s in stages if s["stageName"] == stage_name)
    assert match["tracingEnabled"] is True, "tracingEnabled must flip to True in GetStages"
    assert match["variables"]["greeting"] == "hello", "new stage variable must be visible"
    assert match["deploymentId"] == _deployment_id, "deploymentId must be unaffected by the patch"


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
