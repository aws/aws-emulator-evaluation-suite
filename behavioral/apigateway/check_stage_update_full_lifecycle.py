"""stage-update-full-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stage-update-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStage patches variables/description/deployment pointer and GetStages reflects the change."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-stage-")
    rest_api_id = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    deployment_1 = apigw.create_deployment(restApiId=rest_api_id, description="deployment one")["id"]
    deployment_2 = apigw.create_deployment(restApiId=rest_api_id, description="deployment two")["id"]

    stage_name = ctx.unique_name("stg")
    created_stage = apigw.create_stage(
        restApiId=rest_api_id,
        stageName=stage_name,
        deploymentId=deployment_1,
        description="initial stage",
        variables={"env": "dev"},
    )
    assert created_stage["deploymentId"] == deployment_1, (
        f"expected deploymentId {deployment_1}, got {created_stage['deploymentId']}"
    )
    assert created_stage["variables"] == {"env": "dev"}, (
        f"expected variables {{'env': 'dev'}}, got {created_stage['variables']}"
    )

    apigw.update_stage(
        restApiId=rest_api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/variables/env", "value": "prod"},
            {"op": "replace", "path": "/description", "value": "updated stage"},
            {"op": "replace", "path": "/deploymentId", "value": deployment_2},
        ],
    )

    stages = apigw.get_stages(restApiId=rest_api_id)["item"]
    match = next((s for s in stages if s["stageName"] == stage_name), None)
    assert match is not None, "the updated stage must appear in the GetStages collection"
    assert match["variables"]["env"] == "prod", f"expected variables.env prod, got {match['variables']}"
    assert match["description"] == "updated stage", (
        f"expected description 'updated stage', got {match['description']!r}"
    )
    assert match["deploymentId"] == deployment_2, "changing /deploymentId must re-point the stage"


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
