"""update-stage-cache-and-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-stage-cache-and-list"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStage patches per-method throttle settings and stage variables, and
    GetStages lists every stage for the API with the patched values."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-updstage-"), tags={"sim2real": "update-stage-cache-and-list"}
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
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]

    stage_name = "sim2realdev"
    apigw.create_stage(
        restApiId=api_id, stageName=stage_name, deploymentId=deployment_id, variables={"env": "dev"}
    )
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/variables/env", "value": "staging"},
            {"op": "replace", "path": "/*/*/throttling/rateLimit", "value": "10"},
            {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "5"},
        ],
    )

    stages = apigw.get_stages(restApiId=api_id)["item"]
    by_name = {s["stageName"]: s for s in stages}
    assert stage_name in by_name, f"expected {stage_name} listed, got {list(by_name)}"
    stage = by_name[stage_name]
    assert stage["variables"]["env"] == "staging", stage["variables"]
    settings = stage["methodSettings"]["*/*"]
    assert settings["throttlingRateLimit"] == 10.0, settings
    assert settings["throttlingBurstLimit"] == 5, settings


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
