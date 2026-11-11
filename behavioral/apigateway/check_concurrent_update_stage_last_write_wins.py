"""concurrent-update-stage-last-write-wins."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "concurrent-update-stage-last-write-wins"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two sequential UpdateStage calls apply in request order: fields touched by both calls
    reflect the later call, while fields touched only by the earlier call are preserved
    (no lost-update / wholesale-overwrite corruption)."""
    apigw = ctx.client("apigateway")

    api_name = ctx.unique_name("sim2real-behav-api-")
    rest_api_id = apigw.create_rest_api(name=api_name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))
    root_id = [r for r in apigw.get_resources(restApiId=rest_api_id)["items"] if r["path"] == "/"][0]["id"]

    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    deployment_id = apigw.create_deployment(restApiId=rest_api_id)["id"]

    stage_name = "concur"
    apigw.create_stage(
        restApiId=rest_api_id, stageName=stage_name, deploymentId=deployment_id,
        description="initial", variables={"env": "initial", "owner": "nobody"},
    )

    # Call 1: sets description, env AND owner.
    apigw.update_stage(
        restApiId=rest_api_id, stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/description", "value": "call-1"},
            {"op": "replace", "path": "/variables/env", "value": "v-call1"},
            {"op": "replace", "path": "/variables/owner", "value": "call1-owner"},
        ],
    )

    # Call 2: applied after call 1, only touches description and env (not owner).
    apigw.update_stage(
        restApiId=rest_api_id, stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/description", "value": "call-2"},
            {"op": "replace", "path": "/variables/env", "value": "v-call2"},
        ],
    )

    stage = apigw.get_stage(restApiId=rest_api_id, stageName=stage_name)
    assert stage["description"] == "call-2", f"expected description 'call-2', got {stage['description']!r}"
    assert stage["variables"]["env"] == "v-call2", f"expected variables.env 'v-call2', got {stage['variables']!r}"
    # Field touched only by call 1 must survive call 2's patch untouched (partial-merge, not overwrite).
    assert stage["variables"]["owner"] == "call1-owner", (
        f"expected variables.owner to persist from call 1 as 'call1-owner', got {stage['variables']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
