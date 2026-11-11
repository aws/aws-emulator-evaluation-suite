"""update-stage-conflict-during-deployment."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stage-conflict-during-deployment"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStage rejects a nonexistent /deploymentId with BadRequestException; the stage is kept.
    Repointing at a second real deployment succeeds first, so the rejection is due to the bogus id."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    deployment1_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "test"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment1_id)

    # Positive control: repoint /deploymentId at a second real deployment.
    deployment2_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/deploymentId", "value": deployment2_id}],
    )
    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["deploymentId"] == deployment2_id, (
        f"positive control failed: expected deploymentId {deployment2_id!r}, got "
        f"{stage['deploymentId']!r}"
    )

    err = _client_error(
        lambda: apigw.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {"op": "replace", "path": "/deploymentId", "value": "bogus1234567890xyz"}
            ],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Deployment id does not exist", (
        f"expected the exact unknown-deployment refusal message, got {err.get('Message')!r}"
    )

    stage = next(
        s for s in apigw.get_stages(restApiId=api_id)["item"] if s["stageName"] == stage_name
    )
    assert stage["deploymentId"] == deployment2_id, (
        f"expected deploymentId to remain {deployment2_id!r} after the rejected update, got "
        f"{stage['deploymentId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
