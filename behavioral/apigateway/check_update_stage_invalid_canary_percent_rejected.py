"""update-stage-invalid-canary-percent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stage-invalid-canary-percent-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected UpdateStage to reject percentTraffic=150, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStage rejects a canarySettings.percentTraffic value outside the valid
    [0, 100] range (a quota/range boundary), while a valid canary update still applies."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    dep1 = apigw.create_deployment(restApiId=api_id)
    dep2 = apigw.create_deployment(restApiId=api_id)
    apigw.create_stage(restApiId=api_id, stageName="prod", deploymentId=dep1["id"])

    # A valid canary release (0-100 range) must succeed first.
    apigw.update_stage(
        restApiId=api_id,
        stageName="prod",
        patchOperations=[
            {"op": "replace", "path": "/canarySettings/percentTraffic", "value": "50"},
            {"op": "replace", "path": "/canarySettings/deploymentId", "value": dep2["id"]},
        ],
    )
    stage = apigw.get_stage(restApiId=api_id, stageName="prod")
    assert stage["canarySettings"]["percentTraffic"] == 50.0, stage

    err = _client_error(
        lambda: apigw.update_stage(
            restApiId=api_id,
            stageName="prod",
            patchOperations=[
                {"op": "replace", "path": "/canarySettings/percentTraffic", "value": "150"}
            ],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid traffic settings for stage canary. Must be between 0 and 100", (
        f"expected the exact out-of-range canary refusal message, got {err.get('Message')!r}"
    )

    # The out-of-range patch must not have been applied.
    stage_after = apigw.get_stage(restApiId=api_id, stageName="prod")
    assert stage_after["canarySettings"]["percentTraffic"] == 50.0, stage_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
