"""update-stage-invalid-loglevel-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stage-invalid-loglevel-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStage patching methodSettings loggingLevel to an invalid enum value is rejected."""
    apigw = ctx.client("apigateway")
    api_id, stage_name = _create_api_with_stage(ctx, apigw)

    err = _client_error(
        lambda: apigw.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {"op": "replace", "path": "/*/*/logging/loglevel", "value": "NOT_A_LEVEL"}
            ],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid logging level specified: NOT_A_LEVEL", (
        f"expected the exact invalid-logging-level refusal message, got {err.get('Message')!r}"
    )

    # (b) effect absent: the stage's method settings were not mutated with the bad value.
    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    settings = stage.get("methodSettings", {}).get("*/*", {})
    assert settings.get("loggingLevel") != "NOT_A_LEVEL", "invalid loggingLevel value persisted"

    # (c) positive control: a valid loggingLevel value ("OFF") is accepted and persists.
    # ("INFO"/"ERROR" require a CloudWatch Logs role ARN configured in account settings,
    # which is an unrelated account-level precondition; "OFF" isolates the enum check.)
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "OFF"}],
    )

    # terminal read: independent GetStage, not the UpdateStage response, at the destination.
    final_stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    final_level = final_stage.get("methodSettings", {}).get("*/*", {}).get("loggingLevel")
    assert final_level == "OFF", f"expected loggingLevel OFF to persist, got {final_level!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_api_with_stage(ctx, apigw):
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-apigw-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "teststage"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"])
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))
    return api_id, stage_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
