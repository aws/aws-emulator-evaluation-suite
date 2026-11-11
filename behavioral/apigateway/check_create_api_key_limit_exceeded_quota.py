"""create-api-key-limit-exceeded-quota."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-key-limit-exceeded-quota"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

# "Stages per API" stands in for the API-key quota (default 10,000), which is impractical to
# reach; "usage plans per API key" is not hard-enforced by CreateUsagePlanKey.
_STAGES_PER_API_QUOTA = 10


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Exceeding the "stages per API" quota (default 10) on CreateStage returns
    LimitExceededException, creates nothing, and deleting a stage lets the same create succeed.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-execution-service-limits-table.html"""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]

    stage_names: list[str] = []

    for i in range(_STAGES_PER_API_QUOTA):
        stage_name = f"stage{i}"
        apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
        stage_names.append(stage_name)

    extra_stage_name = "stageextra"
    code, message = _error(
        lambda: apigw.create_stage(restApiId=api_id, stageName=extra_stage_name, deploymentId=deployment_id)
    )
    assert code == "LimitExceededException", f"expected LimitExceededException, got {code!r}"
    assert message == (
        "Maximum number of Stages for this API has been reached.  Please contact AWS if you need additional Stages."
    ), f"unexpected LimitExceededException message {message!r}"

    existing_stage_names = {s["stageName"] for s in apigw.get_stages(restApiId=api_id)["item"]}
    assert extra_stage_name not in existing_stage_names, (
        f"expected {extra_stage_name!r} absent after the rejected create, found it in {sorted(existing_stage_names)!r}"
    )

    for stage_name in stage_names:
        assert stage_name in existing_stage_names, (
            f"expected {stage_name!r} to remain among the existing stages {sorted(existing_stage_names)!r}"
        )

    apigw.delete_stage(restApiId=api_id, stageName=stage_names[0])
    apigw.create_stage(restApiId=api_id, stageName=extra_stage_name, deploymentId=deployment_id)

    restored_stage_names = {s["stageName"] for s in apigw.get_stages(restApiId=api_id)["item"]}
    assert extra_stage_name in restored_stage_names, (
        f"expected {extra_stage_name!r} to succeed once a slot was freed, got {sorted(restored_stage_names)!r}"
    )
    assert stage_names[0] not in restored_stage_names, (
        f"expected deleted stage {stage_names[0]!r} to stay gone, got {sorted(restored_stage_names)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

