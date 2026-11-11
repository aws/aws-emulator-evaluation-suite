"""update-usage-plan-invalid-apistage-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-usage-plan-invalid-apistage-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUsagePlan rejects an /apiStages patch naming a nonexistent restApiId:stageName pair with
    NotFoundException and leaves apiStages unchanged, while adding a valid apiStage succeeds and
    shows in GetUsagePlan."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    stage_name = "prod"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-usageplan-"), tags={"sim2real": CHECK}
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))
    assert plan.get("apiStages", []) == [], f"expected a fresh plan to have no apiStages, got {plan.get('apiStages')!r}"

    # Negative: reference a rest api / stage pair that does not exist.
    bogus_api_id = ctx.unique_name('nope')[:10]
    bogus_ref = f"{bogus_api_id}:missing-stage"
    err = _client_error(
        lambda: apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "add", "path": "/apiStages", "value": bogus_ref}],
        )
    )
    expected = f"Invalid API identifier specified {ctx.account}:{bogus_api_id}"
    assert (err.get("Code"), err.get("Message")) == ("NotFoundException", expected), (
        f"expected NotFoundException {expected!r}, got {err!r}"
    )

    unchanged = apigw.get_usage_plan(usagePlanId=plan_id)
    assert unchanged.get("apiStages", []) == [], "rejected patch must not mutate apiStages"

    # Positive control: the same shape of patch succeeds against a real api:stage pair.
    valid_ref = f"{api_id}:{stage_name}"
    apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[{"op": "add", "path": "/apiStages", "value": valid_ref}],
    )
    ctx.on_cleanup(
        lambda: apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "remove", "path": "/apiStages", "value": valid_ref}],
        )
    )
    after = apigw.get_usage_plan(usagePlanId=plan_id)
    assert len(after["apiStages"]) == 1, f"expected exactly 1 apiStage after the valid patch, got {after['apiStages']!r}"
    assert after["apiStages"][0]["apiId"] == api_id, (
        f"expected apiId {api_id!r}, got {after['apiStages'][0]['apiId']!r}"
    )
    assert after["apiStages"][0]["stage"] == stage_name, (
        f"expected stage {stage_name!r}, got {after['apiStages'][0]['stage']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises,
    because an over-permissive target accepting a patch real AWS refuses must not be reported
    as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
