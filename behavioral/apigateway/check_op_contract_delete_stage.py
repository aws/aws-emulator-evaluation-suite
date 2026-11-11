"""op-contract-delete-stage."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-stage"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteStage removes a stage; even when a UsagePlan's apiStages still points at
    that stage, the stage deletion succeeds and the reference is cascaded away from the
    UsagePlan (which itself survives, minus the now-stale apiStage entry)."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"), tags={"sim2real-check": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.create_stage(restApiId=api_id, stageName="prod", deploymentId=deployment_id)

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-apigw-plan-"),
        apiStages=[{"apiId": api_id, "stage": "prod"}],
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_usage_plan(usagePlanId=plan_id)))

    plan_before = apigw.get_usage_plan(usagePlanId=plan_id)
    assert any(
        s.get("apiId") == api_id and s.get("stage") == "prod" for s in plan_before.get("apiStages", [])
    ), "expected the usage plan to reference the stage before deletion"

    # deleting the stage succeeds even though a usage plan still references it; the
    # reference is cascaded away rather than blocking the delete.
    apigw.delete_stage(restApiId=api_id, stageName="prod")
    err = _client_error(lambda: apigw.get_stage(restApiId=api_id, stageName="prod"))
    assert err.get("Code") == "NotFoundException", f"expected stage gone, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid stage identifier specified", (
        f"expected the exact NotFound message from GetStage, got {err.get('Message')!r}"
    )

    # a mutation on the now-dead stage id must fail the same way as the read
    err = _client_error(
        lambda: apigw.update_stage(
            restApiId=api_id,
            stageName="prod",
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert err.get("Code") == "NotFoundException", f"expected UpdateStage on deleted stage to 404, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid stage identifier specified", (
        f"expected the exact NotFound message from UpdateStage, got {err.get('Message')!r}"
    )

    plan_after = apigw.get_usage_plan(usagePlanId=plan_id)
    assert plan_after["id"] == plan_id, f"expected usage plan {plan_id} to survive, got {plan_after.get('id')}"
    assert not any(
        s.get("apiId") == api_id and s.get("stage") == "prod" for s in plan_after.get("apiStages", [])
    ), "expected the usage plan's stale apiStage reference to be cascaded away"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
