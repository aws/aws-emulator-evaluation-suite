"""usage-plan-key-throttle-override-window."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "usage-plan-key-throttle-override-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding a per-method throttle override to a usage plan shows in GetUsagePlan under
    "{resourcePath}/{httpMethod}" without changing the plan-level default; removing it drops it."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        tags={"sim2real": "usage-plan-key-throttle-override-window"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = _root_resource_id(apigw, api_id)
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200", responseTemplates={}
    )
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    plan_rate, plan_burst = 20.0, 10
    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-plan-"),
        apiStages=[{"apiId": api_id, "stage": stage_name}],
        throttle={"rateLimit": plan_rate, "burstLimit": plan_burst},
        tags={"sim2real": "usage-plan-key-throttle-override-window"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key_id = apigw.create_api_key(
        name=ctx.unique_name("sim2real-key-"),
        enabled=True,
        tags={"sim2real": "usage-plan-key-throttle-override-window"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))
    key_ids = {item["id"] for item in apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]}
    assert key_id in key_ids, f"expected {key_id} in usage plan key associations, got {key_ids!r}"

    baseline = apigw.get_usage_plan(usagePlanId=plan_id)
    baseline_stage = baseline["apiStages"][0]
    assert baseline_stage.get("throttle", {}) == {}, "expected no per-method throttle overrides before patching"
    assert baseline["throttle"]["rateLimit"] == plan_rate, (
        f"expected plan-level rateLimit {plan_rate}, got {baseline['throttle']['rateLimit']!r}"
    )

    method_key = "/items/GET"
    # A top-level resource's path segment is given bare, without JSON-pointer escaping.
    scoped_path = f"/apiStages/{api_id}:{stage_name}/throttle/items/GET"
    apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[
            {"op": "add", "path": f"{scoped_path}/rateLimit", "value": "5"},
            {"op": "add", "path": f"{scoped_path}/burstLimit", "value": "2"},
        ],
    )
    with_override = apigw.get_usage_plan(usagePlanId=plan_id)
    override_entry = with_override["apiStages"][0]["throttle"][method_key]
    assert override_entry["rateLimit"] == 5.0, f"expected override rateLimit 5.0, got {override_entry!r}"
    assert override_entry["burstLimit"] == 2, f"expected override burstLimit 2, got {override_entry!r}"
    # The plan-level default is untouched by a method-scoped override.
    assert with_override["throttle"]["rateLimit"] == plan_rate, (
        f"expected plan-level rateLimit to stay {plan_rate} after a method-scoped override, "
        f"got {with_override['throttle']['rateLimit']!r}"
    )

    apigw.update_usage_plan(
        usagePlanId=plan_id, patchOperations=[{"op": "remove", "path": scoped_path}]
    )
    after_removal = apigw.get_usage_plan(usagePlanId=plan_id)
    remaining_throttle = after_removal["apiStages"][0].get("throttle", {})
    assert method_key not in remaining_throttle, "override entry survived removal -- did not revert"
    assert after_removal["throttle"]["rateLimit"] == plan_rate, (
        f"expected plan-level rateLimit {plan_rate} after override removal, "
        f"got {after_removal['throttle']['rateLimit']!r}"
    )


def _root_resource_id(apigw, api_id: str) -> str:
    for item in apigw.get_resources(restApiId=api_id)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise AssertionError("root resource not found")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
