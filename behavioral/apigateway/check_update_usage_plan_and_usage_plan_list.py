"""update-usage-plan-and-usage-plan-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-usage-plan-and-usage-plan-list"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patching a usage plan's throttle/quota settings updates GetUsagePlans while its
    associated keys remain intact in GetUsagePlanKeys."""
    apigw = ctx.client("apigateway")

    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-usageplan-"),
        throttle={"rateLimit": 10.0, "burstLimit": 5},
        quota={"limit": 1000, "period": "MONTH"},
        tags={"sim2real": "update-usage-plan-and-list"},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key = apigw.create_api_key(
        name=ctx.unique_name("sim2real-usageplan-key-"),
        enabled=True,
        tags={"sim2real": "update-usage-plan-and-list"},
    )
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key["id"]))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key["id"], keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key["id"]))

    apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[
            {"op": "replace", "path": "/throttle/rateLimit", "value": "20"},
            {"op": "replace", "path": "/throttle/burstLimit", "value": "15"},
            {"op": "replace", "path": "/quota/limit", "value": "2000"},
        ],
    )

    plans = [
        p
        for page in apigw.get_paginator("get_usage_plans").paginate()
        for p in page.get("items", [])
    ]
    match = next((p for p in plans if p["id"] == plan_id), None)
    assert match is not None, (
        f"patched usage plan {plan_id} missing from GetUsagePlans, saw {[p['id'] for p in plans]}"
    )
    assert abs(match["throttle"]["rateLimit"] - 20.0) < 1e-6, (
        f"expected patched rateLimit 20.0, got {match['throttle']['rateLimit']}"
    )
    assert match["throttle"]["burstLimit"] == 15, (
        f"expected patched burstLimit 15, got {match['throttle']['burstLimit']}"
    )
    assert match["quota"]["limit"] == 2000, f"expected patched quota limit 2000, got {match['quota']['limit']}"
    assert match["quota"]["period"] == "MONTH", "unpatched quota field must be preserved"

    plan_keys = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert len(plan_keys) == 1, f"expected exactly 1 associated key, got {len(plan_keys)}"
    assert plan_keys[0]["id"] == key["id"], "associated key must remain intact after plan patch"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
