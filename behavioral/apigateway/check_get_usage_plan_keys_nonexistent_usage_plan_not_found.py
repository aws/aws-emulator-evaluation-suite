"""get-usage-plan-keys-nonexistent-usage-plan-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-usage-plan-keys-nonexistent-usage-plan-not-found"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUsagePlanKeys lists a key associated on the plan; a usagePlanId that does not
    exist answers 200 with an empty list rather than a NotFoundException."""
    apigw = ctx.client("apigateway")

    key_name = ctx.unique_name("sim2real-apikey-")
    key_id = apigw.create_api_key(name=key_name, enabled=True)["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-usageplan-"), tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    items = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    matches = [i for i in items if i["id"] == key_id]
    assert len(matches) == 1, f"expected exactly one usage plan key entry for {key_id!r}, got {items!r}"
    assert matches[0]["type"] == "API_KEY", f"expected type API_KEY, got {matches[0]['type']!r}"

    missing = apigw.get_usage_plan_keys(usagePlanId="sim2real-missing-usage-plan")
    assert missing["items"] == [], (
        f"expected an empty list for a nonexistent usagePlanId, got {missing['items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
