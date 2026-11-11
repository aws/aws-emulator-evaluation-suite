"""get-usage-plan-keys-lists-associated."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-usage-plan-keys-lists-associated"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key associated via CreateUsagePlanKey is enumerable via GetUsagePlanKeys with the right type/name."""
    apigw = ctx.client("apigateway")
    key_name = ctx.unique_name("sim2real-apikey-")
    api_key = apigw.create_api_key(name=key_name, enabled=True)
    key_id = api_key["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    plan_id = apigw.create_usage_plan(name=ctx.unique_name("sim2real-usageplan-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    items = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    matches = [i for i in items if i["id"] == key_id]
    assert len(matches) == 1, f"expected exactly one usage plan key entry for {key_id}, got {matches}"
    assert matches[0]["type"] == "API_KEY", f"expected type API_KEY, got {matches[0]['type']}"
    assert matches[0]["name"] == key_name, f"expected name {key_name}, got {matches[0]['name']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
