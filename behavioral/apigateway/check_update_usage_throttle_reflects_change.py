"""update-usage-throttle-reflects-change."""
from __future__ import annotations

import datetime as _dt

from behavioral_harness import tags

CHECK = "update-usage-throttle-reflects-change"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUsage patches the per-key remaining-quota override, reflected in GetUsage."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-bh-plan-"),
        quota={"limit": 1000, "period": "DAY"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key_created = apigw.create_api_key(name=ctx.unique_name("sim2real-bh-key-"), enabled=True)
    key_id = key_created["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    today = _dt.date.today().isoformat()

    # Grant a temporary extension of the remaining quota for today, well beyond the plan limit.
    apigw.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "1500"}],
    )

    usage = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    assert usage["usagePlanId"] == plan_id, (
        f"expected GetUsage to echo the queried plan {plan_id}, got {usage['usagePlanId']}"
    )
    day_entries = usage["items"][key_id]
    assert len(day_entries) == 1, (
        f"expected exactly one [used, remaining] pair for the single day queried, got {day_entries}"
    )
    used, remaining = day_entries[0]
    assert used == 0, "no requests were made against the key, used quota must be 0"
    assert remaining == 1500, f"expected the extended remaining quota of 1500, got {remaining}"

    # Apply a second override and confirm GetUsage reflects the latest value, not the first.
    apigw.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "1800"}],
    )
    usage2 = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    _used2, remaining2 = usage2["items"][key_id][0]
    assert remaining2 == 1800, (
        f"expected the second override to overwrite the first, leaving remaining=1800, got {remaining2}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
