"""usage-plan-quota-period-reset-window."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "usage-plan-quota-period-reset-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Changing a usage plan's quota period DAY->WEEK shows immediately in GetUsagePlan.
    Today's per-key [used, remaining] entry set via UpdateUsage survives the change unreset.
    """
    apigw = ctx.client("apigateway")

    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-plan-"),
        quota={"limit": 1000, "period": "DAY"},
        throttle={"rateLimit": 10.0, "burstLimit": 20},
        tags={"sim2real": CHECK},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    got = apigw.get_usage_plan(usagePlanId=plan_id)
    assert got["quota"]["period"] == "DAY"
    assert got["quota"]["limit"] == 1000

    key_resp = apigw.create_api_key(
        name=ctx.unique_name("sim2real-behav-key-"), enabled=True, tags={"sim2real": CHECK}
    )
    key_id = key_resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    today = datetime.date.today().isoformat()
    usage = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    assert usage["usagePlanId"] == plan_id
    assert usage["startDate"] == today
    assert usage["endDate"] == today
    # An association alone does not synthesize a zero-usage row in GetUsage.
    assert key_id not in usage["items"], f"expected no usage entry yet, got {usage['items'][key_id]!r}"

    # Give the key per-key usage state before the period changes.
    apigw.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "200"}],
    )
    consumed = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    used_c, remaining_c = _day_pair(consumed["items"][key_id])
    assert (used_c, remaining_c) == (0, 200), (
        f"expected UpdateUsage to set remaining=200 (used stays 0 -- UpdateUsage moves "
        f"remaining, never used), got [{used_c}, {remaining_c}]"
    )

    apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[
            {"op": "replace", "path": "/quota/period", "value": "WEEK"},
            {"op": "replace", "path": "/quota/limit", "value": "5000"},
        ],
    )
    updated = apigw.get_usage_plan(usagePlanId=plan_id)
    assert updated["quota"]["period"] == "WEEK", updated["quota"]
    assert updated["quota"]["limit"] == 5000, updated["quota"]

    usage_after = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    assert usage_after["startDate"] == today
    assert usage_after["endDate"] == today
    used_after, remaining_after = _day_pair(usage_after["items"][key_id])
    assert (used_after, remaining_after) == (0, 200), (
        f"expected repointing the quota period to leave today's already-recorded usage "
        f"entry [0, 200] untouched, got [{used_after}, {remaining_after}]"
    )


def _day_pair(value):
    """Normalize a GetUsage day entry ([u, r] or [[u, r]]) to a (used, remaining) tuple."""
    if len(value) == 2 and all(isinstance(v, int) for v in value):
        return value[0], value[1]
    return value[0][0], value[0][1]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
