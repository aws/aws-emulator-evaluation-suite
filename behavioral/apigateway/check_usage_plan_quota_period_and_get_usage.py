"""usage-plan-quota-period-and-get-usage."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "usage-plan-quota-period-and-get-usage"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUsage has no entry for a newly attached key with no traffic (the daily record is created
    lazily, not from the quota), and an UpdateUsage write creates today's entry, visible on an
    independent GetUsage call."""
    apigw = ctx.client("apigateway")

    key_resp = apigw.create_api_key(
        name=ctx.unique_name("sim2real-apigw-key-"),
        enabled=True,
        tags={"sim2real": "usage-plan-quota-period-and-get-usage"},
    )
    key_id = key_resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    quota_limit = 1000
    plan_resp = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-apigw-plan-"),
        quota={"limit": quota_limit, "period": "DAY"},
        throttle={"rateLimit": 50, "burstLimit": 100},
        tags={"sim2real": "usage-plan-quota-period-and-get-usage"},
    )
    plan_id = plan_resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))
    assert plan_resp["quota"]["limit"] == quota_limit, (
        f"expected CreateUsagePlan to echo limit={quota_limit}, got {plan_resp['quota']}"
    )
    assert plan_resp["quota"]["period"] == "DAY", (
        f"expected CreateUsagePlan to echo period=DAY, got {plan_resp['quota']}"
    )

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    today = dt.datetime.now(dt.timezone.utc).date().isoformat()

    initial = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    assert key_id not in initial.get("items", {}), (
        f"expected NO usage entry for a freshly-attached key with no traffic or "
        f"administrative write, got {initial.get('items', {}).get(key_id)!r}"
    )

    # Mid-period administrative write: UpdateUsage lazily creates today's entry for a
    # key that has never had any traffic, setting remaining to 25.
    updated = apigw.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "25"}],
    )
    used_u, remaining_u = _day_pair(updated["items"][key_id])
    assert (used_u, remaining_u) == (0, 25), (
        f"UpdateUsage did not lazily create today's entry as [0, 25], got [{used_u}, {remaining_u}]"
    )

    # The adjustment must persist and be visible on a fresh GetUsage call.
    after = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    used_a, remaining_a = _day_pair(after["items"][key_id])
    assert (used_a, remaining_a) == (0, 25), (
        f"GetUsage did not reflect the UpdateUsage adjustment, got [{used_a}, {remaining_a}]"
    )

    # Negative: only "/remaining" is a supported UpdateUsage patch path.
    err = _client_error(
        lambda: apigw.update_usage(
            usagePlanId=plan_id,
            keyId=key_id,
            patchOperations=[{"op": "replace", "path": "/used", "value": "999"}],
        )
    )
    expected = (
        "BadRequestException",
        "Invalid patch path  '/used' specified for op 'replace'. Must be one of: [/remaining]",
    )
    assert (err.get("Code"), err.get("Message")) == expected, (
        f"expected {expected!r} for an unsupported path, got {err!r}"
    )

    # The rejected patch must not have mutated the stored quota.
    unchanged = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    used_c, remaining_c = _day_pair(unchanged["items"][key_id])
    assert (used_c, remaining_c) == (0, 25), (
        f"expected the rejected patch to leave [0, 25] unchanged, got [{used_c}, {remaining_c}]"
    )


def _day_pair(value):
    """GetUsage/UpdateUsage represent a single day's [used, remaining] entry either
    as a flat 2-element list or as a 1-element list of a 2-element list, depending
    on the date range width. Normalize to a (used, remaining) tuple."""
    if len(value) == 2 and all(isinstance(v, int) for v in value):
        return value[0], value[1]
    return value[0][0], value[0][1]


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises,
    because an emulator accepting input real AWS refuses is the strongest signal available and must
    not be reported as an error mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
