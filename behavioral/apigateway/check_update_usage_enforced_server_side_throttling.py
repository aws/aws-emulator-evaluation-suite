"""update-usage-enforced-server-side-throttling."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags

CHECK = "update-usage-enforced-server-side-throttling"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUsage adjustments to a usage plan key's remaining quota are persisted server-side
    and are visible on a subsequent, independent GetUsage query for the same day."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-plan-"),
        quota={"limit": 1000, "period": "MONTH"},
        throttle={"rateLimit": 10.0, "burstLimit": 20},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key_id = apigw.create_api_key(
        name=ctx.unique_name("sim2real-usage-key-"), enabled=True, tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    today = dt.date.today().isoformat()

    # A brand-new usage-plan key that has never actually made a request has no usage record yet:
    # confirmed against real AWS, GetUsage's "items" map simply omits the key entirely rather
    # than reporting a [0, <limit>] placeholder -- so there is nothing to poll for a "baseline"
    # here. Used-so-far is unambiguously 0 for such a key, and UpdateUsage itself is what actually
    # materializes the day's usage record.
    used_before = 0
    new_remaining = 500
    patch_resp = apigw.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": str(new_remaining)}],
    )
    patched_pair = patch_resp["items"][key_id][0]
    assert patched_pair == [used_before, new_remaining], (
        f"UpdateUsage response should reflect the patched remaining quota, got {patched_pair}"
    )

    def probe():
        items = apigw.get_usage(usagePlanId=plan_id, startDate=today, endDate=today)["items"]
        return items.get(key_id)

    after_pair = _poll_until(
        probe,
        lambda p: p is not None and p[0] == [used_before, new_remaining],
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert after_pair is not None and after_pair[0] == [used_before, new_remaining], after_pair


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
