"""concurrent-update-usage-plan-throttle-race."""
from __future__ import annotations

import time

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-usage-plan-throttle-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


def _retry_contended(fn, attempts: int = 8):
    """Call fn(), retrying while API Gateway refuses it for a concurrent modification of the same
    resource (ConflictException) or throttles it; a caller resolves that contention by retrying."""
    from botocore.exceptions import ClientError

    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ConflictException", "TooManyRequestsException") or attempt == attempts - 1:
                raise
            time.sleep(0.2 * (attempt + 1))


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateUsagePlan patches touching distinct throttle fields apply
    atomically with no lost update: both fields land, neither concurrent writer's patch
    is silently dropped by the other."""
    apigw = ctx.client("apigateway")

    created = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-usageplan-"),
        throttle={"rateLimit": 10.0, "burstLimit": 20},
        tags={"sim2real": CHECK},
    )
    plan_id = created["id"]
    original_name = created["name"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    def _patch_rate():
        return _retry_contended(lambda: apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "replace", "path": "/throttle/rateLimit", "value": "50"}],
        ))

    def _patch_burst():
        return _retry_contended(lambda: apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "replace", "path": "/throttle/burstLimit", "value": "100"}],
        ))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_rate = pool.submit(_patch_rate)
        fut_burst = pool.submit(_patch_burst)
        fut_rate.result()
        fut_burst.result()

    final = apigw.get_usage_plan(usagePlanId=plan_id)
    throttle = final["throttle"]
    assert throttle["rateLimit"] == 50.0, f"rateLimit patch was lost: {throttle}"
    assert throttle["burstLimit"] == 100, f"burstLimit patch was lost: {throttle}"
    # unrelated field, touched by neither racer, must survive untouched
    assert final["name"] == original_name, f"unrelated field 'name' was clobbered: {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
