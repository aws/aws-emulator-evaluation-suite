"""concurrent-usage-plan-key-invalid-keytype-rejected."""
from __future__ import annotations

import threading

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-usage-plan-key-invalid-keytype-rejected"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Under a concurrent race, a CreateUsagePlanKey call with an invalid keyType is
    deterministically rejected with BadRequestException while the valid concurrent racer
    still succeeds -- the invalid enum value is never silently accepted due to the race."""
    apigw = ctx.client("apigateway")

    plan_id = apigw.create_usage_plan(name=ctx.unique_name("sim2real-behav-plan-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key_id = apigw.create_api_key(name=ctx.unique_name("sim2real-behav-key-"), enabled=True)["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    def _valid():
        return apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")

    def _invalid():
        return apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="NOT_A_REAL_TYPE")

    (valid_result, valid_err, _), (invalid_result, invalid_err, invalid_message) = _race([_valid, _invalid])

    assert invalid_err == "BadRequestException", (
        f"invalid keyType was not rejected with BadRequestException (got {invalid_err}, "
        f"result={invalid_result})"
    )
    assert invalid_message == "Invalid Usage Plan key type specified. Must be one of [API_KEY]", invalid_message
    assert valid_err is None, f"the valid racer unexpectedly failed: {valid_err}"
    assert valid_result["id"] == key_id, (
        f"the valid racer's create_usage_plan_key returned the wrong id: "
        f"expected {key_id}, got {valid_result['id']}"
    )

    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    items = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert len(items) == 1, f"expected exactly 1 valid association survived, got {len(items)}"


def _race(fns):
    barrier = threading.Barrier(len(fns))
    results = [None] * len(fns)

    def _worker(i, fn):
        barrier.wait()
        try:
            results[i] = (fn(), None, None)
        except ClientError as e:
            results[i] = (None, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    threads = [threading.Thread(target=_worker, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
