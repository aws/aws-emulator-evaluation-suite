"""concurrent-usage-plan-key-duplicate-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-usage-plan-key-duplicate-conflict"
GROUP = 'concurrency'
SERVICES = ['apigateway']


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))

def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateUsagePlanKey calls associating the same ApiKey with the same UsagePlan yield exactly
    one success, every other call fails with ConflictException, and GetUsagePlanKeys lists one association."""
    ag = ctx.client("apigateway")
    plan_id = ag.create_usage_plan(
        name=ctx.unique_name("plan-"),
        tags={"sim2real": "concurrent-usage-plan-key-duplicate-conflict"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_usage_plan(usagePlanId=plan_id))
    key_id = ag.create_api_key(
        name=ctx.unique_name("key-"),
        enabled=True,
        tags={"sim2real": "concurrent-usage-plan-key-duplicate-conflict"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=key_id))

    n = 5

    def _assoc():
        return ag.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")

    results = _run_concurrent([_assoc for _ in range(n)])
    ctx.on_cleanup(lambda: ag.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly 1 success out of {n} racers, got {successes}"
    error_codes = _concurrent_error_codes(results)
    assert all(c == "ConflictException" for c in error_codes), (
        f"expected every losing racer to fail with ConflictException, got {error_codes}"
    )
    error_messages = [r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)]
    assert error_messages == ["API Key is already subscribed to Usage Plan"] * len(error_codes), error_messages

    keys = ag.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    matching = [k for k in keys if k["id"] == key_id]
    assert len(matching) == 1, f"expected exactly one association, found {len(matching)}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
