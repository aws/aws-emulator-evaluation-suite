"""flush-api-cache-concurrent-modification-accepted."""
from __future__ import annotations

import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flush-api-cache-concurrent-modification-accepted"
GROUP = "concurrency"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushApiCache racing UpdateApiCache on the same API: both succeed with no
    ConcurrentModificationException, the update's new ttl persists, and a later flush succeeds."""
    appsync = ctx.client("appsync")
    api_id = _create_api(ctx, appsync)
    _create_and_wait_cache(ctx, appsync, api_id, ttl=300)

    results = _race({
        "update": lambda: appsync.update_api_cache(
            apiId=api_id, ttl=600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        ),
        "flush": lambda: appsync.flush_api_cache(apiId=api_id),
    })

    outcomes = {k: v[0] for k, v in results.items()}
    assert outcomes == {"update": "ok", "flush": "ok"}, (
        f"expected FlushApiCache and UpdateApiCache to both succeed when racing (real AWS does not "
        f"guard them with the same modification lock), got {outcomes}"
    )

    final = _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=1.0,
        ctx=ctx,
    )
    assert final["status"] == "AVAILABLE", f"cache settled into unexpected status {final['status']}"
    assert final["ttl"] == 600, (
        f"the concurrent UpdateApiCache's ttl change did not persist (got ttl={final['ttl']})"
    )

    # Positive control: once settled, a plain flush still succeeds cleanly.
    appsync.flush_api_cache(apiId=api_id)



def _create_api(ctx, appsync) -> str:
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _create_and_wait_cache(ctx, appsync, api_id, ttl):
    appsync.create_api_cache(
        apiId=api_id, ttl=ttl, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    ctx.on_cleanup(lambda: appsync.delete_api_cache(apiId=api_id))
    _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        lambda c: c["status"] == "AVAILABLE",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=1.0,
        ctx=ctx,
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the API cache reaching the polled status: the run budget ended first; "
                           "not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last}")


def _race(calls):
    """Fire every callable in `calls` at once via a barrier -> {name: (outcome, value_or_code)},
    where outcome is "ok" or "error"."""
    barrier = threading.Barrier(len(calls))
    results = {}

    def _run(name, fn):
        barrier.wait(timeout=10)
        try:
            results[name] = ("ok", fn())
        except ClientError as e:
            results[name] = ("error", e.response["Error"]["Code"])

    threads = [threading.Thread(target=_run, args=(k, v)) for k, v in calls.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
