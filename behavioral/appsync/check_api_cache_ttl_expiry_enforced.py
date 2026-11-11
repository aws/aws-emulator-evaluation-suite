"""api-cache-ttl-expiry-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "api-cache-ttl-expiry-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A short-TTL ApiCache carries its configured ttl through the live resource at
    runtime: created at the minimum ttl (1s), then mutated to a much larger ttl via
    UpdateApiCache, with GetApiCache reflecting the live value at each settled state."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.create_api_cache(
        apiId=api_id, ttl=1, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    ctx.on_cleanup(lambda: appsync.delete_api_cache(apiId=api_id))

    created = _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        lambda cache: cache["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=_budget_s(ctx, 900.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert created["status"] == "AVAILABLE", f"ApiCache settled into {created['status']}: {created}"
    assert created["ttl"] == 1, f"expected ttl=1 at creation, got {created['ttl']}"
    assert created["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"expected apiCachingBehavior=FULL_REQUEST_CACHING at creation, got {created['apiCachingBehavior']}"
    )
    assert created["type"] == "SMALL", f"expected type=SMALL at creation, got {created['type']}"

    appsync.update_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    # The update is applied once the cache is AVAILABLE again carrying the new ttl; a read that
    # still shows the prior settled state keeps the poll waiting.
    updated = _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        lambda cache: cache["status"] == "FAILED"
        or (cache["status"] == "AVAILABLE" and cache["ttl"] == 300),
        timeout_s=_budget_s(ctx, 900.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert updated["status"] == "AVAILABLE", f"ApiCache update settled into {updated['status']}: {updated}"
    assert updated["ttl"] == 300, f"UpdateApiCache did not take effect at runtime: ttl={updated['ttl']}"
    assert updated["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"expected apiCachingBehavior=FULL_REQUEST_CACHING after update, got {updated['apiCachingBehavior']}"
    )
    assert updated["type"] == "SMALL", f"expected type=SMALL after update, got {updated['type']}"


# ===== helpers =====

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s, ctx):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("the API cache reaching the polled state: the run budget ended first; "
                           "not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
