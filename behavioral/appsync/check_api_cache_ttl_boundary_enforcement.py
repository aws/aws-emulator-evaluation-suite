"""api-cache-ttl-boundary-enforcement."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-cache-ttl-boundary-enforcement"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiCache accepts ttl values across the allowed 1-3600 second window, including both
    bounds, and GetApiCache reflects the exact updated ttl.
    """
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    # CreateApiCache provisions a managed ElastiCache replication group, so the first
    # CREATING -> AVAILABLE transition can take over 10 minutes; updates are much faster.
    _create_wait_s = 600.0
    _update_wait_s = 240.0

    appsync.create_api_cache(
        apiId=api_id,
        ttl=300,
        apiCachingBehavior="FULL_REQUEST_CACHING",
        type="SMALL",
        healthMetricsConfig="DISABLED",
    )
    ctx.on_cleanup(lambda: _delete_cache_ignoring_not_found(appsync, api_id))

    cache = _wait_status(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        {"AVAILABLE", "FAILED"},
        timeout_s=_create_wait_s,
        interval_s=5.0,
    )
    assert cache["status"] == "AVAILABLE", cache
    assert cache["ttl"] == 300, cache

    # Raise ttl to the documented maximum (3600s).
    appsync.update_api_cache(
        apiId=api_id, ttl=3600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL",
    )
    at_max = _wait_status(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        {"AVAILABLE", "FAILED"},
        timeout_s=_update_wait_s,
        interval_s=5.0,
    )
    assert at_max["ttl"] == 3600, f"expected ttl=3600, got {at_max['ttl']}"
    assert at_max["status"] == "AVAILABLE", f"expected status=AVAILABLE, got {at_max['status']}"

    # Lower ttl to the documented minimum (1s).
    appsync.update_api_cache(
        apiId=api_id, ttl=1, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL",
    )
    at_min = _wait_status(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        {"AVAILABLE", "FAILED"},
        timeout_s=_update_wait_s,
        interval_s=5.0,
    )
    assert at_min["ttl"] == 1, f"expected ttl=1, got {at_min['ttl']}"
    assert at_min["status"] == "AVAILABLE", f"expected status=AVAILABLE, got {at_min['status']}"

    # An intermediate value round-trips exactly too.
    appsync.update_api_cache(
        apiId=api_id, ttl=42, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL",
    )
    mid = _wait_status(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        {"AVAILABLE", "FAILED"},
        timeout_s=_update_wait_s,
        interval_s=5.0,
    )
    assert mid["ttl"] == 42, f"expected ttl=42, got {mid['ttl']}"


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real-owner": "behavioral-check"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _delete_cache_ignoring_not_found(appsync, api_id: str) -> None:
    try:
        appsync.delete_api_cache(apiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_status(probe: Callable[[], Any], terminal_statuses, timeout_s: float = 300.0,
                  interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last.get("status") in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"never reached {terminal_statuses} within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
