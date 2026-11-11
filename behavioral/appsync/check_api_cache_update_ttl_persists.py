"""api-cache-update-ttl-persists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-cache-update-ttl-persists"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiCache changing ttl is reflected exactly (not rounded/approximated) on
    subsequent GetApiCache calls, confirming ttl updates are durably applied, across
    multiple successive changes."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx, "ttl")

    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: appsync.delete_api_cache(apiId=api_id)))

    created = _poll_for_ttl(ctx, api_id, 300)
    assert created["ttl"] == 300, f"expected ttl=300 after create, got {created['ttl']}"
    assert created["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"expected apiCachingBehavior=FULL_REQUEST_CACHING after create, got {created['apiCachingBehavior']}"
    )
    assert created["type"] == "SMALL", f"expected type=SMALL after create, got {created['type']}"

    if not _wait_for_cache_status(ctx, api_id, "AVAILABLE", timeout_s=900, interval_s=10.0):
        raise AssertionError(
            f"api cache for {api_id} did not reach AVAILABLE within the check's bounded "
            "budget (real AWS ElastiCache-class node provisioning is asynchronous and can "
            "take longer than a single check's 300s timeout allows); cannot exercise "
            "UpdateApiCache without an AVAILABLE cache",
        )

    _update_api_cache_with_retry(
        ctx, api_id, ttl=1800, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )

    updated = _poll_for_ttl(ctx, api_id, 1800)
    assert updated["ttl"] == 1800, f"expected ttl=1800 after update, got {updated['ttl']}"
    assert updated["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"expected apiCachingBehavior=FULL_REQUEST_CACHING after update, got {updated['apiCachingBehavior']}"
    )
    assert updated["type"] == "SMALL", f"expected type=SMALL after update, got {updated['type']}"

    # a second, independent ttl change also persists exactly -- not just the first delta.
    _update_api_cache_with_retry(
        ctx, api_id, ttl=60, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    twice_updated = _poll_for_ttl(ctx, api_id, 60)
    assert twice_updated["ttl"] == 60, f"expected ttl=60 after second update, got {twice_updated['ttl']}"


# ===== helpers (self-contained) =====

def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_graphql_api(ctx, suffix: str) -> str:
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name(f"sim2real-{suffix}-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: appsync.delete_graphql_api(apiId=api_id)))
    return api_id


def _poll_for_ttl(ctx, api_id: str, expected_ttl: int, timeout_s: float = 60.0, interval_s: float = 3.0) -> dict:
    """Poll GetApiCache (bounded, short) until its persisted ttl matches expected_ttl --
    the config record CreateApiCache/UpdateApiCache write synchronously, independent of the
    (much slower) underlying cache-node provisioning, so this only needs to absorb brief
    read-after-write propagation, never the multi-minute node-availability window."""
    appsync = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    cache = None
    while time.monotonic() < deadline:
        cache = appsync.get_api_cache(apiId=api_id)["apiCache"]
        if cache["ttl"] == expected_ttl:
            return cache
        time.sleep(interval_s)
    raise AssertionError(
        f"api cache for {api_id} never reported ttl={expected_ttl} within {timeout_s}s "
        f"(last={cache})"
    )


def _wait_for_cache_status(ctx, api_id: str, expected_status: str, timeout_s: float = 220.0, interval_s: float = 10.0) -> bool:
    """Bounded poll for the cache's operational status -- returns True once it reaches
    expected_status, False if the bounded window runs out first, and raises if the cache
    enters FAILED."""
    appsync = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_api_cache(apiId=api_id)["apiCache"].get("status")
        if status == expected_status:
            return True
        if status == "FAILED":
            raise AssertionError(f"api cache for {api_id} entered FAILED state")
        time.sleep(interval_s)
    return False


def _update_api_cache_with_retry(ctx, api_id: str, *, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs) -> None:
    """By the time this is called the cache has already been observed AVAILABLE (see
    ``_wait_for_cache_status``), so the only remaining transient signal is a
    ConflictException while the resource briefly converges from a previous
    create/update -- retry that (bounded, short) rather than any long availability
    wait."""
    appsync = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            appsync.update_api_cache(apiId=api_id, **kwargs)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            code = err.get("Code")
            retryable = code == "ConflictException" or (
                code == "BadRequestException" and "not yet available" in err.get("Message", "").lower()
            )
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
