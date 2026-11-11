"""update-api-cache-ttl-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-api-cache-ttl-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiCache with a ttl outside the allowed 1-3600s bounds is rejected with
    BadRequestException, and the cache's persisted ttl is left untouched. Waits for AVAILABLE
    first, since UpdateApiCache answers the same BadRequestException while still provisioning."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx, "cache")

    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: appsync.delete_api_cache(apiId=api_id)))
    _poll_for_ttl(ctx, api_id, 300)

    if not _wait_for_cache_status(ctx, api_id, "AVAILABLE", timeout_s=900, interval_s=10.0):
        raise AssertionError(
            f"api cache for {api_id} did not reach AVAILABLE within the check's bounded "
            "budget; cannot isolate the ttl-bounds rejection from the not-yet-available "
            "rejection without an AVAILABLE cache",
        )

    def _out_of_range_update() -> None:
        appsync.update_api_cache(
            apiId=api_id, ttl=3601, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )

    code, msg = _error(_out_of_range_update)
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert msg == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", (
        f"unexpected message: {msg!r}"
    )

    # the forbidden effect must not have happened: ttl is unchanged.
    unchanged = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert unchanged["ttl"] == 300, f"ttl must remain 300 after rejected update, got {unchanged['ttl']}"

    def _below_range_update() -> None:
        appsync.update_api_cache(
            apiId=api_id, ttl=0, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )

    code_low, msg_low = _error(_below_range_update)
    assert code_low == "BadRequestException", f"expected BadRequestException, got {code_low!r}"
    assert msg_low == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", (
        f"unexpected message: {msg_low!r}"
    )
    still_unchanged = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert still_unchanged["ttl"] == 300, (
        f"ttl must remain 300 after rejected below-range update, got {still_unchanged['ttl']}"
    )

    # positive control: a valid ttl within bounds is accepted and persists.
    _update_api_cache_with_retry(
        ctx, api_id, ttl=120, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    valid = _poll_for_ttl(ctx, api_id, 120)
    assert valid["ttl"] == 120, f"in-range UpdateApiCache(ttl=120) must persist, got {valid['ttl']}"


# ===== helpers =====

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
        tags={"sim2real": CHECK},
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
    expected_status, False if the bounded window is exhausted first (the caller decides
    whether that's a skip)."""
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
