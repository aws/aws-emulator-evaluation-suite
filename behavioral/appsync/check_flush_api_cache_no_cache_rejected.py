"""flush-api-cache-no-cache-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "flush-api-cache-no-cache-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FlushApiCache on an API with no cache fails NotFoundException rather than a silent no-op, and the
    identical call stops hitting that path once an ApiCache resource exists."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-flush-")

    api = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": "flush-api-cache-no-cache-rejected"}
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    # Negative: no cache has ever been created for this Api -> rejected, not a silent no-op.
    code, message = _error(lambda: appsync.flush_api_cache(apiId=api_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException flushing a nonexistent cache, got {code!r}"
    )
    assert message == "Unable to flush the cache as it doesn't exist, please create the cache first.", (
        f"unexpected FlushApiCache message: {message!r}"
    )

    # Independent read, same claim: GetApiCache agrees no cache record exists either -- the
    # FlushApiCache rejection above reflects real absence-of-cache state, not a code peculiar
    # to FlushApiCache itself.
    get_code_before, get_message_before = _error(lambda: appsync.get_api_cache(apiId=api_id))
    assert get_code_before == "NotFoundException", (
        f"expected GetApiCache NotFoundException before any cache exists, got {get_code_before!r}"
    )
    assert get_message_before == "Unable to get the cache as it doesn't exist, please create the cache first.", (
        f"unexpected GetApiCache message: {get_message_before!r}"
    )

    # Positive control: provision a real cache (the resource is created synchronously by
    # CreateApiCache; only the underlying nodes provision async) and confirm the identical
    # FlushApiCache call no longer sees the resource as absent.
    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    # No separate DeleteApiCache teardown: AppSync refuses it while the cache is still
    # creating, and the GraphQL API's own cleanup deletes the cache with the API.

    _poll_until(
        lambda: _flush_sees_cache(appsync, api_id),
        bool,
        timeout_s=60.0,
        interval_s=3.0,
    )

    # Independent read, same claim: GetApiCache now reports the cache record we created,
    # corroborating the FlushApiCache transition through a different operation.
    cache_record = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert cache_record.get("apiCachingBehavior") == "FULL_REQUEST_CACHING", (
        "GetApiCache should independently confirm the cache we created now exists, got "
        f"{cache_record!r}"
    )


def _error(fn):
    """Call fn() and return its botocore error (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _flush_sees_cache(appsync, api_id) -> bool:
    """True once FlushApiCache no longer answers NotFoundException (success or any other refusal)."""
    from botocore.exceptions import ClientError

    try:
        appsync.flush_api_cache(apiId=api_id)
    except ClientError as err:
        return err.response["Error"]["Code"] != "NotFoundException"
    return True


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
