"""flush-api-cache-nonexistent-cache-bad-request."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "flush-api-cache-nonexistent-cache-bad-request"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FlushApiCache on an API whose ApiCache was never created fails NotFoundException (not
    BadRequestException), and stops doing so once CreateApiCache has created the cache resource."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    # Cheap half: a cache that was never created.
    code, message = _error(lambda: appsync.flush_api_cache(apiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Unable to flush the cache as it doesn't exist, please create the cache first.", (
        f"unexpected FlushApiCache message: {message!r}"
    )

    # Deeper half: create a real cache and prove FlushApiCache stops seeing it as absent --
    # otherwise the NotFoundException above is indistinguishable from FlushApiCache rejecting
    # every call regardless of cache state.
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

    # Effect present: GetApiCache -- an independent read, not the mutating call's own response --
    # agrees the resource now exists and reflects what was actually created.
    cache = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert cache["ttl"] == 300, f"expected ttl=300 for {api_id}, got {cache!r}"


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


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-api-")
    api_id = appsync.create_graphql_api(name=name, authenticationType="API_KEY")["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


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
