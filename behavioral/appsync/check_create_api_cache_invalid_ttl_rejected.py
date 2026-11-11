"""create-api-cache-invalid-ttl-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-cache-invalid-ttl-rejected"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiCache with a ttl outside 1-3600 s fails with BadRequestException and creates no
    cache, while the same API accepts an in-range ttl, so the refusal is specific to the value."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-apicache-badttl-")
    api_id = appsync.create_graphql_api(name=name, authenticationType="API_KEY")["graphqlApi"][
        "apiId"
    ]
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, api_id))

    code, message = _error(
        lambda: appsync.create_api_cache(
            apiId=api_id, ttl=999999, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException for out-of-range ttl, got {code!r}"
    assert message == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", (
        f"expected the exact out-of-range ttl message, got {message!r}"
    )

    # A cache must NOT have actually been created as a side effect of the rejected call.
    not_found_code, not_found_message = _error(lambda: appsync.get_api_cache(apiId=api_id))
    assert not_found_code == "NotFoundException", (
        f"rejected CreateApiCache should not leave a cache behind, got {not_found_code!r}"
    )
    assert not_found_message == "Unable to get the cache as it doesn't exist, please create the cache first.", (
        f"expected the exact missing-cache message, got {not_found_message!r}"
    )

    # Positive control: the same api accepts an in-range ttl.
    ctx.on_cleanup(lambda: _safe_delete_api_cache(appsync, api_id))
    created = appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    assert created["ttl"] == 300, f"expected ttl=300 on positive control, got {created['ttl']!r}"


# ===== helpers =====
def _safe_delete_graphql_api(appsync, api_id) -> None:
    try:
        appsync.delete_graphql_api(apiId=api_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _safe_delete_api_cache(appsync, api_id) -> None:
    # DeleteApiCache is refused with BadRequestException until the cache is AVAILABLE, which takes
    # minutes after create; retry that code within the cleanup budget, raise anything else.
    deadline = time.monotonic() + 600.0
    while True:
        try:
            appsync.delete_api_cache(apiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
