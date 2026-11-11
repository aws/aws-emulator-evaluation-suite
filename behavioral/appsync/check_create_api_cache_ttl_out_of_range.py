"""create-api-cache-ttl-out-of-range."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "create-api-cache-ttl-out-of-range"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiCache with a ttl outside 1-3600 s fails BadRequestException and leaves no cache, while
    an in-range ttl on the same apiId is accepted."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    def attempt():
        return svc.create_api_cache(
            apiId=api_id, ttl=999999, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )

    code, message = _error(attempt)
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", (
        f"expected the exact out-of-range ttl message, got {message!r}"
    )

    # The rejected call must not have left a cache behind (independent read, a
    # different operation than the one that mutated).
    not_found_code, not_found_message = _error(lambda: svc.get_api_cache(apiId=api_id))
    assert not_found_code == "NotFoundException", (
        f"rejected CreateApiCache (ttl out of range) should not leave a cache behind, "
        f"got {not_found_code!r}"
    )
    assert not_found_message == "Unable to get the cache as it doesn't exist, please create the cache first.", (
        f"expected the exact missing-cache message, got {not_found_message!r}"
    )

    # Positive control: an in-range ttl on the identical apiId is accepted.
    created = svc.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    ctx.on_cleanup(lambda: _delete_cache_ignoring_not_found(svc, api_id))
    assert created["ttl"] == 300, created


def _delete_cache_ignoring_not_found(svc, api_id) -> None:
    """A cache still being created refuses DeleteApiCache; DeleteGraphqlApi (registered
    earlier, so it runs after this) removes the cache with its API in that case."""
    try:
        svc.delete_api_cache(apiId=api_id)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "NotFoundException":
            return
        if err.get("Code") == "BadRequestException" and err.get("Message") == (
            "Cannot delete cache as it is either not available or its creation failed."
        ):
            return
        raise

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
