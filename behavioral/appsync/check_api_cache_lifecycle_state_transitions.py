"""api-cache-lifecycle-state-transitions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")

CHECK = "api-cache-lifecycle-state-transitions"
GROUP = 'api-cache'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new API cache is absent, then CREATING with its config echoed; deleting it while CREATING
    is refused, a state-machine guard an emulator can miss by allowing deletion from any state.
    """
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    # No cache exists yet.
    code, message = _error(lambda: svc.get_api_cache(apiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException before any cache exists, got {code}"
    assert message == (
        "Unable to get the cache as it doesn't exist, please create the cache first."
    ), message

    svc.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )

    cache = svc.get_api_cache(apiId=api_id)["apiCache"]
    assert cache["status"] in ("CREATING", "AVAILABLE"), cache
    assert cache["ttl"] == 300, cache
    assert cache["type"] == "SMALL", cache
    assert cache["apiCachingBehavior"] == "FULL_REQUEST_CACHING", cache

    # Provisioning to AVAILABLE takes several minutes, so only the CREATING transitions are graded.
    if cache["status"] == "CREATING":
        # Deletion is only legal from AVAILABLE.
        code, message = _error(lambda: svc.delete_api_cache(apiId=api_id))
        assert code == "BadRequestException", (
            f"expected BadRequestException deleting a CREATING cache, got {code}"
        )
        assert message == (
            "Cannot delete cache as it is either not available or its creation failed."
        ), message
        still = svc.get_api_cache(apiId=api_id)["apiCache"]
        assert still["status"] in ("CREATING", "AVAILABLE"), still
    else:
        svc.delete_api_cache(apiId=api_id)
        # message varies: this branch runs only when a cache is AVAILABLE straight after
        # CreateApiCache, which real AWS never does, so no message has been observed for it.
        code, _ = _error(lambda: svc.get_api_cache(apiId=api_id))
        assert code == "NotFoundException", f"expected NotFoundException after DeleteApiCache, got {code}"
        flush_code, _ = _error(lambda: svc.flush_api_cache(apiId=api_id))
        assert flush_code == "NotFoundException", (
            f"FlushApiCache on a deleted cache should 404, got {flush_code}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
