"""update-api-cache-invalid-ttl-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-api-cache-invalid-ttl-rejected"
GROUP = "state-machine"
SERVICES = ["appsync"]

# A SMALL ApiCache takes several minutes to leave CREATING on real AWS, so the poll's own bound is
# 600s and a poll that closes without AVAILABLE raises.
_AVAILABLE_TIMEOUT_S = 600.0
_AVAILABLE_POLL_S = 2.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateApiCache with an out-of-range ttl on an AVAILABLE cache fails with BadRequestException
    and leaves the cache unchanged, while a valid-ttl update on the same cache succeeds.
    """
    appsync = ctx.client("appsync")
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-cache-updttl-"),
        authenticationType="API_KEY",
        tags={"sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, api_id))

    created = appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    ctx.on_cleanup(lambda: _safe_delete_api_cache(appsync, api_id))
    assert created["ttl"] == 300

    available = _wait_status(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"], {"AVAILABLE", "FAILED"}
    )
    assert available["status"] == "AVAILABLE", (
        f"api cache never reached AVAILABLE (status={available['status']!r}); cannot isolate "
        "the ttl-bounds rejection from AppSync's own not-yet-available rejection"
    )

    # Positive control: UpdateApiCache with a VALID ttl must succeed, so the ttl=0 rejection
    # below cannot be mistaken for "UpdateApiCache rejects everything regardless of ttl".
    updated = appsync.update_api_cache(
        apiId=api_id, ttl=600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    assert updated["ttl"] == 600, f"positive-control UpdateApiCache did not take effect: {updated}"
    confirmed = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert confirmed["ttl"] == 600, confirmed

    # ttl=0 is below the documented 1-3600 second range.
    code, message = _error(
        lambda: appsync.update_api_cache(
            apiId=api_id, ttl=0, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for ttl=0 (min is 1), got {code!r}"
    )
    assert message == (
        "TTL value cannot be smaller than 1 second and larger than 3600 seconds."
    ), message

    # A rejected UpdateApiCache must not have partially mutated the existing cache.
    still = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert still["ttl"] == 600, (
        f"rejected UpdateApiCache mutated ttl anyway: expected 600, got {still['ttl']}"
    )
    assert still["apiCachingBehavior"] == "FULL_REQUEST_CACHING"


# ===== helpers =====
def _safe_delete_graphql_api(appsync, api_id) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.delete_graphql_api(apiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_api_cache(appsync, api_id) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.delete_api_cache(apiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _wait_status(probe, terminal_statuses):
    deadline = time.monotonic() + _AVAILABLE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last.get("status") in terminal_statuses:
            return last
        time.sleep(_AVAILABLE_POLL_S)
    raise AssertionError(f"never reached {terminal_statuses} within {_AVAILABLE_TIMEOUT_S}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
