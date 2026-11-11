"""create-serverless-cache-conflicting-name-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-serverless-cache-conflicting-name-rejected"
GROUP = "negative-classes"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateServerlessCache with an existing name is rejected (ServerlessCacheAlreadyExistsFault)
    without touching the existing cache, and the identical call succeeds once that cache is
    deleted, so the rejection is scoped to the name collision."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-ec-slc-conflict-")
    ec.create_serverless_cache(ServerlessCacheName=name, Engine="redis", SubnetIds=ctx.network().subnet_ids[:3])
    ctx.on_cleanup(lambda: _delete_serverless_cache_if_present(ctx, name))
    cache = _wait_serverless_cache_available(ctx, name)
    original_create_time = cache["CreateTime"]

    code, message = _error(lambda: ec.create_serverless_cache(ServerlessCacheName=name, Engine="redis", SubnetIds=ctx.network().subnet_ids[:3]))
    assert code == "ServerlessCacheAlreadyExistsFault", f"expected conflict error, got {code!r}"
    assert message == "Serverless Cache already exists", message

    # Effect absent: there is still exactly one cache under this name, unmodified.
    caches = ec.describe_serverless_caches(ServerlessCacheName=name)["ServerlessCaches"]
    assert len(caches) == 1, f"expected exactly one cache, found {len(caches)}"
    assert caches[0]["CreateTime"] == original_create_time, "the existing cache was overwritten"

    # Restore: remove the state that forbade creation, then demand the identical call now
    # succeeds -- this is a name collision being enforced, not every CreateServerlessCache
    # call under this name being refused.
    ec.delete_serverless_cache(ServerlessCacheName=name)
    _wait_serverless_cache_deleted(ctx, name)
    gone_code, gone_message = _error(lambda: ec.describe_serverless_caches(ServerlessCacheName=name))
    assert gone_code == "ServerlessCacheNotFoundFault", f"expected the cache gone, got {gone_code!r}"
    assert gone_message == f"Serverless cache with name {name} not found.", gone_message

    ec.create_serverless_cache(ServerlessCacheName=name, Engine="redis", SubnetIds=ctx.network().subnet_ids[:3])
    restored_cache = _wait_serverless_cache_available(ctx, name)
    assert restored_cache["ServerlessCacheName"] == name, (
        f"expected the restored cache to be named {name!r}, got {restored_cache['ServerlessCacheName']!r}"
    )
    assert restored_cache["CreateTime"] != original_create_time, (
        "expected a freshly created cache with a new CreateTime, not the deleted one"
    )

    # Positive control: a distinct name succeeds normally.
    other_name = ctx.unique_name("sim2real-ec-slc-other-")
    ec.create_serverless_cache(ServerlessCacheName=other_name, Engine="redis", SubnetIds=ctx.network().subnet_ids[:3])
    ctx.on_cleanup(lambda: _delete_serverless_cache_if_present(ctx, other_name))
    other_cache = _wait_serverless_cache_available(ctx, other_name)
    assert other_cache["ServerlessCacheName"] == other_name, (
        f"expected {other_name!r}, got {other_cache['ServerlessCacheName']!r}"
    )


# ===== helpers =====


def _wait_serverless_cache_available(ctx: Any, name: str, timeout_s: float = 900.0) -> dict:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        caches = ec.describe_serverless_caches(ServerlessCacheName=name)["ServerlessCaches"]
        last = caches[0] if caches else None
        if last and last["Status"] == "available":
            return last
        time.sleep(2)
    raise AssertionError(f"serverless cache {name} never reached available, last={last}")


def _wait_serverless_cache_deleted(ctx: Any, name: str, timeout_s: float = 900.0) -> None:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ec.describe_serverless_caches(ServerlessCacheName=name)
        except ec.exceptions.ServerlessCacheNotFoundFault:
            return
        time.sleep(2)
    raise AssertionError(f"serverless cache {name} was not deleted within {timeout_s}s")


def _delete_serverless_cache_if_present(ctx: Any, name: str) -> None:
    """Delete the cache and wait until it is gone; a cache still creating is retried.

    Both caches' teardowns share the 1800 s cleanup budget, so each is bounded by 840 s."""
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + 840.0
    while True:
        try:
            ec.delete_serverless_cache(ServerlessCacheName=name)
            break
        except ec.exceptions.ServerlessCacheNotFoundFault:
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidServerlessCacheStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_serverless_cache_deleted(ctx, name, timeout_s=max(deadline - time.monotonic(), 0.0))


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
