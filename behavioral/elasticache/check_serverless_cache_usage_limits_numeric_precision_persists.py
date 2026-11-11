"""serverless-cache-usage-limits-numeric-precision-persists."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "serverless-cache-usage-limits-numeric-precision-persists"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DataStorage and ECPUPerSecond usage-limit integers round-trip through
    create -> modify -> describe with no rounding or precision loss, and the
    cache this check deletes is provably gone and unusable afterward."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-sclimits-")

    create_limits = {
        "DataStorage": {"Minimum": 1, "Maximum": 12, "Unit": "GB"},
        "ECPUPerSecond": {"Minimum": 1000, "Maximum": 13000},
    }
    create_resp = ec.create_serverless_cache(
        ServerlessCacheName=name,
        Engine="redis",
        CacheUsageLimits=create_limits,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        SubnetIds=ctx.network().subnet_ids[:3],
    )
    ctx.on_cleanup(lambda: _delete_serverless_cache_safe(ec, name))

    limits = create_resp["ServerlessCache"]["CacheUsageLimits"]
    assert limits["DataStorage"]["Minimum"] == 1, limits
    assert limits["DataStorage"]["Maximum"] == 12, limits
    assert limits["DataStorage"]["Unit"] == "GB", limits
    assert limits["ECPUPerSecond"]["Minimum"] == 1000, limits
    assert limits["ECPUPerSecond"]["Maximum"] == 13000, limits

    _poll_until(
        lambda: ec.describe_serverless_caches(ServerlessCacheName=name)["ServerlessCaches"][0],
        lambda c: c.get("Status") == "available",
        timeout_s=900.0,
        interval_s=15.0,
    )

    modify_limits = {
        "DataStorage": {"Minimum": 2, "Maximum": 37, "Unit": "GB"},
        "ECPUPerSecond": {"Minimum": 2000, "Maximum": 42000},
    }
    ec.modify_serverless_cache(ServerlessCacheName=name, CacheUsageLimits=modify_limits)

    final = _poll_until(
        lambda: ec.describe_serverless_caches(ServerlessCacheName=name)["ServerlessCaches"][0],
        lambda c: (
            c.get("Status") == "available"
            and c.get("CacheUsageLimits", {}).get("DataStorage", {}).get("Maximum") == 37
        ),
        timeout_s=900.0,
        interval_s=15.0,
    )

    final_limits = final["CacheUsageLimits"]
    assert final_limits["DataStorage"]["Minimum"] == 2, final_limits
    assert final_limits["DataStorage"]["Maximum"] == 37, final_limits
    assert final_limits["DataStorage"]["Unit"] == "GB", final_limits
    assert final_limits["ECPUPerSecond"]["Minimum"] == 2000, final_limits
    assert final_limits["ECPUPerSecond"]["Maximum"] == 42000, final_limits

    # The cleanup delete is otherwise a free negative left unasserted: prove the cache is
    # gone by an independent read, and that a mutation on the dead id is specifically refused.
    _delete_and_wait_gone(ec, name)
    assert _describe_serverless_or_none(ec, name) is None, f"{name} still resolves after delete"
    _assert_not_found(
        lambda: ec.modify_serverless_cache(ServerlessCacheName=name, CacheUsageLimits=modify_limits),
        name,
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 900.0,
    interval_s: float = 15.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _describe_serverless_or_none(ec, name: str) -> Any:
    try:
        caches = ec.describe_serverless_caches(ServerlessCacheName=name)["ServerlessCaches"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ServerlessCacheNotFoundFault":
            return None
        raise
    return caches[0] if caches else None


def _delete_and_wait_gone(
    ec, name: str, timeout_s: float = 900.0, interval_s: float = 15.0
) -> None:
    ec.delete_serverless_cache(ServerlessCacheName=name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _describe_serverless_or_none(ec, name) is None:
            return
        time.sleep(interval_s)
    raise AssertionError(f"{name} did not disappear within {timeout_s}s of delete")


def _assert_not_found(fn: Callable[[], Any], name: str) -> None:
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ServerlessCacheNotFoundFault", (
            f"expected ServerlessCacheNotFoundFault for a mutation on deleted {name}, got {code}"
        )
        message = exc.response.get("Error", {}).get("Message")
        expected = f"Serverless cache with name {name} not found."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        return
    raise AssertionError(f"mutation on deleted {name} SUCCEEDED (should have been rejected)")


def _delete_serverless_cache_safe(ec, name: str) -> None:
    """Delete the cache, retrying while it is still in a state that refuses deletion."""
    deadline = time.monotonic() + 900.0
    while True:
        try:
            ec.delete_serverless_cache(ServerlessCacheName=name)
            return
        except ec.exceptions.ServerlessCacheNotFoundFault:
            return
        except ec.exceptions.InvalidServerlessCacheStateFault:
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
