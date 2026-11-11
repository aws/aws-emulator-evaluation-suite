"""create-serverless-cache-usage-limit-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-serverless-cache-usage-limit-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateServerlessCache with a usage limit below the documented minimum (e.g. a
    negative DataStorage.Maximum) is rejected outright, not silently clamped to 0/None."""
    ec = ctx.client("elasticache")
    bad_name = ctx.unique_name("sim2real-ecsl-bad-")

    code, message = _error(
        lambda: ec.create_serverless_cache(
            ServerlessCacheName=bad_name,
            Engine="redis",
            CacheUsageLimits={"DataStorage": {"Maximum": -5, "Unit": "GB"}},
            SubnetIds=ctx.network().subnet_ids[:3],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == (
        "Invalid value for DataStorage limit. Must be between 1 and 5000. "
        "You can set the value to zero to remove the limit."
    ), message

    # The rejected cache must not have been created (not silently clamped).
    not_found_code, not_found_message = _error(
        lambda: ec.describe_serverless_caches(ServerlessCacheName=bad_name)
    )
    assert not_found_code == "ServerlessCacheNotFoundFault", (
        f"expected ServerlessCacheNotFoundFault, got {not_found_code}"
    )
    assert not_found_message == f"Serverless cache with name {bad_name} not found.", not_found_message

    # Positive control: the SAME shape of call (CacheUsageLimits.DataStorage.Maximum), but
    # with an in-range value, succeeds. This is what tells "rejects an out-of-range usage
    # limit" apart from "rejects CacheUsageLimits altogether" -- a target that refused every
    # CacheUsageLimits, valid or not, would still pass a bare no-limits control.
    good_name = ctx.unique_name("sim2real-ecsl-ok-")
    ec.create_serverless_cache(
        ServerlessCacheName=good_name,
        Engine="redis",
        CacheUsageLimits={"DataStorage": {"Maximum": 10, "Unit": "GB"}},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        SubnetIds=ctx.network().subnet_ids[:3],
    )
    ctx.on_cleanup(lambda: ec.delete_serverless_cache(ServerlessCacheName=good_name))

    cache = _poll_until(
        lambda: ec.describe_serverless_caches(ServerlessCacheName=good_name)[
            "ServerlessCaches"
        ][0],
        lambda c: c["Status"] in ("available", "create-failed"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert cache["Status"] == "available", f"serverless cache ended in {cache['Status']}"
    applied_max = cache.get("CacheUsageLimits", {}).get("DataStorage", {}).get("Maximum")
    assert applied_max == 10, (
        f"in-range DataStorage.Maximum=10 did not persist, got {applied_max!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error (Code, Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
