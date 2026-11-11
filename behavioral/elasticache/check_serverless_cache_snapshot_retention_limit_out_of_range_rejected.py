"""serverless-cache-snapshot-retention-limit-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "serverless-cache-snapshot-retention-limit-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticache"]


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyServerlessCache with SnapshotRetentionLimit=36 is rejected with InvalidParameterValue and the
    exact 0-35 range message, leaving the limit at 1, while a later limit of 5 is applied."""
    ec = ctx.client("elasticache")
    cache_name = ctx.unique_name("sim2real-slcretlim-")
    ec.create_serverless_cache(
        ServerlessCacheName=cache_name,
        Engine="redis",
        SnapshotRetentionLimit=1,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        SubnetIds=ctx.network().subnet_ids[:3],
    )
    ctx.on_cleanup(lambda: ec.delete_serverless_cache(ServerlessCacheName=cache_name))
    _wait_serverless_status(ec, cache_name, "available", timeout_s=900)

    code, message = _error(
        lambda: ec.modify_serverless_cache(ServerlessCacheName=cache_name, SnapshotRetentionLimit=36)
    )
    assert code == "InvalidParameterValue", (
        f"out-of-range SnapshotRetentionLimit=36 failed with {code!r}, expected 'InvalidParameterValue'"
    )
    expected_message = (
        "Invalid snapshot retention limit: 36. Snapshot retention limit must be between 0 and 35."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = ec.describe_serverless_caches(ServerlessCacheName=cache_name)["ServerlessCaches"][0]
    assert unchanged["SnapshotRetentionLimit"] == 1, (
        f"SnapshotRetentionLimit changed to {unchanged['SnapshotRetentionLimit']!r} after a rejected "
        "out-of-range update, expected it to stay 1"
    )

    # Positive control: a valid retention-limit update on the same cache still works.
    ec.modify_serverless_cache(ServerlessCacheName=cache_name, SnapshotRetentionLimit=5)
    final = _wait_serverless_field(ec, cache_name, "SnapshotRetentionLimit", 5, timeout_s=300)
    assert final["SnapshotRetentionLimit"] == 5, (
        f"positive-control ModifyServerlessCache left SnapshotRetentionLimit at {final['SnapshotRetentionLimit']!r}, expected 5"
    )


def _wait_serverless_status(ec, cache_name, target_status, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        caches = ec.describe_serverless_caches(ServerlessCacheName=cache_name)["ServerlessCaches"]
        if caches and caches[0]["Status"] == target_status:
            return caches[0]
        time.sleep(interval_s)
    raise AssertionError(f"serverless cache {cache_name} never reached status {target_status!r} within {timeout_s}s")


def _wait_serverless_field(ec, cache_name, field, target_value, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        caches = ec.describe_serverless_caches(ServerlessCacheName=cache_name)["ServerlessCaches"]
        if caches and caches[0].get(field) == target_value and caches[0]["Status"] == "available":
            return caches[0]
        time.sleep(interval_s)
    raise AssertionError(f"serverless cache {cache_name} field {field} never became {target_value!r} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
