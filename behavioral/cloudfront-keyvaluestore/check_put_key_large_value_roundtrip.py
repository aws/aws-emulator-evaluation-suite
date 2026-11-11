"""put-key-large-value-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-large-value-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multi-kilobyte value is stored and returned byte-for-byte, and the store's
    reported size grows by at least the value's length."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    large_value = "0123456789abcdef" * 60  # 960 bytes, comfortably under the documented 1 KB value limit
    put_resp = dp.put_key(KvsARN=arn, Key="big", Value=large_value, IfMatch=etag0)
    assert put_resp["TotalSizeInBytes"] >= len(large_value), (
        f"expected TotalSizeInBytes >= {len(large_value)} after the put, got {put_resp['TotalSizeInBytes']}"
    )

    got = dp.get_key(KvsARN=arn, Key="big")
    assert got["Value"] == large_value, f"expected the 960-byte value back verbatim, got {got['Value']!r}"
    assert len(got["Value"]) == 960, f"expected 960 bytes back, got {len(got['Value'])}"

    # Independent side-channel (a different op than the mutating PutKey): the size
    # growth must be visible through DescribeKeyValueStore too, not just echoed back
    # by the call that wrote it.
    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["TotalSizeInBytes"] >= len(large_value), (
        f"expected DescribeKeyValueStore to independently report TotalSizeInBytes >= "
        f"{len(large_value)}, got {described['TotalSizeInBytes']}"
    )


def _wait_for_store_ready(ctx, name, timeout_s=180.0, interval_s=3.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        d = cf.describe_key_value_store(Name=name)
        status = d["KeyValueStore"]["Status"].upper()
        if status == "READY":
            return
        assert "FAIL" not in status, f"store entered a failure status: {status}"
        time.sleep(interval_s)
    raise AssertionError(f"store never reached READY within timeout, last status={status}")


def _create_ready_store(ctx):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")
    resp = cf.create_key_value_store(Name=name, Comment="sim2real behavioral check")
    arn = resp["KeyValueStore"]["ARN"]

    def _cleanup() -> None:
        d = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=d["ETag"])

    ctx.on_cleanup(_cleanup)
    _wait_for_store_ready(ctx, name)
    return {"name": name, "arn": arn}


def _dp_etag(dp, arn):
    return dp.describe_key_value_store(KvsARN=arn)["ETag"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
