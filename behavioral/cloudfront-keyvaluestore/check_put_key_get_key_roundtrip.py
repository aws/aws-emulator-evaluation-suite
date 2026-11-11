"""put-key-get-key-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-get-key-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutKey creates a key-value pair that GetKey then returns verbatim, and the
    store's ItemCount reflects the addition."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    etag = _dp_etag(dp, store["arn"])

    key, value = "greeting", "hello-world"
    put_resp = dp.put_key(KvsARN=store["arn"], Key=key, Value=value, IfMatch=etag)
    assert put_resp["ItemCount"] == 1, f"PutKey into a fresh store should report ItemCount 1, got {put_resp['ItemCount']!r}"
    assert put_resp["TotalSizeInBytes"] > 0, (
        f"PutKey should report a positive TotalSizeInBytes after storing a non-empty value, got {put_resp['TotalSizeInBytes']!r}"
    )

    got = dp.get_key(KvsARN=store["arn"], Key=key)
    assert got["Value"] == value, f"GetKey({key!r}) should return the value just PutKey wrote verbatim, got {got['Value']!r}"
    assert got["Key"] == key, f"GetKey({key!r}) should echo the requested key, got {got['Key']!r}"
    assert got["ItemCount"] == 1, f"GetKey should report the store's ItemCount (1), got {got['ItemCount']!r}"


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
    resp = cf.create_key_value_store(
        Name=name,
        Comment="sim2real behavioral check",
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
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
