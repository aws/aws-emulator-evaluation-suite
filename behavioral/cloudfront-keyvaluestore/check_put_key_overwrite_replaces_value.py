"""put-key-overwrite-replaces-value."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-overwrite-replaces-value"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second PutKey on the same key replaces its value (no duplicate item created)."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    put1 = dp.put_key(KvsARN=arn, Key="k", Value="v1", IfMatch=etag0)
    assert put1["ItemCount"] == 1, f"expected ItemCount 1 after first PutKey, got {put1['ItemCount']!r}"
    first = dp.get_key(KvsARN=arn, Key="k")
    assert first["Value"] == "v1", f"expected first GetKey to return 'v1', got {first['Value']!r}"

    put2 = dp.put_key(KvsARN=arn, Key="k", Value="v2", IfMatch=put1["ETag"])
    assert put2["ItemCount"] == 1, "overwriting an existing key must not change ItemCount"

    got = dp.get_key(KvsARN=arn, Key="k")
    assert got["Value"] == "v2", f"expected overwritten GetKey to return 'v2', got {got['Value']!r}"


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
