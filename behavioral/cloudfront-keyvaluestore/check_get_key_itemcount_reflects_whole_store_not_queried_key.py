"""get-key-itemcount-reflects-whole-store-not-queried-key."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-key-itemcount-reflects-whole-store-not-queried-key"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetKey's ItemCount/TotalSizeInBytes describe the WHOLE store, not just the
    single key that was queried: in a 3-key store, GetKey on any one of them
    reports ItemCount == 3, not 1."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    keys = ["multi-a", "multi-b", "multi-c"]
    seed = dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=[{"Key": k, "Value": f"value-{k}"} for k in keys])
    assert seed["ItemCount"] == 3, f"expected ItemCount == 3 after seeding 3 keys, got {seed['ItemCount']}"

    for k in keys:
        got = dp.get_key(KvsARN=arn, Key=k)
        assert got["Value"] == f"value-{k}", f"GetKey({k}) expected Value 'value-{k}', got {got['Value']!r}"
        assert got["ItemCount"] == 3, f"GetKey({k}) should report the store's total ItemCount (3), not 1"
        assert got["TotalSizeInBytes"] == seed["TotalSizeInBytes"], (
            f"GetKey({k}) TotalSizeInBytes {got['TotalSizeInBytes']} != "
            f"UpdateKeys-reported {seed['TotalSizeInBytes']}"
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
