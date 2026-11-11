"""describe-key-value-store-tracks-item-count-and-size."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-key-value-store-tracks-item-count-and-size"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeKeyValueStore's ItemCount and TotalSizeInBytes accurately track the
    net effect of puts and deletes on the store's contents."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    baseline = dp.describe_key_value_store(KvsARN=arn)
    assert baseline["ItemCount"] == 0, f"expected a freshly-created store to have ItemCount 0, got {baseline['ItemCount']}"
    assert baseline["TotalSizeInBytes"] == 0, (
        f"expected a freshly-created store to have TotalSizeInBytes 0, got {baseline['TotalSizeInBytes']}"
    )

    etag = baseline["ETag"]
    put1 = dp.put_key(KvsARN=arn, Key="size-a", Value="v" * 100, IfMatch=etag)
    after_one = dp.describe_key_value_store(KvsARN=arn)
    assert after_one["ItemCount"] == 1, f"expected ItemCount 1 after one PutKey, got {after_one['ItemCount']}"
    assert after_one["TotalSizeInBytes"] > 0, (
        f"expected TotalSizeInBytes > 0 after one PutKey, got {after_one['TotalSizeInBytes']}"
    )
    size_after_one = after_one["TotalSizeInBytes"]

    put2 = dp.put_key(KvsARN=arn, Key="size-b", Value="v" * 200, IfMatch=put1["ETag"])
    after_two = dp.describe_key_value_store(KvsARN=arn)
    assert after_two["ItemCount"] == 2, f"expected ItemCount 2 after two PutKeys, got {after_two['ItemCount']}"
    assert after_two["TotalSizeInBytes"] > size_after_one, (
        f"expected TotalSizeInBytes to grow past {size_after_one} after a second, larger PutKey, "
        f"got {after_two['TotalSizeInBytes']}"
    )

    both_deleted = dp.update_keys(
        KvsARN=arn,
        IfMatch=put2["ETag"],
        Deletes=[{"Key": "size-a"}, {"Key": "size-b"}],
    )
    assert both_deleted["ItemCount"] == 0, (
        f"expected ItemCount 0 on UpdateKeys' own response after deleting both keys, "
        f"got {both_deleted['ItemCount']}"
    )
    assert both_deleted["TotalSizeInBytes"] == 0, (
        f"expected TotalSizeInBytes 0 on UpdateKeys' own response after deleting both keys, "
        f"got {both_deleted['TotalSizeInBytes']}"
    )
    final = dp.describe_key_value_store(KvsARN=arn)
    assert final["ItemCount"] == 0, (
        f"expected an independent DescribeKeyValueStore to report ItemCount 0 after both keys were "
        f"deleted, got {final['ItemCount']}"
    )
    assert final["TotalSizeInBytes"] == 0, (
        f"expected an independent DescribeKeyValueStore to report TotalSizeInBytes 0 after both keys "
        f"were deleted, got {final['TotalSizeInBytes']}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
