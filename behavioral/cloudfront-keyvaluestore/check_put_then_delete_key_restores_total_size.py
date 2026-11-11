"""put-then-delete-key-restores-total-size."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-then-delete-key-restores-total-size"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After PutKey then DeleteKey, DescribeKeyValueStore shows TotalSizeInBytes and ItemCount back
    at their exact pre-put values; a second delete of the absent key is a no-op and it stays gone."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    baseline = dp.describe_key_value_store(KvsARN=arn)
    baseline_count = baseline["ItemCount"]
    baseline_size = baseline["TotalSizeInBytes"]
    assert baseline_count == 0, f"expected an empty store, got ItemCount={baseline_count}"
    assert baseline_size == 0, f"expected an empty store, got TotalSizeInBytes={baseline_size}"

    put = dp.put_key(KvsARN=arn, Key="grows-then-shrinks", Value="v" * 777, IfMatch=baseline["ETag"])
    grown = dp.describe_key_value_store(KvsARN=arn)
    assert grown["ItemCount"] == baseline_count + 1, (
        f"expected ItemCount {baseline_count + 1}, got {grown['ItemCount']}"
    )
    assert grown["TotalSizeInBytes"] > baseline_size, (
        f"expected TotalSizeInBytes to grow past {baseline_size}, got {grown['TotalSizeInBytes']}"
    )

    dp.delete_key(KvsARN=arn, Key="grows-then-shrinks", IfMatch=put["ETag"])

    not_found, not_found_message = _error_code(lambda: dp.get_key(KvsARN=arn, Key="grows-then-shrinks"))
    assert not_found == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {not_found}"
    expected_message = "No such Key exists"
    assert not_found_message == expected_message, (
        f"expected message {expected_message!r}, got {not_found_message!r}"
    )

    # a second DeleteKey of the absent key is an idempotent no-op: it succeeds,
    # reports the unchanged counters, and the key stays gone.
    current_etag = _dp_etag(dp, arn)
    redelete = dp.delete_key(KvsARN=arn, Key="grows-then-shrinks", IfMatch=current_etag)
    assert redelete["ItemCount"] == baseline_count, (
        f"expected the no-op delete to report ItemCount {baseline_count}, got {redelete['ItemCount']}"
    )
    assert redelete["TotalSizeInBytes"] == baseline_size, (
        f"expected the no-op delete to report TotalSizeInBytes {baseline_size}, got {redelete['TotalSizeInBytes']}"
    )
    still_gone, still_gone_message = _error_code(lambda: dp.get_key(KvsARN=arn, Key="grows-then-shrinks"))
    assert still_gone == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {still_gone}"
    assert still_gone_message == expected_message, (
        f"expected message {expected_message!r}, got {still_gone_message!r}"
    )

    # terminal, independent read: the failed redelete left counters untouched, and
    # they sit at the exact pre-put baseline, not merely back to zero by coincidence.
    restored = dp.describe_key_value_store(KvsARN=arn)
    assert restored["ItemCount"] == baseline_count, (
        f"expected ItemCount to return to {baseline_count}, got {restored['ItemCount']}"
    )
    assert restored["TotalSizeInBytes"] == baseline_size, (
        f"expected TotalSizeInBytes to return to exactly {baseline_size}, got {restored['TotalSizeInBytes']}"
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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
