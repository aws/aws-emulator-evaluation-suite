"""describe-key-value-store-created-stable-last-modified-advances."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-key-value-store-created-stable-last-modified-advances"
GROUP = "state"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The data-plane DescribeKeyValueStore's Created timestamp never changes across
    writes (it is the store's creation time), while LastModified advances to
    reflect each write -- the two fields track genuinely different things."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    baseline = dp.describe_key_value_store(KvsARN=arn)
    created = baseline["Created"]

    dp.put_key(KvsARN=arn, Key="touch-1", Value="v1", IfMatch=baseline["ETag"])
    after_one = dp.describe_key_value_store(KvsARN=arn)
    assert after_one["Created"] == created, "Created must not change across writes"
    last_modified_1 = after_one.get("LastModified")
    assert last_modified_1 is not None, "LastModified should be populated after a write"

    dp.put_key(KvsARN=arn, Key="touch-2", Value="v2", IfMatch=after_one["ETag"])

    deadline = time.monotonic() + 30.0
    after_two = None
    while time.monotonic() < deadline:
        after_two = dp.describe_key_value_store(KvsARN=arn)
        assert after_two["Created"] == created, "Created must remain stable across further writes"
        if after_two["LastModified"] > last_modified_1:
            break
        time.sleep(2.0)
    else:
        raise AssertionError(
            f"LastModified never advanced past {last_modified_1} within 30s, "
            f"last seen {after_two['LastModified'] if after_two else None}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
