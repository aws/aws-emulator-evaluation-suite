"""update-keys-multiple-puts-single-etag-bump."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-keys-multiple-puts-single-etag-bump"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single UpdateKeys call with several Puts creates every key and bumps the
    ETag exactly once (not once per item)."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    keys = [f"multi-{i}" for i in range(5)]
    puts = [{"Key": k, "Value": f"value-{k}"} for k in keys]
    resp = dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=puts)
    assert resp["ItemCount"] == 5, f"expected ItemCount 5 after a 5-item batch, got {resp['ItemCount']!r}"
    assert resp["ETag"] != etag0, f"ETag must move after the batch: still {etag0!r}"

    listed = dp.list_keys(KvsARN=arn, MaxResults=10)
    assert listed.get("NextToken") is None, (
        f"expected no NextToken for 5 items under MaxResults=10, got {listed.get('NextToken')!r}"
    )
    listed_keys = {item["Key"] for item in listed["Items"]}
    assert listed_keys == set(keys), f"expected ListKeys to return exactly {set(keys)!r}, got {listed_keys!r}"
    for k in keys:
        value = dp.get_key(KvsARN=arn, Key=k)["Value"]
        assert value == f"value-{k}", f"expected key {k!r} to hold {'value-' + k!r}, got {value!r}"

    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["ETag"] == resp["ETag"], (
        f"DescribeKeyValueStore must report the batch's ETag {resp['ETag']!r}, got {described['ETag']!r}"
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
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
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
