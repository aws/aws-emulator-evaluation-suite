"""put-key-case-sensitive-distinct-keys."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-case-sensitive-distinct-keys"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Keys are compared case-sensitively: "Key1" and "key1" are two distinct
    entries, each independently retrievable, and the store's ItemCount counts
    them as two items, not one."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    resp = dp.update_keys(
        KvsARN=arn,
        IfMatch=etag0,
        Puts=[
            {"Key": "CaseKey", "Value": "upper-value"},
            {"Key": "casekey", "Value": "lower-value"},
        ],
    )
    assert resp["ItemCount"] == 2, "differently-cased keys must be treated as distinct entries"

    upper_value = dp.get_key(KvsARN=arn, Key="CaseKey")["Value"]
    assert upper_value == "upper-value", f"expected 'upper-value' for CaseKey, got {upper_value!r}"
    lower_value = dp.get_key(KvsARN=arn, Key="casekey")["Value"]
    assert lower_value == "lower-value", f"expected 'lower-value' for casekey, got {lower_value!r}"

    listed = dp.list_keys(KvsARN=arn, MaxResults=50)["Items"]
    listed_keys = {item["Key"] for item in listed}
    assert listed_keys == {"CaseKey", "casekey"}, f"expected both cased keys listed, got {listed_keys!r}"


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
    cf.tag_resource(Resource=arn, Tags={"Items": [{"Key": "sim2real", "Value": "true"}]})

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
