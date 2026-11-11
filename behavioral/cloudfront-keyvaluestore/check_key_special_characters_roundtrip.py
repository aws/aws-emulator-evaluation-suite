"""key-special-characters-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "key-special-characters-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Keys and values containing unicode, punctuation, quotes and newlines survive
    a PutKey/GetKey round trip unmangled (no re-encoding or truncation)."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    key = "unicode-key-\u65e5\u672c\u8a9e-\U0001f600"
    value = 'line1\nline2\t"quoted"\'s value \u2014 \u00e9\u00e8\u00e7 \U0001f680'

    put_resp = dp.put_key(KvsARN=arn, Key=key, Value=value, IfMatch=etag0)
    assert put_resp["ItemCount"] == 1, f"expected ItemCount 1 after first PutKey, got {put_resp['ItemCount']}"

    got = dp.get_key(KvsARN=arn, Key=key)
    assert got["Key"] == key, f"expected Key {key!r} back unmangled, got {got['Key']!r}"
    assert got["Value"] == value, f"expected Value {value!r} back unmangled, got {got['Value']!r}"


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
