"""put-key-empty-value-allowed."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-empty-value-allowed"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The Value shape declares no minimum length (unlike Key, which requires at
    least 1 byte): PutKey with an empty-string Value is accepted, GetKey returns it
    back as an empty string (not null/omitted), and it still counts as one item."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    resp = dp.put_key(KvsARN=arn, Key="empty-value-key", Value="", IfMatch=etag0)
    assert resp["ItemCount"] == 1, f"expected ItemCount 1 after PutKey with an empty Value, got {resp['ItemCount']!r}"

    got = dp.get_key(KvsARN=arn, Key="empty-value-key")
    assert got["Value"] == "", f"expected GetKey to return an empty string (not null/omitted), got {got['Value']!r}"
    assert got["ItemCount"] == 1, f"expected GetKey to report ItemCount 1 for the empty-value item, got {got['ItemCount']!r}"


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
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
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
