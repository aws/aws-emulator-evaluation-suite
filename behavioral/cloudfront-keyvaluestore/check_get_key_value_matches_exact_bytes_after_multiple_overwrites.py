"""get-key-value-matches-exact-bytes-after-multiple-overwrites."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-key-value-matches-exact-bytes-after-multiple-overwrites"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A chain of overwrites on the same key (each using the previous response's
    ETag) never leaves stale data visible: ItemCount stays at 1 throughout, and the
    final GetKey reflects only the last write."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag = _dp_etag(dp, arn)

    versions = ["v1-initial", "v2-updated", "v3-final"]
    for value in versions:
        put_resp = dp.put_key(KvsARN=arn, Key="chain", Value=value, IfMatch=etag)
        assert put_resp["ItemCount"] == 1, f"expected ItemCount 1 after overwrite, got {put_resp['ItemCount']}"
        etag = put_resp["ETag"]
        got_value = dp.get_key(KvsARN=arn, Key="chain")["Value"]
        assert got_value == value, f"expected GetKey to reflect just-written {value!r}, got {got_value!r}"

    final = dp.get_key(KvsARN=arn, Key="chain")
    assert final["Value"] == versions[-1], f"expected final Value {versions[-1]!r}, got {final['Value']!r}"
    assert final["ItemCount"] == 1, f"expected final ItemCount 1, got {final['ItemCount']}"


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
