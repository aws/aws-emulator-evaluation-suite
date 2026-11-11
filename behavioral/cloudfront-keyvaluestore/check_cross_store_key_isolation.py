"""cross-store-key-isolation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cross-store-key-isolation"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two independently-created key value stores are fully isolated: writing the
    SAME key name with different values in each store never leaks across the
    ARN boundary, and each store's ItemCount only counts its own keys."""
    store_a = _create_ready_store(ctx)
    store_b = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")

    etag_a = _dp_etag(dp, store_a["arn"])
    etag_b = _dp_etag(dp, store_b["arn"])

    dp.put_key(KvsARN=store_a["arn"], Key="shared-name", Value="value-in-a", IfMatch=etag_a)
    dp.put_key(KvsARN=store_b["arn"], Key="shared-name", Value="value-in-b", IfMatch=etag_b)

    got_a = dp.get_key(KvsARN=store_a["arn"], Key="shared-name")["Value"]
    got_b = dp.get_key(KvsARN=store_b["arn"], Key="shared-name")["Value"]
    assert got_a == "value-in-a", f"store A leaked cross-store value: expected 'value-in-a', got {got_a!r}"
    assert got_b == "value-in-b", f"store B leaked cross-store value: expected 'value-in-b', got {got_b!r}"

    desc_a = dp.describe_key_value_store(KvsARN=store_a["arn"])
    desc_b = dp.describe_key_value_store(KvsARN=store_b["arn"])
    assert desc_a["ItemCount"] == 1, f"store A ItemCount should count only its own key: expected 1, got {desc_a['ItemCount']}"
    assert desc_b["ItemCount"] == 1, f"store B ItemCount should count only its own key: expected 1, got {desc_b['ItemCount']}"
    # NOTE: ETags are versions of each store's own content/history, not globally
    # unique tokens -- two independently-created stores that each received exactly
    # one write can legitimately report the same ETag value. Isolation is verified
    # above via each store's own Get/ItemCount, not via ETag divergence.


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
