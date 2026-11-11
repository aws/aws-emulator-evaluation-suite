"""list-keys-reflects-zero-after-deleting-all-keys."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-keys-reflects-zero-after-deleting-all-keys"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """After every key in a store is deleted, ListKeys returns an empty Items list
    with no NextToken, and DescribeKeyValueStore agrees the store is empty."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    keys = ["empty-a", "empty-b", "empty-c"]
    setup = dp.update_keys(
        KvsARN=arn, IfMatch=etag0, Puts=[{"Key": k, "Value": "v"} for k in keys]
    )
    assert setup["ItemCount"] == 3, f"expected ItemCount 3 after seeding, got {setup['ItemCount']}"
    listed_before = dp.list_keys(KvsARN=arn)
    assert len(listed_before["Items"]) == 3, (
        f"expected 3 listed items after seeding, got {len(listed_before['Items'])}"
    )

    cleared = dp.update_keys(
        KvsARN=arn, IfMatch=setup["ETag"], Deletes=[{"Key": k} for k in keys]
    )
    assert cleared["ItemCount"] == 0, f"expected ItemCount 0 after clearing, got {cleared['ItemCount']}"

    listed_after = dp.list_keys(KvsARN=arn)
    assert listed_after["Items"] == [], f"expected no items after clearing, got {listed_after['Items']}"
    assert not listed_after.get("NextToken"), (
        f"expected no NextToken on an empty store, got {listed_after.get('NextToken')!r}"
    )

    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["ItemCount"] == 0, f"expected ItemCount 0, got {described['ItemCount']}"
    assert described["TotalSizeInBytes"] == 0, (
        f"expected TotalSizeInBytes 0, got {described['TotalSizeInBytes']}"
    )

    # the keys are dead, not merely absent from the listing: an independent
    # per-key read of each deleted key fails with the specific not-found code.
    for k in keys:
        err = _error(lambda k=k: dp.get_key(KvsARN=arn, Key=k))
        assert err == ("ResourceNotFoundException", "No such Key exists"), (
            f"expected ResourceNotFoundException reading deleted key {k!r}, got {err!r}"
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


def _error(fn):
    """(code, message) of the ClientError fn() raises; an AssertionError when it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
