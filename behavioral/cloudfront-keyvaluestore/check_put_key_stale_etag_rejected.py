"""put-key-stale-etag-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-stale-etag-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutKey with a superseded IfMatch ETag is rejected with ValidationException ("Pre-Condition
    failed during update of Key-Value-Store", not ConflictException) and the stale write never
    lands; a retry with the current ETag succeeds."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    put1 = dp.put_key(KvsARN=arn, Key="k", Value="v1", IfMatch=etag0)
    stale_etag = etag0  # etag0 is now superseded by put1["ETag"]

    code, msg = _error(lambda: dp.put_key(KvsARN=arn, Key="k", Value="should-not-apply", IfMatch=stale_etag))
    assert (code, msg) == ("ValidationException", "Pre-Condition failed during update of Key-Value-Store"), (
        f"{code}:{msg}"
    )

    # effect absent: the stale write must not have overwritten the value
    got_after_reject = dp.get_key(KvsARN=arn, Key="k")["Value"]
    assert got_after_reject == "v1", f"expected 'v1' (rejected write must not land), got {got_after_reject!r}"

    # positive control: the same op with the current ETag succeeds
    put2 = dp.put_key(KvsARN=arn, Key="k", Value="v2", IfMatch=put1["ETag"])
    assert put2["ItemCount"] == 1, f"expected ItemCount 1, got {put2['ItemCount']!r}"
    got_after_accept = dp.get_key(KvsARN=arn, Key="k")["Value"]
    assert got_after_accept == "v2", f"expected 'v2' (accepted write must land), got {got_after_accept!r}"


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
