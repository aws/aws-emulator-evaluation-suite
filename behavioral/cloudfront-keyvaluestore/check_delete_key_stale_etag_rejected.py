"""delete-key-stale-etag-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-key-stale-etag-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteKey with a superseded IfMatch ETag is rejected with ValidationException (not
    ConflictException) and leaves the key in place; a retry with the current ETag succeeds."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    put1 = dp.put_key(KvsARN=arn, Key="k", Value="v1", IfMatch=etag0)
    stale_etag = put1["ETag"]
    # make put1["ETag"] stale by writing a second key
    put2 = dp.put_key(KvsARN=arn, Key="k2", Value="v2", IfMatch=stale_etag)

    err = _error(lambda: dp.delete_key(KvsARN=arn, Key="k", IfMatch=stale_etag))
    assert err == ("ValidationException", "Pre-Condition failed during update of Key-Value-Store"), err

    # effect absent: key "k" must still exist
    assert dp.get_key(KvsARN=arn, Key="k")["Value"] == "v1"

    # positive control: delete with the current ETag succeeds
    dp.delete_key(KvsARN=arn, Key="k", IfMatch=put2["ETag"])
    not_found = _error(lambda: dp.get_key(KvsARN=arn, Key="k"))
    assert not_found == ("ResourceNotFoundException", "No such Key exists"), not_found


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
