"""control-plane-etag-rejected-for-data-plane-put."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "control-plane-etag-rejected-for-data-plane-put"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The CloudFront DescribeKeyValueStore ETag is not the data-plane store's version token:
    using it as PutKey's IfMatch is rejected as a version mismatch, not accepted."""
    store = _create_ready_store(ctx)
    cf = ctx.client("cloudfront")
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    control_plane_etag = cf.describe_key_value_store(Name=store["name"])["ETag"]
    data_plane_etag = _dp_etag(dp, arn)
    assert control_plane_etag != data_plane_etag, "control-plane and data-plane ETags unexpectedly equal"

    err = _error(
        lambda: dp.put_key(KvsARN=arn, Key="cross-etag-key", Value="should-not-land", IfMatch=control_plane_etag)
    )
    assert err == ("ValidationException", "Pre-Condition failed during update of Key-Value-Store"), (
        f"expected ValidationException for cross-plane ETag, got {err!r}"
    )

    not_found = _error(lambda: dp.get_key(KvsARN=arn, Key="cross-etag-key"))
    assert not_found == ("ResourceNotFoundException", "No such Key exists"), (
        f"expected the rejected put to leave no key behind, got {not_found!r}"
    )

    # Positive control: the correct data-plane ETag is accepted.
    ok = dp.put_key(KvsARN=arn, Key="cross-etag-key", Value="landed", IfMatch=data_plane_etag)
    assert ok["ItemCount"] == 1, f"expected ItemCount == 1 after the positive-control put, got {ok['ItemCount']!r}"
    landed_value = dp.get_key(KvsARN=arn, Key="cross-etag-key")["Value"]
    assert landed_value == "landed", f"expected the positive-control value to land, got {landed_value!r}"


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
