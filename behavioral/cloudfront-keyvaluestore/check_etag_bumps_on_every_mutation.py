"""etag-bumps-on-every-mutation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "etag-bumps-on-every-mutation"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every successful write (PutKey, PutKey, DeleteKey) advances the store's
    data-plane ETag to a new, distinct value, and DescribeKeyValueStore always
    reports the most recent one."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    etag0 = _dp_etag(dp, arn)
    put1 = dp.put_key(KvsARN=arn, Key="a", Value="1", IfMatch=etag0)
    etag1 = put1["ETag"]
    assert etag1 != etag0, f"PutKey('a') ETag ({etag1}) must differ from the pre-write ETag ({etag0})"

    put2 = dp.put_key(KvsARN=arn, Key="b", Value="2", IfMatch=etag1)
    etag2 = put2["ETag"]
    assert etag2 != etag1 and etag2 != etag0, (
        f"PutKey('b') ETag ({etag2}) must differ from both prior ETags ({etag1}, {etag0})"
    )

    del1 = dp.delete_key(KvsARN=arn, Key="a", IfMatch=etag2)
    etag3 = del1["ETag"]
    assert etag3 not in (etag0, etag1, etag2), (
        f"DeleteKey('a') ETag ({etag3}) must differ from every prior ETag {(etag0, etag1, etag2)}"
    )

    # the delete already happened above; the free negative is that it is gone via
    # an independent read, not just that the ETag moved.
    not_found = _error(lambda: dp.get_key(KvsARN=arn, Key="a"))
    assert not_found == ("ResourceNotFoundException", "No such Key exists"), (
        f"GetKey('a') after DeleteKey must fail with ResourceNotFoundException, got {not_found!r}"
    )

    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["ETag"] == etag3, (
        f"DescribeKeyValueStore ETag ({described['ETag']}) must equal the latest mutation's ETag ({etag3})"
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
        Tags={"Items": [{"Key": "sim2real", "Value": "behavioral-check"}]},
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
