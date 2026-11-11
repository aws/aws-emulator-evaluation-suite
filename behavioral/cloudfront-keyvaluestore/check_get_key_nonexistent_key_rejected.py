"""get-key-nonexistent-key-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-key-nonexistent-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetKey for a key that was never written to an existing, Ready store is
    rejected with ResourceNotFoundException, while GetKey for a key that really
    was put succeeds."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    err = _error(lambda: dp.get_key(KvsARN=arn, Key="never-written"))
    assert err == ("ResourceNotFoundException", "No such Key exists"), (
        f"expected ResourceNotFoundException for a never-written key, got {err!r}"
    )

    # positive control: a key that was actually put is retrievable
    etag0 = _dp_etag(dp, arn)
    dp.put_key(KvsARN=arn, Key="was-written", Value="present", IfMatch=etag0)
    got = dp.get_key(KvsARN=arn, Key="was-written")
    assert got["Value"] == "present", (
        f"expected the previously-put key to read back 'present', got {got.get('Value')!r}"
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
