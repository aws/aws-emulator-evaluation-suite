"""put-key-oversized-key-rejected-validation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-oversized-key-rejected-validation"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutKey enforces the documented Key size quota at the exact byte boundary
    (max 512 bytes): a 513-byte key is rejected with ServiceQuotaExceededException
    before it ever lands, while a key of exactly 512 bytes succeeds and round-trips."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    oversized_key = "k" * 513  # one byte past the documented 512-byte max
    code, msg = _error(lambda: dp.put_key(KvsARN=arn, Key=oversized_key, Value="v", IfMatch=etag0))
    assert (code, msg) == (
        "ServiceQuotaExceededException",
        "Limit exceeded: Maximum size of a key in a key value pair",
    ), f"{code}:{msg}"

    desc = dp.describe_key_value_store(KvsARN=arn)
    assert desc["ItemCount"] == 0, "an invalid PutKey must not have written anything"

    # Positive control: a key of exactly the documented max succeeds.
    valid_key = "k" * 512
    ok = dp.put_key(KvsARN=arn, Key=valid_key, Value="v", IfMatch=desc["ETag"])
    assert ok["ItemCount"] == 1, f"expected ItemCount 1 after one PutKey, got {ok['ItemCount']}"
    got = dp.get_key(KvsARN=arn, Key=valid_key)["Value"]
    assert got == "v", f"expected round-tripped Value 'v', got {got!r}"


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
