"""update-keys-batch-exceeding-max-items-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-keys-batch-exceeding-max-items-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateKeys caps a single batch at 50 key-value pairs. A batch of 51 Puts is
    rejected wholesale (ServiceQuotaExceededException; nothing is written), while a
    batch of exactly 50 succeeds."""
    _ensure_awscrt()
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    too_many = [{"Key": f"overflow-key-{i:03d}", "Value": f"v{i}"} for i in range(51)]
    code, msg = _error_code(lambda: dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=too_many))
    assert code == "ServiceQuotaExceededException", f"{code}:{msg}"
    expected_message = "Limit exceeded: Maximum key values pairs that you can update in a single API request"
    assert msg == expected_message, f"expected message {expected_message!r}, got {msg!r}"

    desc = dp.describe_key_value_store(KvsARN=arn)
    assert desc["ItemCount"] == 0, "an over-the-limit batch must not partially apply"
    assert desc["ETag"] == etag0, "a rejected batch must not bump the store's version"

    # Positive control: a batch at exactly the 50-item limit succeeds in full.
    exactly_at_limit = [{"Key": f"boundary-key-{i:03d}", "Value": f"v{i}"} for i in range(50)]
    ok = dp.update_keys(KvsARN=arn, IfMatch=desc["ETag"], Puts=exactly_at_limit)
    assert ok["ItemCount"] == 50, f"expected 50 items after the boundary batch, got {ok['ItemCount']}"

    # Independent reads at the destination, through operations other than the mutating UpdateKeys.
    final = dp.describe_key_value_store(KvsARN=arn)
    assert final["ItemCount"] == 50, (
        f"describe_key_value_store reports {final['ItemCount']} items after the boundary batch, expected 50"
    )
    first_val = dp.get_key(KvsARN=arn, Key="boundary-key-000")["Value"]
    assert first_val == "v0", f"boundary-key-000 should read back 'v0', got {first_val!r}"
    last_val = dp.get_key(KvsARN=arn, Key="boundary-key-049")["Value"]
    assert last_val == "v49", f"boundary-key-049 should read back 'v49', got {last_val!r}"


def _ensure_awscrt() -> None:
    """SigV4A signing for this data plane needs awscrt; without it the runner lacks a dependency."""
    from botocore.compat import HAS_CRT

    if not HAS_CRT:
        from fidelity_tests_runner import RequiredToolMissing

        raise RequiredToolMissing(["awscrt"])


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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
