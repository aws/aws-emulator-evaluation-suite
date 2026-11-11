"""list-keys-maxresults-out-of-range-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-keys-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListKeys' MaxResults is constrained to the range 1-50: a value above the
    maximum is rejected, while the maximum valid value (50) succeeds."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=[{"Key": "k", "Value": "v"}])

    # botocore's client-side parameter validator would otherwise block this locally
    # (it enforces MaxResults' modeled range of 1-50 before any request is sent);
    # disable it via ctx.client's config override so the malformed request reaches
    # the service while still carrying the target's credentials — a bare
    # boto3.client() with no explicit creds resolves the ambient chain instead.
    from botocore.config import Config
    from botocore.exceptions import ClientError

    unchecked = ctx.client("cloudfront-keyvaluestore", config=Config(parameter_validation=False))
    try:
        unchecked.list_keys(KvsARN=arn, MaxResults=51)
        code, msg = None, None
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"].get("Message")
    assert (code, msg) == (
        "ValidationException",
        "1 validation error detected: Value '51' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 50",
    ), f"{code}:{msg}"

    # Positive control: the maximum valid value (50) is accepted.
    resp = dp.list_keys(KvsARN=arn, MaxResults=50)
    assert len(resp["Items"]) == 1


# ===== helpers =====
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
        Tags={
            "Items": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real:check", "Value": CHECK},
            ]
        },
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

