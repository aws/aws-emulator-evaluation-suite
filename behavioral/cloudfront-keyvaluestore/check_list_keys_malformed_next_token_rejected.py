"""list-keys-malformed-next-token-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-keys-malformed-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListKeys rejects a syntactically bogus NextToken with ValidationException
    rather than treating it as an empty/first page, and a real NextToken obtained
    from a previous ListKeys call still works on the same store."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    puts = [{"Key": f"tok-key-{i}", "Value": "v"} for i in range(3)]
    dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=puts)

    err = _error(lambda: dp.list_keys(KvsARN=arn, MaxResults=1, NextToken="not-a-real-token!!"))
    assert err == (
        "ValidationException",
        "Pagination token exception in operation 'ListKeys': decoding error; possible tampering detected",
    ), f"expected ValidationException for a malformed NextToken, got {err!r}"

    # Positive control: a real NextToken from an actual first page works.
    first_page = dp.list_keys(KvsARN=arn, MaxResults=1)
    assert len(first_page["Items"]) == 1, f"expected 1 item with MaxResults=1, got {len(first_page['Items'])}"
    real_token = first_page["NextToken"]
    assert real_token, "expected a NextToken when more items remain after the first page"
    second_page = dp.list_keys(KvsARN=arn, MaxResults=1, NextToken=real_token)
    assert len(second_page["Items"]) == 1, f"expected 1 item with MaxResults=1, got {len(second_page['Items'])}"
    assert second_page["Items"][0]["Key"] != first_page["Items"][0]["Key"], (
        "expected the second page to return a different key than the first"
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
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
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
