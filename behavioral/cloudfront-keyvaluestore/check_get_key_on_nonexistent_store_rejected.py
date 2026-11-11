"""get-key-on-nonexistent-store-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-key-on-nonexistent-store-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetKey against a KvsARN that never existed is rejected with ResourceNotFoundException, the
    same code as a missing key in an existing store; GetKey against a Ready store succeeds."""
    sts = ctx.client("sts")
    real_account = sts.get_caller_identity()["Account"]
    made_up_arn = f"arn:aws:cloudfront::{real_account}:key-value-store/00000000-0000-0000-0000-000000000000"
    dp = ctx.client("cloudfront-keyvaluestore")

    # The account-scoped data-plane host (<account>.cloudfront-kvs.global.api.aws) does not
    # resolve in DNS for an account holding no KeyValueStore at all, so a real store must exist
    # before the made-up-ARN call below or that call fails with EndpointConnectionError instead
    # of being graded -- an account holding no KeyValueStore has none until this check creates
    # one. The host can also take longer than the store's own READY transition to become
    # resolvable, so wait for it to answer before grading anything.
    store = _create_ready_store(ctx)
    arn = store["arn"]
    _wait_for_dp_host_resolvable(dp, arn)

    got_err = _error(lambda: dp.get_key(KvsARN=made_up_arn, Key="anything"))
    assert got_err == ("ResourceNotFoundException", "No such Key-Value-Store exists"), (
        f"GetKey on a KvsARN that never existed: expected ResourceNotFoundException, got {got_err!r}"
    )

    # Positive control: the same call against a real, Ready store with a real key succeeds.
    etag0 = _dp_etag(dp, arn)
    dp.put_key(KvsARN=arn, Key="anything", Value="present", IfMatch=etag0)
    got = dp.get_key(KvsARN=arn, Key="anything")["Value"]
    assert got == "present", f"expected the positive-control GetKey to return 'present', got {got!r}"


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
        Tags={"Items": [{"Key": "sim2real-behav", "Value": CHECK}]},
    )
    arn = resp["KeyValueStore"]["ARN"]

    def _cleanup() -> None:
        d = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=d["ETag"])

    ctx.on_cleanup(_cleanup)
    _wait_for_store_ready(ctx, name)
    return {"name": name, "arn": arn}


def _wait_for_dp_host_resolvable(dp, arn, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import EndpointConnectionError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            dp.describe_key_value_store(KvsARN=arn)
            return
        except EndpointConnectionError as e:
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(
        f"cloudfront-keyvaluestore data-plane host never became reachable within "
        f"{timeout_s}s of the store reaching READY: {last_exc}"
    )


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
