"""update-keys-exceeding-value-quota-in-batch-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-keys-exceeding-value-quota-in-batch-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateKeys' all-or-nothing guarantee extends to per-value quota violations:
    a batch where every Put is valid except one oversized value is rejected in
    full (ServiceQuotaExceededException), and NONE of the otherwise-valid Puts land."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    batch = [
        {"Key": "batch-ok-1", "Value": "fine"},
        {"Key": "batch-ok-2", "Value": "also-fine"},
        {"Key": "batch-too-big", "Value": "x" * 4096},
    ]
    code, message = _error_code(lambda: dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=batch))
    assert code == "ServiceQuotaExceededException", (code, message)
    assert message == "Limit exceeded: Maximum size of the value in a key value pair", message

    desc = dp.describe_key_value_store(KvsARN=arn)
    assert desc["ItemCount"] == 0, "none of the batch's otherwise-valid Puts should have landed"
    assert desc["ETag"] == etag0, f"a rejected batch must not bump the store's version: {desc['ETag']!r} != {etag0!r}"

    # Independent read confirming absence: batch-ok-1 was never gettable, even
    # though it was itself a valid Put -- the oversized sibling doomed the whole batch.
    nf_code, nf_message = _error_code(lambda: dp.get_key(KvsARN=arn, Key="batch-ok-1"))
    assert nf_code == "ResourceNotFoundException", (nf_code, nf_message)
    assert nf_message == "No such Key exists", nf_message

    # Positive control: the same batch minus the oversized entry succeeds in full.
    ok = dp.update_keys(
        KvsARN=arn,
        IfMatch=etag0,
        Puts=[{"Key": "batch-ok-1", "Value": "fine"}, {"Key": "batch-ok-2", "Value": "also-fine"}],
    )
    assert ok["ItemCount"] == 2, f"expected 2 items after the positive-control batch, got {ok['ItemCount']}"

    # Terminal assertion: an independent read at the destination, through a different operation than
    # the one that wrote it.
    got1 = dp.get_key(KvsARN=arn, Key="batch-ok-1")["Value"]
    assert got1 == "fine", got1
    got2 = dp.get_key(KvsARN=arn, Key="batch-ok-2")["Value"]
    assert got2 == "also-fine", got2
    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["ItemCount"] == 2, f"describe should independently confirm 2 items, got {described['ItemCount']}"


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


def _error_code(fn):
    """Return (code, message) for the ClientError ``fn`` raises. An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
