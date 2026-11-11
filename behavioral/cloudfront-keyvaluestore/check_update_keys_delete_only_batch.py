"""update-keys-delete-only-batch."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-keys-delete-only-batch"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single UpdateKeys call with only Deletes (no Puts) removes every named key
    in one atomic step and leaves the untouched key alone."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    setup = dp.update_keys(
        KvsARN=arn,
        IfMatch=etag0,
        Puts=[
            {"Key": "keep", "Value": "stays"},
            {"Key": "drop-1", "Value": "gone-1"},
            {"Key": "drop-2", "Value": "gone-2"},
        ],
    )
    assert setup["ItemCount"] == 3, f"expected ItemCount 3 after seeding 3 keys, got {setup['ItemCount']}"

    resp = dp.update_keys(
        KvsARN=arn,
        IfMatch=setup["ETag"],
        Deletes=[{"Key": "drop-1"}, {"Key": "drop-2"}],
    )
    assert resp["ItemCount"] == 1, f"expected ItemCount 1 after deleting 2 of 3 keys, got {resp['ItemCount']}"

    kept = dp.get_key(KvsARN=arn, Key="keep")["Value"]
    assert kept == "stays", f"expected untouched key 'keep' to still hold 'stays', got {kept!r}"
    for gone in ("drop-1", "drop-2"):
        code, message = _error_code(lambda gone=gone: dp.get_key(KvsARN=arn, Key=gone))
        assert code == "ResourceNotFoundException", (
            f"expected GetKey({gone!r}) to fail with ResourceNotFoundException after the delete-only "
            f"batch, got {code!r}: {message!r}"
        )
        assert message == "No such Key exists", f"GetKey({gone!r}) returned message {message!r}"


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
