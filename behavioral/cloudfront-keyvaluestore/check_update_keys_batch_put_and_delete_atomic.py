"""update-keys-batch-put-and-delete-atomic."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-keys-batch-put-and-delete-atomic"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single UpdateKeys call applies a Puts+Deletes batch atomically: the deleted
    key disappears, the new key appears, an untouched key is unaffected, and the
    whole batch bumps the ETag exactly once."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    put_k1 = dp.put_key(KvsARN=arn, Key="k1", Value="v1", IfMatch=etag0)
    put_k2 = dp.put_key(KvsARN=arn, Key="k2", Value="v2", IfMatch=put_k1["ETag"])
    assert put_k2["ItemCount"] == 2, f"expected 2 items after seeding k1+k2, got {put_k2['ItemCount']}"

    batch = dp.update_keys(
        KvsARN=arn,
        IfMatch=put_k2["ETag"],
        Puts=[{"Key": "k3", "Value": "v3"}],
        Deletes=[{"Key": "k1"}],
    )
    assert batch["ItemCount"] == 2, "batch should have net zero change (one add, one remove)"
    assert batch["ETag"] != put_k2["ETag"], f"ETag must bump exactly once, still {put_k2['ETag']!r}"

    code, message = _error_code(lambda: dp.get_key(KvsARN=arn, Key="k1"))
    assert code == "ResourceNotFoundException", f"expected k1 gone after the batch, got {code!r}: {message!r}"
    assert message == "No such Key exists", f"GetKey on the deleted k1 returned message {message!r}"

    assert dp.get_key(KvsARN=arn, Key="k3")["Value"] == "v3", "k3 must be present with the value from the batch's Puts"
    assert dp.get_key(KvsARN=arn, Key="k2")["Value"] == "v2", "untouched key must survive the batch"

    # DeleteKey on the now-deleted key is an accepted no-op: nothing is resurrected or removed
    again = dp.delete_key(KvsARN=arn, Key="k1", IfMatch=batch["ETag"])
    assert again["ItemCount"] == 2, f"deleting an already-gone key must leave 2 items, got {again['ItemCount']}"


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
