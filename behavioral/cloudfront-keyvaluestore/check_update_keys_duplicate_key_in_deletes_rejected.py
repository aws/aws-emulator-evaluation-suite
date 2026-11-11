"""update-keys-duplicate-key-in-deletes-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-keys-duplicate-key-in-deletes-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateKeys naming the same key twice in Deletes is rejected with ValidationException and
    applies nothing, while a Deletes list of distinct keys succeeds."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    seed = dp.update_keys(
        KvsARN=arn,
        IfMatch=etag0,
        Puts=[
            {"Key": "dup-target", "Value": "v1"},
            {"Key": "untouched", "Value": "v2"},
        ],
    )
    assert seed["ItemCount"] == 2, f"expected ItemCount 2 after seeding two puts, got {seed['ItemCount']}"

    err = _error(
        lambda: dp.update_keys(
            KvsARN=arn,
            IfMatch=seed["ETag"],
            Deletes=[{"Key": "dup-target"}, {"Key": "dup-target"}],
        )
    )
    assert err == (
        "ValidationException",
        "Validation error during update keys. Payload contains multiple updates for the same key.",
    ), f"expected ValidationException for a Deletes list with a repeated key, got {err!r}"

    # effect absent: the key must still exist, and the ETag must not have moved
    still_there = dp.get_key(KvsARN=arn, Key="dup-target")["Value"]
    assert still_there == "v1", f"expected 'dup-target' untouched by the rejected batch, got value {still_there!r}"
    etag_after_reject = _dp_etag(dp, arn)
    assert etag_after_reject == seed["ETag"], (
        f"expected ETag unchanged by the rejected batch, was {seed['ETag']} now {etag_after_reject}"
    )

    # positive control: a Deletes list with distinct keys succeeds
    resp = dp.update_keys(KvsARN=arn, IfMatch=seed["ETag"], Deletes=[{"Key": "dup-target"}])
    assert resp["ItemCount"] == 1, f"expected ItemCount 1 after deleting one of two keys, got {resp['ItemCount']}"
    not_found = _error(lambda: dp.get_key(KvsARN=arn, Key="dup-target"))
    assert not_found == ("ResourceNotFoundException", "No such Key exists"), (
        f"expected ResourceNotFoundException for the deleted key, got {not_found!r}"
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
