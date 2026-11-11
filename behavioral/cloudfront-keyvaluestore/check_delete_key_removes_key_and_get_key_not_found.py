"""delete-key-removes-key-and-get-key-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-key-removes-key-and-get-key-not-found"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteKey removes the key: ItemCount drops and GetKey returns ResourceNotFoundException; a
    second DeleteKey of the same key succeeds as a no-op, and a fresh PutKey under the name succeeds."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    put_resp = dp.put_key(KvsARN=arn, Key="ephemeral", Value="soon-gone", IfMatch=etag0)
    assert put_resp["ItemCount"] == 1, f"expected ItemCount 1 after PutKey, got {put_resp['ItemCount']}"
    got = dp.get_key(KvsARN=arn, Key="ephemeral")["Value"]
    assert got == "soon-gone", f"expected 'soon-gone' before delete, got {got!r}"

    del_resp = dp.delete_key(KvsARN=arn, Key="ephemeral", IfMatch=put_resp["ETag"])
    assert del_resp["ItemCount"] == 0, f"expected ItemCount 0 after DeleteKey, got {del_resp['ItemCount']}"

    err = _error(lambda: dp.get_key(KvsARN=arn, Key="ephemeral"))
    assert err == ("ResourceNotFoundException", "No such Key exists"), (
        f"expected ResourceNotFoundException from GetKey on the deleted key, got {err!r}"
    )

    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["ItemCount"] == 0, f"expected store ItemCount 0, got {described['ItemCount']}"

    # idempotent: a second DeleteKey on the now-dead key succeeds as a no-op, not an error
    redel_resp = dp.delete_key(KvsARN=arn, Key="ephemeral", IfMatch=del_resp["ETag"])
    assert redel_resp["ItemCount"] == 0, f"expected ItemCount to stay 0 on a repeat DeleteKey, got {redel_resp['ItemCount']}"

    # reusable: the identifier can be put again and behaves as a normal fresh key
    reput_resp = dp.put_key(KvsARN=arn, Key="ephemeral", Value="back-again", IfMatch=redel_resp["ETag"])
    assert reput_resp["ItemCount"] == 1, f"expected ItemCount 1 after reusing the identifier, got {reput_resp['ItemCount']}"
    reget = dp.get_key(KvsARN=arn, Key="ephemeral")["Value"]
    assert reget == "back-again", f"expected 'back-again' after reuse, got {reget!r}"


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
