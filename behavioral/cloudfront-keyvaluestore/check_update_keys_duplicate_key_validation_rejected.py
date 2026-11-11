"""update-keys-duplicate-key-validation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-keys-duplicate-key-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateKeys whose Puts list names the same key twice is rejected with ValidationException
    and applies nothing; the deduplicated batch on the same ETag succeeds."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    code, message = _error_code(
        lambda: dp.update_keys(
            KvsARN=arn,
            IfMatch=etag0,
            Puts=[{"Key": "dup", "Value": "a"}, {"Key": "dup", "Value": "b"}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    assert message == (
        "Validation error during update keys. Payload contains multiple updates for the same key."
    ), message

    # effect absent: the key must not exist, and the ETag must not have moved
    nf_code, nf_message = _error_code(lambda: dp.get_key(KvsARN=arn, Key="dup"))
    assert nf_code == "ResourceNotFoundException", (
        f"key 'dup' must not exist after the rejected batch, got {nf_code!r}: {nf_message!r}"
    )
    assert nf_message == "No such Key exists", nf_message
    etag1 = _dp_etag(dp, arn)
    assert etag1 == etag0, f"ETag must not move on a rejected batch: expected {etag0!r}, got {etag1!r}"

    # positive control: the same ETag still works for a corrected, valid batch
    resp = dp.update_keys(KvsARN=arn, IfMatch=etag0, Puts=[{"Key": "dup", "Value": "a"}])
    assert resp["ItemCount"] == 1, f"expected ItemCount 1 after the corrected batch, got {resp['ItemCount']!r}"
    value = dp.get_key(KvsARN=arn, Key="dup")["Value"]
    assert value == "a", f"expected key 'dup' to hold 'a' after the corrected batch, got {value!r}"


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
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
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
