"""put-key-key-containing-slash-characters-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-key-containing-slash-characters-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key containing '/' characters, bound into the URI path, round-trips exactly through PutKey
    and GetKey, not split into extra path segments or truncated at the first slash."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)

    key_with_slashes = "path/like/key/with/slashes"
    put_resp = dp.put_key(KvsARN=arn, Key=key_with_slashes, Value="slash-value", IfMatch=etag0)
    assert put_resp["ItemCount"] == 1, f"expected ItemCount 1 after first put, got {put_resp['ItemCount']}"

    got = dp.get_key(KvsARN=arn, Key=key_with_slashes)
    assert got["Key"] == key_with_slashes, f"key round-tripped as {got['Key']!r}, expected {key_with_slashes!r}"
    assert got["Value"] == "slash-value", f"value round-tripped as {got['Value']!r}"

    listed = dp.list_keys(KvsARN=arn, MaxResults=50)["Items"]
    assert {item["Key"] for item in listed} == {key_with_slashes}, (
        f"expected exactly {{{key_with_slashes!r}}} in the listing, got {[i['Key'] for i in listed]}"
    )

    del_resp = dp.delete_key(KvsARN=arn, Key=key_with_slashes, IfMatch=put_resp["ETag"])
    assert del_resp["ItemCount"] == 0, f"expected ItemCount 0 after delete, got {del_resp['ItemCount']}"

    nf_code, nf_message = _error_code(lambda: dp.get_key(KvsARN=arn, Key=key_with_slashes))
    assert nf_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the deleted slash-key, got {nf_code!r}: {nf_message!r}"
    )
    assert nf_message == "No such Key exists", nf_message
    described = dp.describe_key_value_store(KvsARN=arn)
    assert described["ItemCount"] == 0, f"expected store ItemCount 0 after delete, got {described['ItemCount']}"


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
