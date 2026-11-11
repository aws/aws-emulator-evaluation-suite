"""concurrent-delete-key-race-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-delete-key-race-single-winner"
GROUP = "concurrency"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Several DeleteKey calls racing on one key with the same IfMatch ETag: exactly one wins and
    removes the key, every other racer gets ValidationException, and the key is deleted once."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    etag0 = _dp_etag(dp, arn)
    seeded = dp.put_key(KvsARN=arn, Key="contested-delete", Value="present", IfMatch=etag0)
    shared_etag = seeded["ETag"]

    racer_count = 5

    def _racer(_i: int):
        client = ctx.client("cloudfront-keyvaluestore")
        try:
            resp = client.delete_key(KvsARN=arn, Key="contested-delete", IfMatch=shared_etag)
            return ("ok", resp)
        except Exception as exc:  # noqa: BLE001 - classify below
            err = getattr(exc, "response", {}).get("Error", {})
            return ("error", (err.get("Code"), err.get("Message")))

    results = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, i) for i in range(racer_count)]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winning delete, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losing racers, got {len(failures)}: {results}"
    )
    stale = ("ValidationException", "Pre-Condition failed during update of Key-Value-Store")
    assert all(err == stale for (_, err) in failures), failures
    assert successes[0][1]["ItemCount"] == 0, (
        f"expected the winning delete to leave the store empty, got ItemCount="
        f"{successes[0][1]['ItemCount']}"
    )

    code, message = _error_code(lambda: dp.get_key(KvsARN=arn, Key="contested-delete"))
    assert code == "ResourceNotFoundException", (
        f"expected the deleted key to read back ResourceNotFoundException, got {code!r}: {message!r}"
    )
    assert message == "No such Key exists", f"GetKey on the deleted key returned message {message!r}"


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
