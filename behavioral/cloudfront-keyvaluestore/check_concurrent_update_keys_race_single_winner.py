"""concurrent-update-keys-race-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-update-keys-race-single-winner"
GROUP = "concurrency"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Several Puts-only UpdateKeys batches racing with the same IfMatch ETag: exactly one batch
    wins and every other racer gets ValidationException (not ConflictException) with none of its
    keys applied, so optimistic concurrency is store-wide."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    shared_etag = _dp_etag(dp, arn)

    racer_count = 5

    def _racer(i: int):
        client = ctx.client("cloudfront-keyvaluestore")
        batch = [{"Key": f"racer-{i}-a", "Value": "x"}, {"Key": f"racer-{i}-b", "Value": "y"}]
        try:
            resp = client.update_keys(KvsARN=arn, IfMatch=shared_etag, Puts=batch)
            return ("ok", i, resp)
        except Exception as exc:  # noqa: BLE001 - classify below
            err = getattr(exc, "response", {}).get("Error", {})
            return ("error", i, (err.get("Code"), err.get("Message")))

    results = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, i) for i in range(racer_count)]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winning batch, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losing batches, got {len(failures)}: {results}"
    )
    assert all(
        err == ("ValidationException", "Pre-Condition failed during update of Key-Value-Store")
        for (_, _, err) in failures
    ), failures

    winner_i = successes[0][1]
    desc = dp.describe_key_value_store(KvsARN=arn)
    assert desc["ItemCount"] == 2, "only the winning batch's two keys should exist"
    winner_value = dp.get_key(KvsARN=arn, Key=f"racer-{winner_i}-a")["Value"]
    assert winner_value == "x", f"expected winning batch's key value 'x', got {winner_value!r}"

    for i in range(racer_count):
        if i == winner_i:
            continue
        err = _error(lambda i=i: dp.get_key(KvsARN=arn, Key=f"racer-{i}-a"))
        assert err == ("ResourceNotFoundException", "No such Key exists"), (
            f"losing racer {i}'s keys should not exist, got GetKey error {err!r}"
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
        Tags={"Items": [{"Key": "sim2real", "Value": "behavioral-check"}]},
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
