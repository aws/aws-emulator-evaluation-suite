"""concurrent-put-key-stale-etag-only-one-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-put-key-stale-etag-only-one-wins"
GROUP = "concurrency"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Several PutKey calls racing with the same IfMatch ETag: exactly one wins, every other racer
    gets ValidationException (KVS's stale-version answer, not ConflictException), and the key's
    final value is the winner's."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]
    shared_etag = _dp_etag(dp, arn)

    racer_count = 6
    values = [f"racer-{i}" for i in range(racer_count)]

    def _racer(value: str):
        client = ctx.client("cloudfront-keyvaluestore")
        try:
            resp = client.put_key(KvsARN=arn, Key="contested", Value=value, IfMatch=shared_etag)
            return ("ok", value, resp)
        except Exception as exc:  # noqa: BLE001 - classify below
            error = getattr(exc, "response", {}).get("Error", {})
            return ("error", value, (error.get("Code"), error.get("Message")))

    results = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, v) for v in values]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    stale = ("ValidationException", "Pre-Condition failed during update of Key-Value-Store")
    assert all(error == stale for (_, _, error) in failures), failures

    winner_value = successes[0][1]
    got = dp.get_key(KvsARN=arn, Key="contested")
    assert got["Value"] == winner_value, f"expected final value {winner_value!r}, got {got['Value']!r}"


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
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
