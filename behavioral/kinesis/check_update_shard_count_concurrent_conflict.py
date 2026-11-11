"""update-shard-count-concurrent-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )

def _wait_stream_ready(c, name, timeout_s=150):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 90, 2, f"stream {name} shards addressable")

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))

def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

CHECK = "update-shard-count-concurrent-conflict"
GROUP = 'resharding'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateShardCount calls on one stream: exactly one is accepted, the loser fails with
    ResourceInUseException (exact not-ACTIVE message) or LimitExceededException, and the stream ends with
    the winner's open-shard count."""
    # Start at 2 shards so BOTH racers are individually-valid requests. Kinesis statically rejects a
    # single UpdateShardCount that more than doubles the current shard count (1 -> 4 fails with
    # InvalidArgumentException on its own merits), which would mask the contention behavior.
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=2)

    targets = [3, 4]

    def scale_to(n):
        return lambda: c.update_shard_count(
            StreamName=name, TargetShardCount=n, ScalingType="UNIFORM_SCALING"
        )

    results = _run_concurrent([scale_to(t) for t in targets], timeout_s=90)
    successes = _concurrent_successes(results)
    error_codes = _concurrent_error_codes(results)

    # EXACTLY one, not "at least one": the whole point of the check is that an
    # over-permissive emulator accepting BOTH concurrent resharding requests is a
    # divergence. A bare `successes >= 1` would let successes == 2 pass silently.
    assert successes == 1, (
        f"exactly one concurrent UpdateShardCount should be accepted (the stream enters "
        f"UPDATING and the loser must conflict), got {successes} successes; "
        f"error_codes={error_codes}"
    )
    assert "ResourceInUseException" in error_codes or "LimitExceededException" in error_codes, (
        f"the losing racer should fail with a state-conflict error, got {error_codes}"
    )
    in_use = f"Stream {name} under account {ctx.account} not ACTIVE, instead in state UPDATING"
    for r in results:
        if isinstance(r, ClientError) and r.response["Error"]["Code"] == "ResourceInUseException":
            assert r.response["Error"]["Message"] == in_use, (
                f"expected the ResourceInUseException message {in_use!r}, got {r.response['Error']!r}"
            )
    winner_target = next(
        t for t, r in zip(targets, results) if not isinstance(r, BaseException)
    )

    _wait_stream_ready(c, name)

    # Independent terminal read: the winner's own response is not the verdict. The stream's
    # reported OpenShardCount after both racers have settled must match the target the winner
    # actually asked for, not the loser's, and not something in between.
    final_open_shards = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
        "OpenShardCount"
    ]
    assert final_open_shards == winner_target, (
        f"final OpenShardCount should reflect the winning racer's target ({winner_target}), "
        f"got {final_open_shards}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
