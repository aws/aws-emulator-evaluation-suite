"""metrics-states-stream-write-over-one-shard-quota-rejected-and-only-accepted-records-counted."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-stream-write-over-one-shard-quota-rejected-and-only-accepted-records-counted"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "kinesis"]

_NAMESPACE = "AWS/Kinesis"
_METRIC_BUDGET_S = 600.0
_POLL_S = 10.0
_PK = "sim2real-pk"
#: One round of concurrent PutRecords of small records offers several times the per-shard
#: record-rate quota (1000 records/s). The shard's token bucket absorbs short bursts, so the
#: round may be partially refused or fully accepted; either way only accepted entries may count.
_RECORD_BYTES = 64
_BATCH = 500
_THREADS = 8


# timing:real-time — metric: 15 s https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Concurrent PutRecords over one provisioned shard's record-rate quota may refuse entries; any
    refusal carries ProvisionedThroughputExceededException with its exact message, a drain returns
    exactly the accepted payloads, and the stream metrics count only the accepted entries.
    """
    kinesis = ctx.client("kinesis")
    cw = ctx.client("cloudwatch")
    stream = _stream(ctx, kinesis)

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    accepted: dict[bytes, int] = {}
    refused: set[bytes] = set()
    errors: set[tuple[str, str]] = set()

    def _put(tag: int) -> list:
        records = [_payload(tag, i) for i in range(_BATCH)]
        # An ACTIVE stream's data plane can answer ResourceNotFoundException for a few seconds;
        # a not-found call stores nothing, so it is retried until the stream accepts writes.
        deadline = time.monotonic() + _budget_s(ctx, 60.0)
        while True:
            try:
                resp = kinesis.put_records(
                    StreamName=stream, Records=[{"Data": r, "PartitionKey": _PK} for r in records])
                break
            except ClientError as exc:
                if (exc.response["Error"]["Code"] != "ResourceNotFoundException"
                        or time.monotonic() > deadline):
                    raise
                time.sleep(1.0)
        assert len(resp["Records"]) == len(records), (
            f"PutRecords returned {len(resp['Records'])} result entries for {len(records)} records"
        )
        failed = sum(1 for e in resp["Records"] if "ErrorCode" in e)
        assert resp.get("FailedRecordCount", 0) == failed, (
            f"FailedRecordCount {resp.get('FailedRecordCount')!r} != {failed} errored entries"
        )
        return list(zip(records, resp["Records"]))

    with ThreadPoolExecutor(max_workers=_THREADS) as pool:
        for pairs in pool.map(_put, range(_THREADS)):
            for data, entry in pairs:
                if "ErrorCode" in entry:
                    refused.add(data)
                    errors.add((entry["ErrorCode"], entry.get("ErrorMessage")))
                else:
                    accepted[data] = len(data) + len(_PK)
    assert accepted, "every entry was refused; no positive control to count against"
    shard_id = kinesis.list_shards(StreamName=stream)["Shards"][0]["ShardId"]
    want_error = (
        "ProvisionedThroughputExceededException",
        f"Rate exceeded for shard {shard_id} in stream {stream} under account {ctx.account}.",
    )
    assert errors <= {want_error}, (
        f"refused entries carried (ErrorCode, ErrorMessage) {sorted(errors)!r}; expected only "
        f"{want_error!r}"
    )

    # Effect-absent at the shard: drain it and compare to what the service said it kept.
    drained = _drain(kinesis, stream, expect=len(accepted), budget_s=_budget_s(ctx, 180.0))
    assert set(drained) == set(accepted), (
        f"drain returned {len(drained)} records; {len(set(drained) - set(accepted))} were refused "
        f"entries and {len(set(accepted) - set(drained))} accepted entries are missing"
    )
    assert len(drained) == len(accepted), f"drain returned duplicates: {len(drained)} records"

    dims = [{"Name": "StreamName", "Value": stream}]
    want = {
        "IncomingRecords": float(len(accepted)),
        "IncomingBytes": float(sum(accepted.values())),
        "PutRecords.ThrottledRecords": float(len(refused)),
        "PutRecords.SuccessfulRecords": float(len(accepted)),
    }

    def _read():
        r = {m: _sum(cw, m, dims, window_start) for m in want}
        r["WriteProvisionedThroughputExceeded"] = _sum(
            cw, "WriteProvisionedThroughputExceeded", dims, window_start)
        return r

    def _throttle_ok(r):
        return r["WriteProvisionedThroughputExceeded"] > 0 if refused else (
            r["WriteProvisionedThroughputExceeded"] == 0)

    got = _poll(_read, lambda r: all(r[m] == v for m, v in want.items()) and _throttle_ok(r),
                f"AWS/Kinesis stream sums to reach {want!r} with WriteProvisionedThroughputExceeded "
                f"{'> 0' if refused else '== 0'}", budget_s=_budget_s(ctx, _METRIC_BUDGET_S))
    assert _throttle_ok(got), f"throttle metric disagrees with {len(refused)} refusals: {got!r}"


def _budget_s(ctx, cap_s: float) -> float:
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 10 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 10.0))


def _payload(call: int, i: int) -> bytes:
    head = f"sim2real-{call:04d}-{i:04d}-".encode()
    return head + b"x" * (_RECORD_BYTES - len(head))


def _stream(ctx, kinesis) -> str:
    name = ctx.unique_name("sim2real-behav-kthr-")
    kinesis.create_stream(StreamName=name, ShardCount=1,
                          StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    kinesis.get_waiter("stream_exists").wait(StreamName=name,
                                             WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": "1"})
    return name


def _drain(kinesis, stream: str, expect: int, budget_s: float) -> list[bytes]:
    shards = kinesis.list_shards(StreamName=stream)["Shards"]
    assert len(shards) == 1, f"expected one shard, got {[s['ShardId'] for s in shards]}"
    it = kinesis.get_shard_iterator(StreamName=stream, ShardId=shards[0]["ShardId"],
                                    ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    out: list[bytes] = []
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        try:
            resp = kinesis.get_records(ShardIterator=it, Limit=10000)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ProvisionedThroughputExceededException":
                raise
            time.sleep(1.0)  # our own read burst; the retry is the wait
            continue
        out.extend(r["Data"] for r in resp["Records"])
        it = resp["NextShardIterator"]
        if len(out) >= expect and resp.get("MillisBehindLatest", 1) == 0:
            return out
        time.sleep(0.5)
    raise AssertionError(f"drain read {len(out)} of {expect} accepted records in {budget_s:.0f}s")


def _sum(cw, metric: str, dims: list, start) -> float:
    pts = cw.get_metric_statistics(
        Namespace=_NAMESPACE, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60,
        Statistics=["Sum"],
    )["Datapoints"]
    return float(sum(p["Sum"] for p in pts))


def _poll(read, done, what: str, budget_s: float):
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = read()
        if done(last):
            return last
        time.sleep(_POLL_S)
    raise AssertionError(f"timed out after {budget_s:.0f}s waiting for {what}; last {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
