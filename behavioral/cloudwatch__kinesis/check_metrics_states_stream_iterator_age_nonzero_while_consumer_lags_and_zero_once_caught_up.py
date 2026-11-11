"""metrics-states-stream-iterator-age-nonzero-while-consumer-lags-and-zero-once-caught-up."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-states-stream-iterator-age-nonzero-while-consumer-lags-and-zero-once-caught-up"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "kinesis"]

_NAMESPACE = "AWS/Kinesis"
_METRIC = "GetRecords.IteratorAgeMilliseconds"
_METRIC_BUDGET_S = 600.0
_POLL_S = 15.0
_PK = "sim2real-pk"
_PAYLOADS = [f"sim2real-lag-{i}-".encode() + b"y" * (13 * i + 5) for i in range(6)]
_TIP = b"sim2real-lag-tip"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html
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
    """A lagging consumer makes GetRecords.IteratorAgeMilliseconds report the lag
    (MillisBehindLatest above 0), and once it polls the tip a later datapoint reads Maximum 0
    (MillisBehindLatest 0)."""
    kinesis = ctx.client("kinesis")
    cw = ctx.client("cloudwatch")
    stream = _stream(ctx, kinesis)
    dims = [{"Name": "StreamName", "Value": stream}]

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    for p in _PAYLOADS:
        kinesis.put_record(StreamName=stream, Data=p, PartitionKey=_PK)

    # Let the records age by waiting on an observable: IncomingRecords for these puts landing in
    # CloudWatch. Nothing has read the shard yet, so the consumer is lagging for that whole time.
    incoming = _poll(lambda: _stat(cw, "IncomingRecords", dims, window_start, "Sum"),
                     lambda pts: sum(p["Sum"] for p in pts) == float(len(_PAYLOADS)),
                     f"IncomingRecords to reach {len(_PAYLOADS)}")
    assert sum(p["Sum"] for p in incoming) == float(len(_PAYLOADS)), f"IncomingRecords {incoming!r}"

    # The tip record. A GetRecords call that reads THROUGH to the tip reports
    # IteratorAge 0 even when every record it returned was a minute old, so a lagging consumer is
    # one that leaves newer records unread behind the one it just got.
    kinesis.put_record(StreamName=stream, Data=_TIP, PartitionKey=_PK)

    shard = kinesis.list_shards(StreamName=stream)["Shards"][0]["ShardId"]
    it = kinesis.get_shard_iterator(StreamName=stream, ShardId=shard,
                                    ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    got: list[dict] = []
    deadline = time.monotonic() + 120.0
    while not got and time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=it, Limit=1)  # the lagging read
        got.extend(resp["Records"])
        it = resp["NextShardIterator"]
    assert [r["Data"] for r in got] == _PAYLOADS[:1], (
        f"the lagging Limit=1 read returned {[r['Data'][:24] for r in got]!r}")
    assert resp["MillisBehindLatest"] > 0, (
        f"a consumer with {len(_PAYLOADS)} newer records unread reports MillisBehindLatest "
        f"{resp['MillisBehindLatest']!r}")
    while len(got) < len(_PAYLOADS) + 1 and time.monotonic() < deadline:  # catch up
        resp = kinesis.get_records(ShardIterator=it)
        got.extend(resp["Records"])
        it = resp["NextShardIterator"]
    assert [r["Data"] for r in got] == _PAYLOADS + [_TIP], (
        f"catch-up read returned {len(got)} records; expected the {len(_PAYLOADS)} payloads + tip")
    lag_ms = (got[-1]["ApproximateArrivalTimestamp"]
              - got[0]["ApproximateArrivalTimestamp"]).total_seconds() * 1000.0
    assert lag_ms > 0.0, f"the tip arrived {lag_ms:.0f}ms after the first record; no lag created"
    read_at = datetime.now(timezone.utc)
    caught_up_at = read_at

    state = {"it": it}

    def _tip_read_then_stats():
        # The consumer keeps polling the tip so later minutes carry caught-up GetRecords calls.
        resp = kinesis.get_records(ShardIterator=state["it"])
        state["it"] = resp["NextShardIterator"]
        assert resp["Records"] == [], f"tip read returned unexpected records {resp['Records']!r}"
        assert resp["MillisBehindLatest"] == 0, (
            f"a caught-up consumer reports MillisBehindLatest {resp['MillisBehindLatest']!r}")
        return _stat(cw, _METRIC, dims, window_start, "Maximum")

    def _lagging(pts):
        return [p for p in pts if p["Maximum"] >= 0.5 * lag_ms]

    def _zero_after(pts):
        return [p for p in pts if p["Maximum"] == 0.0
                and p["Timestamp"] >= caught_up_at.replace(second=0, microsecond=0)
                + timedelta(minutes=1)]

    pts = _poll(_tip_read_then_stats, lambda p: bool(_lagging(p)) and bool(_zero_after(p)),
                f"{_METRIC} to show a lagging Maximum >= {0.5 * lag_ms:.0f}ms and then a later "
                "Maximum of 0 once caught up", interval=10.0)
    lag_pt = max(_lagging(pts), key=lambda p: p["Timestamp"])
    zero_pt = min(_zero_after(pts), key=lambda p: p["Timestamp"])
    assert zero_pt["Timestamp"] > lag_pt["Timestamp"], (
        f"the zero datapoint {zero_pt!r} does not follow the lagging one {lag_pt!r}")
    top = max(p["Maximum"] for p in pts)
    assert top <= (read_at - window_start).total_seconds() * 1000.0 + 60000.0, (
        f"{_METRIC} Maximum {top}ms exceeds any age a record in this stream could have had")


def _stream(ctx, kinesis) -> str:
    name = ctx.unique_name("sim2real-behav-klag-")
    kinesis.create_stream(StreamName=name, ShardCount=1,
                          StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    kinesis.get_waiter("stream_exists").wait(StreamName=name,
                                             WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": "1"})
    return name


def _stat(cw, metric: str, dims: list, start, stat: str) -> list:
    return cw.get_metric_statistics(
        Namespace=_NAMESPACE, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60,
        Statistics=[stat],
    )["Datapoints"]


def _poll(read, done, what: str, interval: float = _POLL_S):
    deadline = time.monotonic() + _METRIC_BUDGET_S
    last = None
    while time.monotonic() < deadline:
        last = read()
        if done(last):
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {_METRIC_BUDGET_S}s waiting for {what}; last {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
