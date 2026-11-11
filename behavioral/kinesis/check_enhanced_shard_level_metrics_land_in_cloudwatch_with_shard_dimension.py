"""enhanced-shard-level-metrics-land-in-cloudwatch-with-shard-dimension."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enhanced-shard-level-metrics-land-in-cloudwatch-with-shard-dimension"
GROUP = "monitoring"
SERVICES = ["kinesis"]

#: 7 separate PutRecord calls, so both the record count and the operation count are 7.
_N_RECORDS = 7
#: Every payload is the same length, so the byte total is exactly derivable.
_PAYLOADS = tuple(f"metric-probe-{i:03d}".encode() for i in range(_N_RECORDS))
_PARTITION_KEY = "metric-pk"
_DATA_BYTES = sum(len(p) for p in _PAYLOADS)
_PK_BYTES = _N_RECORDS * len(_PARTITION_KEY.encode())

_NAMESPACE = "AWS/Kinesis"
#: Deadline for AWS/Kinesis datapoints to appear once shard-level metrics are CURRENT; usually
#: ~30-40s, but shard-level datapoints have been seen to take over 180s.
_METRIC_DEADLINE_S = 240.0


# timing:real-time — metric: 31 s https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html
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
    """EnableEnhancedMonitoring makes Kinesis DELIVER shard-dimensioned AWS/Kinesis datapoints to
    CloudWatch whose Sum equals exactly the traffic this check produced — not merely echo the
    metric list back on DescribeStreamSummary."""
    kinesis = ctx.client("kinesis")
    cloudwatch = ctx.client("cloudwatch")

    stream = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, stream["name"])

    # Enhanced (shard-level) metrics are OFF by default; arm them before producing any traffic.
    desired = kinesis.enable_enhanced_monitoring(
        StreamName=stream["name"], ShardLevelMetrics=["ALL"]
    )["DesiredShardLevelMetrics"]
    assert desired, (
        "EnableEnhancedMonitoring returned an empty DesiredShardLevelMetrics; expected the "
        f"expansion of ['ALL'], got {desired!r}"
    )

    # The DESIRED set takes effect asynchronously: traffic put before the CURRENT set reaches it
    # is never counted at the ShardId level, so wait for DescribeStreamSummary to report it.
    _poll_until(
        lambda: set(
            (kinesis.describe_stream_summary(StreamName=stream["name"])
             ["StreamDescriptionSummary"]["EnhancedMonitoring"][0]["ShardLevelMetrics"])
        ),
        lambda current: current >= set(desired),
        timeout_s=180.0,
        interval_s=5.0,
        description=(
            f"DescribeStreamSummary.EnhancedMonitoring for {stream['name']} to report the CURRENT "
            f"shard-level metric set reaching the DESIRED set {sorted(desired)}"
        ),
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    for payload in _PAYLOADS:
        kinesis.put_record(
            StreamName=stream["name"], Data=payload, PartitionKey=_PARTITION_KEY
        )

    # Drain in the same run so OutgoingRecords has traffic to report. This read is incidental to
    # the metric assertions; the terminal assertion is at CloudWatch, not here.
    drained = _drain_shard(ctx, stream["name"], shard_id, expect=_N_RECORDS)
    assert drained == list(_PAYLOADS), (
        f"GetRecords drain returned {drained!r}; expected the {_N_RECORDS} payloads that were put, "
        "in order — the metric assertions below are only meaningful if the traffic really landed"
    )

    stream_dims = [{"Name": "StreamName", "Value": stream["name"]}]
    shard_dims = stream_dims + [{"Name": "ShardId", "Value": shard_id}]

    # ---- Terminal read at the DESTINATION (CloudWatch), via a different operation ----
    def _sums() -> dict[str, float | None]:
        return {
            "stream_incoming_records": _metric_sum(
                cloudwatch, "IncomingRecords", stream_dims, window_start
            ),
            "shard_incoming_records": _metric_sum(
                cloudwatch, "IncomingRecords", shard_dims, window_start
            ),
            "shard_incoming_bytes": _metric_sum(
                cloudwatch, "IncomingBytes", shard_dims, window_start
            ),
            "shard_outgoing_records": _metric_sum(
                cloudwatch, "OutgoingRecords", shard_dims, window_start
            ),
            "shard_incoming_samples": _metric_sum(
                cloudwatch, "IncomingRecords", shard_dims, window_start, statistic="SampleCount"
            ),
        }

    # The predicate is the FULL expected state, not just "something arrived": a minute bucket can
    # become visible before its neighbour, so polling on presence alone races a partial Sum into the
    # exact-equality assertions below. A wrong value therefore surfaces as this poll's timeout, whose
    # message carries the last observation.
    sums = _poll_until(
        _sums,
        _expected_sums,
        timeout_s=_METRIC_DEADLINE_S,
        interval_s=20.0,
        description=(
            f"AWS/Kinesis stream-level and ShardId-dimensioned datapoints for {stream['name']} / "
            f"{shard_id} to become visible in CloudWatch with their complete sums"
        ),
    )

    assert sums["shard_incoming_records"] == float(_N_RECORDS), (
        f"AWS/Kinesis IncomingRecords Sum dimensioned by ShardId={shard_id} is "
        f"{sums['shard_incoming_records']}; expected exactly {_N_RECORDS} — the number of PutRecord "
        "calls this check made"
    )
    assert sums["stream_incoming_records"] == float(_N_RECORDS), (
        f"AWS/Kinesis IncomingRecords Sum dimensioned by StreamName only is "
        f"{sums['stream_incoming_records']}; expected exactly {_N_RECORDS}"
    )
    # A one-shard stream must agree with itself across the two dimension levels.
    assert sums["stream_incoming_records"] == sums["shard_incoming_records"], (
        f"stream-level IncomingRecords ({sums['stream_incoming_records']}) disagrees with "
        f"shard-level IncomingRecords ({sums['shard_incoming_records']}) on a ONE-shard stream; "
        "the two aggregates must be equal"
    )
    # IncomingBytes counts the data blob PLUS the partition key, not the data blob alone.
    assert sums["shard_incoming_bytes"] == float(_DATA_BYTES + _PK_BYTES), (
        f"AWS/Kinesis IncomingBytes Sum for ShardId={shard_id} is "
        f"{sums['shard_incoming_bytes']}; expected exactly {_DATA_BYTES + _PK_BYTES} — the "
        f"{_N_RECORDS} data blobs ({_DATA_BYTES} bytes) plus their partition keys ({_PK_BYTES} bytes)"
    )
    assert sums["shard_outgoing_records"] == float(_N_RECORDS), (
        f"AWS/Kinesis OutgoingRecords Sum for ShardId={shard_id} is "
        f"{sums['shard_outgoing_records']}; expected exactly {_N_RECORDS} — every record put was "
        "read back by the GetRecords drain above"
    )
    # SampleCount counts PUT OPERATIONS (the separate PutRecord calls), distinct from the Sum.
    assert sums["shard_incoming_samples"] == float(_N_RECORDS), (
        f"AWS/Kinesis IncomingRecords SampleCount statistic for ShardId={shard_id} is "
        f"{sums['shard_incoming_samples']}; expected exactly {_N_RECORDS} — the number of separate "
        "PutRecord calls this check made, distinct from the Sum of the IncomingRecords values"
    )

    # ListMetrics' catalog is a separate consistency domain from GetMetricStatistics: it can still
    # report nothing after the datapoints have landed, so it is polled too.
    listed = _poll_until(
        lambda: _list_metric_dimension_names(cloudwatch, "IncomingRecords", stream["name"], shard_id),
        lambda names: names == {"StreamName", "ShardId"},
        timeout_s=120.0,
        interval_s=10.0,
        description=(
            f"ListMetrics(Namespace={_NAMESPACE!r}, MetricName='IncomingRecords') to register the "
            f"ShardId={shard_id} dimensioned metric"
        ),
    )
    assert listed == {"StreamName", "ShardId"}, (
        f"ListMetrics(Namespace={_NAMESPACE!r}, MetricName='IncomingRecords') reports dimension "
        f"names {sorted(listed)} for shard {shard_id}; expected exactly ['ShardId', 'StreamName']"
    )



def _expected_sums(sums: dict) -> bool:
    """True once every AWS/Kinesis aggregate has landed AT its complete expected value."""
    incoming_bytes = sums["shard_incoming_bytes"]
    return (
        sums["shard_incoming_records"] == float(_N_RECORDS)
        and sums["stream_incoming_records"] == float(_N_RECORDS)
        and sums["shard_outgoing_records"] == float(_N_RECORDS)
        and sums["shard_incoming_samples"] == float(_N_RECORDS)
        and incoming_bytes == float(_DATA_BYTES + _PK_BYTES)
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observation: {last!r}"
    )


def _create_active_stream(ctx, *, shard_count: int = 1) -> dict[str, str]:
    """Create-or-adopt a provisioned stream, tagged, and wait until it is ACTIVE."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kds-")
    try:
        kinesis.create_stream(
            StreamName=name,
            ShardCount=shard_count,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
            Tags={"sim2real": "behavioral", "sim2real-check": CHECK},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
            raise
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=240.0,
        interval_s=3.0,
        description=f"stream {name} to reach ACTIVE",
    )
    return {"name": name, "arn": summary["StreamARN"]}


def _single_shard_id(ctx, stream_name: str) -> str:
    """ListShards can lag ACTIVE briefly; poll until exactly one shard is addressable."""
    kinesis = ctx.client("kinesis")

    def probe() -> list:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ResourceInUseException", "ResourceNotFoundException"):
                return []
            raise

    shards = _poll_until(
        probe,
        lambda s: len(s) == 1,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"exactly one shard to be addressable on {stream_name}",
    )
    return shards[0]["ShardId"]


def _drain_shard(ctx, stream_name: str, shard_id: str, *, expect: int) -> list[bytes]:
    """Read from TRIM_HORIZON until `expect` records have been collected; raise if they never are."""
    kinesis = ctx.client("kinesis")
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    collected: list[bytes] = []
    state = {"iterator": iterator}

    def probe() -> int:
        # GetRecords is limited to 5 TPS per shard, so this loop is deliberately slow-polled.
        resp = kinesis.get_records(ShardIterator=state["iterator"], Limit=1000)
        collected.extend(r["Data"] for r in resp["Records"])
        state["iterator"] = resp.get("NextShardIterator") or state["iterator"]
        return len(collected)

    _poll_until(
        probe,
        lambda n: n >= expect,
        timeout_s=90.0,
        interval_s=2.0,
        description=f"{expect} records to be readable from {shard_id}",
    )
    return collected


def _metric_sum(
    cloudwatch, metric_name: str, dimensions: list, window_start, *, statistic: str = "Sum"
) -> float | None:
    """Sum every datapoint's `statistic` in the window, or None when the metric has not landed yet.

    Returning None (rather than 0.0) keeps "not yet delivered" distinguishable from "delivered as
    zero" — the whole point of the poll above.
    """
    resp = cloudwatch.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=window_start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=[statistic],
    )
    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return None
    return float(sum(dp[statistic] for dp in datapoints))


def _list_metric_dimension_names(
    cloudwatch, metric_name: str, stream_name: str, shard_id: str
) -> set[str]:
    """Dimension names CloudWatch reports for the shard-dimensioned metric; {} if not registered."""
    paginator = cloudwatch.get_paginator("list_metrics")
    for page in paginator.paginate(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=[{"Name": "ShardId", "Value": shard_id}],
    ):
        for metric in page["Metrics"]:
            names = {d["Name"] for d in metric["Dimensions"]}
            values = {d["Value"] for d in metric["Dimensions"]}
            if shard_id in values and stream_name in values:
                return names
    return set()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
