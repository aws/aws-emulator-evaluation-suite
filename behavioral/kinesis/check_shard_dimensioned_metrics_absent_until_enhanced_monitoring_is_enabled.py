"""shard-dimensioned-metrics-absent-until-enhanced-monitoring-is-enabled."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shard-dimensioned-metrics-absent-until-enhanced-monitoring-is-enabled"
GROUP = "monitoring"
SERVICES = ["kinesis"]

#: Identical traffic to both twins, in the same instant.
_N_RECORDS = 6
_PAYLOADS = tuple(f"twin-probe-{i:03d}".encode() for i in range(_N_RECORDS))
#: Traffic written to the unarmed twin after enhanced monitoring is switched on.
_REPAIR_RECORDS = 4
_REPAIR_PAYLOADS = tuple(f"repair-probe-{i:03d}".encode() for i in range(_REPAIR_RECORDS))
_PARTITION_KEY = "twin-pk"

_NAMESPACE = "AWS/Kinesis"
#: Ceiling for the armed twin's shard metric to appear once monitoring is confirmed active;
#: the first datapoint typically lands 15-30s after traffic, so this is headroom.
_ARM_DEADLINE_S = 420.0
#: Ceiling for EnableEnhancedMonitoring's own control-plane confirmation (typically ~6s).
_ARM_CONFIRM_DEADLINE_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Shard-dimensioned AWS/Kinesis metrics are absent for a stream without enhanced monitoring
    while an identically loaded armed twin gets them, and appear once monitoring is enabled.
    """
    kinesis = ctx.client("kinesis")
    cloudwatch = ctx.client("cloudwatch")

    armed = _create_active_stream(ctx)
    plain = _create_active_stream(ctx)
    armed_shard = _single_shard_id(ctx, armed["name"])
    plain_shard = _single_shard_id(ctx, plain["name"])

    kinesis.enable_enhanced_monitoring(StreamName=armed["name"], ShardLevelMetrics=["ALL"])
    # EnableEnhancedMonitoring is asynchronous: traffic produced before the backend actually
    # activates shard-level collection is dropped, not queued. Confirm activation via an
    # independent read (DescribeStreamSummary) BEFORE either twin sees any traffic — otherwise
    # the armed twin's own puts can be the thing silently missing, and no timeout fixes that.
    armed_enabled = _poll_until(
        lambda: _enabled_shard_metrics(kinesis, armed["name"]),
        lambda s: bool(s),
        timeout_s=_ARM_CONFIRM_DEADLINE_S,
        interval_s=3.0,
        description=(
            f"DescribeStreamSummary to confirm enhanced monitoring active on armed twin "
            f"{armed['name']}"
        ),
    )
    assert armed_enabled, (
        f"the armed twin {armed['name']} confirmed enhanced monitoring with an empty metric set "
        f"{sorted(armed_enabled)}; expected a non-empty expansion of ['ALL']"
    )

    plain_enabled = _enabled_shard_metrics(kinesis, plain["name"])
    assert plain_enabled == set(), (
        f"the control twin {plain['name']} reports EnhancedMonitoring {sorted(plain_enabled)} "
        "before anything enabled it; expected an empty set, otherwise the absence leg below is "
        "measuring the wrong thing"
    )

    # ---- Identical work, at the same moment, on both twins ----
    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    puts_at = time.monotonic()
    for payload in _PAYLOADS:
        kinesis.put_record(StreamName=armed["name"], Data=payload, PartitionKey=_PARTITION_KEY)
        kinesis.put_record(StreamName=plain["name"], Data=payload, PartitionKey=_PARTITION_KEY)

    armed_shard_dims = [
        {"Name": "StreamName", "Value": armed["name"]},
        {"Name": "ShardId", "Value": armed_shard},
    ]
    plain_stream_dims = [{"Name": "StreamName", "Value": plain["name"]}]
    plain_shard_dims = plain_stream_dims + [{"Name": "ShardId", "Value": plain_shard}]

    # ---- The demonstrated control: the ARMED twin's shard metric really does arrive ----
    _poll_until(
        lambda: _metric_sum(cloudwatch, "IncomingRecords", armed_shard_dims, window_start),
        lambda s: s == float(_N_RECORDS),
        timeout_s=_ARM_DEADLINE_S,
        interval_s=20.0,
        description=(
            f"the ARMED twin's ShardId-dimensioned IncomingRecords Sum for {armed_shard} to reach "
            f"exactly {_N_RECORDS}"
        ),
    )
    latency_s = time.monotonic() - puts_at

    # ---- Absence on the unarmed twin, at that same instant, on two independent observables ----
    # Polled to the complete expected value for the same reason as the armed twin: a partial minute
    # bucket must be waited out, not asserted against.
    plain_stream_sum = _poll_until(
        lambda: _metric_sum(cloudwatch, "IncomingRecords", plain_stream_dims, window_start),
        lambda s: s == float(_N_RECORDS),
        timeout_s=180.0,
        interval_s=20.0,
        description=(
            f"the unarmed twin's STREAM-level IncomingRecords Sum to reach exactly {_N_RECORDS}, "
            "which is what makes its shard-level absence meaningful"
        ),
    )
    assert plain_stream_sum == float(_N_RECORDS), (
        f"the unarmed twin {plain['name']} reports stream-level IncomingRecords Sum "
        f"{plain_stream_sum}; expected exactly {_N_RECORDS}. Without this the absence below could "
        "just mean no metric pipeline reaches this stream at all"
    )
    plain_shard_sum = _metric_sum(
        cloudwatch, "IncomingRecords", plain_shard_dims, window_start
    )
    assert plain_shard_sum is None, (
        f"the unarmed twin {plain['name']} published a ShardId-dimensioned IncomingRecords Sum of "
        f"{plain_shard_sum} for {plain_shard} {latency_s:.0f}s after the puts, in the same window "
        f"in which the ARMED twin's arrived; enhanced monitoring is OFF on this stream so expected "
        "no datapoints at all"
    )
    plain_listed = _list_shard_metrics(cloudwatch, plain["name"], plain_shard)
    assert plain_listed == [], (
        f"ListMetrics reports ShardId-dimensioned AWS/Kinesis metrics {plain_listed} for the "
        f"unarmed twin's shard {plain_shard}; expected none"
    )

    # ---- Repair exactly the withheld thing, and demand delivery ----
    kinesis.enable_enhanced_monitoring(StreamName=plain["name"], ShardLevelMetrics=["ALL"])
    # Same asynchronous-activation rule applies to the repair leg: confirm before producing
    # traffic, or the repair's own puts can be the thing that silently never arrives.
    _poll_until(
        lambda: _enabled_shard_metrics(kinesis, plain["name"]),
        lambda s: bool(s),
        timeout_s=_ARM_CONFIRM_DEADLINE_S,
        interval_s=3.0,
        description=(
            f"DescribeStreamSummary to confirm enhanced monitoring active on the repaired twin "
            f"{plain['name']}"
        ),
    )
    repair_window_start = datetime.now(timezone.utc)
    for payload in _REPAIR_PAYLOADS:
        kinesis.put_record(StreamName=plain["name"], Data=payload, PartitionKey=_PARTITION_KEY)

    # Deadline derived from the latency MEASURED on the armed twin in this same run, not guessed.
    repair_deadline = max(3.0 * latency_s, 240.0)
    repaired_sum = _poll_until(
        lambda: _metric_sum(
            cloudwatch, "IncomingRecords", plain_shard_dims, repair_window_start
        ),
        lambda s: s == float(_REPAIR_RECORDS),
        timeout_s=repair_deadline,
        interval_s=20.0,
        description=(
            f"the previously-unarmed twin's ShardId-dimensioned IncomingRecords Sum for "
            f"{plain_shard} to reach exactly {_REPAIR_RECORDS} within {repair_deadline:.0f}s (3x "
            f"the {latency_s:.0f}s measured on the armed twin) once enhanced monitoring is enabled"
        ),
    )
    assert repaired_sum == float(_REPAIR_RECORDS), (
        f"after enabling enhanced monitoring, the ShardId-dimensioned IncomingRecords Sum for "
        f"{plain_shard} over the post-enable window is {repaired_sum}; expected exactly "
        f"{_REPAIR_RECORDS} — the records put after the enable, and none of the {_N_RECORDS} put "
        "before it"
    )
    repaired_listed = _list_shard_metrics(cloudwatch, plain["name"], plain_shard)
    assert "IncomingRecords" in repaired_listed, (
        f"ListMetrics still reports {repaired_listed} for shard {plain_shard} after enhanced "
        "monitoring was enabled and traffic flowed; expected IncomingRecords to be registered"
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


def _enabled_shard_metrics(kinesis, stream_name: str) -> set[str]:
    """The set of shard-level metric names DescribeStreamSummary reports as currently enabled."""
    entries = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
        "EnhancedMonitoring"
    ]
    return {m for e in entries for m in e.get("ShardLevelMetrics", [])}


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


def _metric_sum(cloudwatch, metric_name: str, dimensions: list, window_start) -> float | None:
    """Sum every datapoint in the window, or None when nothing has been published.

    None (rather than 0.0) is what keeps "never delivered" distinguishable from "delivered as zero".
    """
    resp = cloudwatch.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=window_start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return None
    return float(sum(dp["Sum"] for dp in datapoints))


def _list_shard_metrics(cloudwatch, stream_name: str, shard_id: str) -> list[str]:
    """AWS/Kinesis metric names CloudWatch has registered against this exact shard."""
    found: set[str] = set()
    paginator = cloudwatch.get_paginator("list_metrics")
    for page in paginator.paginate(
        Namespace=_NAMESPACE, Dimensions=[{"Name": "ShardId", "Value": shard_id}]
    ):
        for metric in page["Metrics"]:
            values = {d["Value"] for d in metric["Dimensions"]}
            if shard_id in values and stream_name in values:
                found.add(metric["MetricName"])
    return sorted(found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
