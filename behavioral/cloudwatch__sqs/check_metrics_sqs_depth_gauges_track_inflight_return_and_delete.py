"""metrics-sqs-depth-gauges-track-inflight-return-and-delete."""

# On real AWS:
# a queue with 5 sent and 2 received-but-held published ApproximateNumberOfMessagesVisible=3.0 and
# ApproximateNumberOfMessagesNotVisible=2.0 (Unit Count) on the same 60 s timestamp, with
# ApproximateAgeOfOldestMessage > 0 (Unit Seconds) on that timestamp; the first gauge datapoint
# arrived ~3 minutes after CreateQueue. Every wait below polls for the value; none asserts a latency.

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-sqs-depth-gauges-track-inflight-return-and-delete"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "sqs"]

_NS = "AWS/SQS"
_VIS = "ApproximateNumberOfMessagesVisible"
_NOTVIS = "ApproximateNumberOfMessagesNotVisible"
_DELAYED = "ApproximateNumberOfMessagesDelayed"
_AGE = "ApproximateAgeOfOldestMessage"
_DELETED = "NumberOfMessagesDeleted"

#: Five bodies of distinct lengths; the count is what the gauges must account for.
_BODIES = ("depth-a", "depth-bb", "depth-ccc", "depth-dddd", "depth-eeeee")
_HELD = 2
#: Per-phase budget for a gauge value to ARRIVE. Not a latency claim: SQS publishes these at a
#: one-minute cadence and this is how many cadences we are willing to wait for each transition.
_PHASE_BUDGET_S = 900.0
_DISCOVERY_BUDGET_S = 900.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html
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
    """The AWS/SQS depth gauges follow send, receive-and-hold, visibility reset and delete: Visible=3 /
    NotVisible=2, then 5 / 0, then 0 / 0 on later timestamps, NumberOfMessagesDeleted exactly 5, each
    with its unit and only the QueueName dimension -- the series depth alarms and autoscaling bind to."""
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    name = ctx.unique_name("sim2real-cwsqs-depth-")
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": "cloudwatch__sqs", "sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    start = datetime.now(timezone.utc) - timedelta(minutes=10)

    for body in _BODIES:
        sqs.send_message(QueueUrl=url, MessageBody=body)

    held: list[str] = []
    deadline = time.monotonic() + 120.0
    while len(held) < _HELD and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, VisibilityTimeout=1200, WaitTimeSeconds=5
        )
        held.extend(m["ReceiptHandle"] for m in resp.get("Messages", []))
    assert len(held) == _HELD, (
        f"the data plane did not hand out {_HELD} messages to hold in flight: got {len(held)}; the "
        f"gauge values below would not be attributable to this check"
    )

    # ---- phase 1: 3 visible, 2 in flight, backlog has an age -------------------------------- #
    ts1, s1 = _poll_joint(
        cw, name, start, None,
        {_VIS: lambda v: v == 3.0, _NOTVIS: lambda v: v == 2.0},
        description=f"{_VIS}=3 and {_NOTVIS}=2 on one timestamp for QueueName={name}",
    )
    for metric in (_VIS, _NOTVIS):
        assert s1[metric][ts1][1] == "Count", (
            f"AWS/SQS {metric} for QueueName={name} carries Unit {s1[metric][ts1][1]!r}, "
            f"expected 'Count'"
        )
    age_ts, age_s = _poll_joint(
        cw, name, start, None, {_AGE: lambda v: v > 0.0},
        description=f"{_AGE} > 0 for QueueName={name} while it holds a 3-message backlog",
    )
    assert age_s[_AGE][age_ts][1] == "Seconds", (
        f"AWS/SQS {_AGE} for QueueName={name} carries Unit {age_s[_AGE][age_ts][1]!r}, expected "
        f"'Seconds' — an age reported as Count is invisible to any value-only assertion"
    )

    # ---- phase 2: the held messages come BACK to visible ------------------------------------ #
    for handle in held:
        sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=handle, VisibilityTimeout=0)
    ts2, _ = _poll_joint(
        cw, name, start, ts1,
        {_VIS: lambda v: v == 5.0, _NOTVIS: lambda v: v == 0.0},
        description=(
            f"{_VIS}=5 and {_NOTVIS}=0 on a timestamp after {ts1.isoformat()} for QueueName={name}, "
            f"once the {_HELD} held messages were returned with ChangeMessageVisibility 0"
        ),
    )

    # ---- phase 3: drain everything, the gauges fall to zero --------------------------------- #
    deleted: list[str] = []
    deadline = time.monotonic() + 180.0
    while len(deleted) < len(_BODIES) and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            deleted.append(m["Body"])
    assert sorted(deleted) == sorted(_BODIES), (
        f"draining the queue deleted bodies {sorted(deleted)!r}, expected exactly "
        f"{sorted(_BODIES)!r}"
    )
    _poll_joint(
        cw, name, start, ts2,
        {_VIS: lambda v: v == 0.0, _NOTVIS: lambda v: v == 0.0, _AGE: lambda v: v == 0.0},
        description=(
            f"{_VIS}=0, {_NOTVIS}=0 and {_AGE}=0 on a timestamp after {ts2.isoformat()} for "
            f"QueueName={name}, once all {len(_BODIES)} messages were deleted"
        ),
    )
    deleted_sum = _poll_value(
        lambda: _sum(cw, name, _DELETED, start),
        lambda v: v is not None and v >= float(len(_BODIES)),
        description=f"{_DELETED} Sum for QueueName={name} reaching {len(_BODIES)}",
    )
    assert deleted_sum == float(len(_BODIES)), (
        f"AWS/SQS {_DELETED} Sum for QueueName={name} read {deleted_sum!r}; this check issued "
        f"exactly {len(_BODIES)} successful DeleteMessage calls"
    )

    # ---- series identity: the exact binding a dashboard or alarm names ---------------------- #
    want = {_VIS, _NOTVIS, _DELAYED, _AGE, _DELETED}
    listed = _poll_value(
        lambda: _list_metrics(cw, name),
        lambda got: want <= {m["MetricName"] for m in got},
        timeout_s=_DISCOVERY_BUDGET_S,
        description=f"ListMetrics naming {sorted(want)} for QueueName={name}",
    )
    for m in listed:
        if m["MetricName"] not in want:
            continue
        assert m["Namespace"] == _NS, f"series {m!r} is not in namespace {_NS!r}"
        assert m["Dimensions"] == [{"Name": "QueueName", "Value": name}], (
            f"AWS/SQS {m['MetricName']} is published under Dimensions {m['Dimensions']!r}; the "
            f"contract is exactly [{{'Name': 'QueueName', 'Value': {name!r}}}], and an alarm "
            f"bound to that list receives nothing from any other shape"
        )

    # Re-read after discovery: an over-count published late shows here, not at first arrival.
    final = _sum(cw, name, _DELETED, start)
    assert final == float(len(_BODIES)), (
        f"on re-read, AWS/SQS {_DELETED} Sum for QueueName={name} is {final!r}, expected "
        f"{float(len(_BODIES))}"
    )


# ===== helpers =====
def _series(cw, queue: str, metric: str, start: datetime, stat: str = "Maximum") -> dict:
    """{Timestamp: (value, Unit)} for one AWS/SQS series at 60 s resolution."""
    dps = cw.get_metric_statistics(
        Namespace=_NS,
        MetricName=metric,
        Dimensions=[{"Name": "QueueName", "Value": queue}],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=[stat],
    )["Datapoints"]
    return {d["Timestamp"]: (float(d[stat]), d.get("Unit")) for d in dps}


def _sum(cw, queue: str, metric: str, start: datetime) -> float | None:
    s = _series(cw, queue, metric, start, stat="Sum")
    return float(sum(v for v, _ in s.values())) if s else None


def _poll_joint(cw, queue, start, after, preds, *, timeout_s=_PHASE_BUDGET_S, interval_s=20.0,
                description="joint reading"):
    """Return (ts, series) for the first timestamp later than *after* on which EVERY metric in
    *preds* has a datapoint satisfying its predicate. Raises on the deadline; never partial."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        series = {m: _series(cw, queue, m, start) for m in preds}
        common = set.intersection(*(set(s) for s in series.values()))
        for ts in sorted(common):
            if after is not None and ts <= after:
                continue
            if all(pred(series[m][ts][0]) for m, pred in preds.items()):
                return ts, series
        last = {m: sorted((t.isoformat(), v) for t, (v, _) in s.items())[-4:]
                for m, s in series.items()}
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} never arrived within {timeout_s}s; last readings {last!r}"
            )
        time.sleep(interval_s)


def _poll_value(probe, ok, *, timeout_s=_PHASE_BUDGET_S, interval_s=20.0, description="value"):
    deadline = time.monotonic() + timeout_s
    while True:
        got = probe()
        if ok(got):
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} never arrived within {timeout_s}s; last {got!r}")
        time.sleep(interval_s)


def _list_metrics(cw, queue: str) -> list[dict]:
    out: list[dict] = []
    kwargs: dict = {"Namespace": _NS, "Dimensions": [{"Name": "QueueName", "Value": queue}]}
    while True:
        page = cw.list_metrics(**kwargs)
        out.extend(page["Metrics"])
        token = page.get("NextToken")
        if not token:
            return out
        kwargs["NextToken"] = token


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
