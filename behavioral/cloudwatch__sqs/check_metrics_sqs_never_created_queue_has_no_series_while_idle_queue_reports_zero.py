"""metrics-sqs-never-created-queue-has-no-series-while-idle-queue-reports-zero."""

# On real AWS, a queue that EXISTS but is idle, never sent to or received from, publishes explicit
# 0.0 datapoints for every depth gauge and for NumberOfMessagesSent/Received/Deleted, and
# SentMessageSize alone stays absent. The empty-vs-zero distinction is real, but it sits one step
# further out: a QueueName that was never created returns an empty Datapoints list for every
# metric, on every sample over 15 minutes, while the idle queue beside it reports zeros. That is
# what this check asserts.

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-sqs-never-created-queue-has-no-series-while-idle-queue-reports-zero"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "sqs"]

_NS = "AWS/SQS"
_GAUGES = (
    "ApproximateNumberOfMessagesVisible",
    "ApproximateNumberOfMessagesNotVisible",
    "ApproximateNumberOfMessagesDelayed",
    "ApproximateAgeOfOldestMessage",
)
_COUNTERS = ("NumberOfMessagesSent", "NumberOfMessagesReceived", "NumberOfMessagesDeleted")
_SIZE = "SentMessageSize"
_ALL = _GAUGES + _COUNTERS + (_SIZE, "NumberOfEmptyReceives")
_ARRIVAL_BUDGET_S = 900.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A never-created QueueName, or the idle queue under a wrong dimension name or mis-cased namespace,
    has NO AWS/SQS series, while the idle queue correctly addressed reports explicit 0.0 for every gauge
    and counter: a synthesised zero would make a typo'd alarm look healthy forever."""
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    idle = ctx.unique_name("sim2real-cwsqs-idle-")
    url = sqs.create_queue(
        QueueName=idle, tags={"sim2real": "cloudwatch__sqs", "sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    # Minted by the same generator and never passed to CreateQueue, so no run can occupy it.
    never = ctx.unique_name("sim2real-cwsqs-never-")
    start = datetime.now(timezone.utc) - timedelta(minutes=10)

    # ---- positive control: the idle queue publishes EXPLICIT zeros --------------------------- #
    want = _GAUGES + _COUNTERS
    deadline = time.monotonic() + _ARRIVAL_BUDGET_S
    while True:
        idle_series = {m: _points(cw, _NS, "QueueName", idle, m, start) for m in want}
        if all(idle_series.values()):
            break
        assert time.monotonic() < deadline, (
            f"the idle queue {idle} never published a datapoint for "
            f"{sorted(m for m, p in idle_series.items() if not p)!r} within {_ARRIVAL_BUDGET_S}s; "
            f"an existing queue reports its gauges and counters every period, zero-valued when idle"
        )
        time.sleep(20.0)
    nonzero = {m: p for m, p in idle_series.items() if any(v != 0.0 for v in p)}
    assert not nonzero, (
        f"the idle queue {idle} (no traffic at all) published non-zero values {nonzero!r}"
    )

    # ---- the absences, each read after the pipeline above proved live ------------------------ #
    for metric in _ALL:
        got = _points(cw, _NS, "QueueName", never, metric, start)
        assert got == [], (
            f"AWS/SQS {metric} for QueueName={never} — a queue that was NEVER created — returned "
            f"datapoints {got!r}; it must return an empty list, not a synthesised zero"
        )
    size = _points(cw, _NS, "QueueName", idle, _SIZE, start)
    assert size == [], (
        f"AWS/SQS {_SIZE} for the idle queue {idle} returned {size!r}: no message was sent, so there "
        f"is no size sample to publish (the counters above are zero; this series is absent)"
    )
    for metric in ("ApproximateNumberOfMessagesVisible", "NumberOfMessagesSent"):
        wrong_dim = _points(cw, _NS, "QueueUrl", url, metric, start)
        assert wrong_dim == [], (
            f"AWS/SQS {metric} addressed as Dimensions=[QueueUrl={url}] returned {wrong_dim!r}; SQS "
            f"publishes under QueueName only, so a series bound to any other dimension is empty"
        )
        wrong_ns = _points(cw, "aws/sqs", "QueueName", idle, metric, start)
        assert wrong_ns == [], (
            f"{metric} for QueueName={idle} in namespace 'aws/sqs' returned {wrong_ns!r}; "
            f"namespaces are case-sensitive and the series lives in {_NS!r} only"
        )

    # ---- the control still holds after the absence reads ------------------------------------- #
    again = _points(cw, _NS, "QueueName", idle, "ApproximateNumberOfMessagesVisible", start)
    assert again and set(again) == {0.0}, (
        f"after the absence reads, the idle queue's correctly-addressed Visible series read "
        f"{again!r}; the absences are only meaningful while it is still served as zeros"
    )


# ===== helpers =====
def _points(cw, namespace: str, dim: str, value: str, metric: str, start: datetime) -> list[float]:
    dps = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=[{"Name": dim, "Value": value}],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=["Maximum"],
    )["Datapoints"]
    return [float(d["Maximum"]) for d in sorted(dps, key=lambda d: d["Timestamp"])]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
