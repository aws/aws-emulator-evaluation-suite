"""metrics-sqs-dlq-redrive-lands-in-dlq-own-series-not-its-sent-count."""

# On real AWS:
# after a maxReceiveCount=1 redrive, the DLQ published ApproximateNumberOfMessagesVisible=1.0 under
# its OWN QueueName while its NumberOfMessagesSent series carried explicit 0.0 datapoints; the
# source published Visible=0.0 / NotVisible=0.0 and NumberOfMessagesSent Sum=1.0,
# NumberOfMessagesReceived Sum=1.0 (the receive that triggered the move returned nothing). This
# matches the AWS/SQS documentation for NumberOfMessagesSent: a manual send to a dead-letter queue is
# counted, a move caused by a failed processing attempt is not.

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-sqs-dlq-redrive-lands-in-dlq-own-series-not-its-sent-count"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "sqs"]

_NS = "AWS/SQS"
_VIS = "ApproximateNumberOfMessagesVisible"
_NOTVIS = "ApproximateNumberOfMessagesNotVisible"
_SENT = "NumberOfMessagesSent"
_RECV = "NumberOfMessagesReceived"
_PHASE_BUDGET_S = 900.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A message redriven to a dead-letter queue shows up in the DLQ's OWN depth series and leaves the
    source's, while the DLQ's NumberOfMessagesSent stays an explicit 0 -- a redrive is not a send; one
    manual SendMessage then moves it to exactly 1."""
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    dlq_name, dlq_url = _create_queue(ctx, sqs, "dlq-")
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    src_name, src_url = _create_queue(
        ctx, sqs, "src-",
        {"RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "1"})},
    )
    start = datetime.now(timezone.utc) - timedelta(minutes=10)

    sqs.send_message(QueueUrl=src_url, MessageBody="poison-body")
    first = sqs.receive_message(QueueUrl=src_url, VisibilityTimeout=1, WaitTimeSeconds=10)
    assert len(first.get("Messages", [])) == 1, (
        f"the first receive on the source did not return the one message sent: {first!r}"
    )

    # The receive AFTER maxReceiveCount is exhausted performs the move and returns nothing.
    moved = False
    deadline = time.monotonic() + 120.0
    while not moved and time.monotonic() < deadline:
        time.sleep(2)
        again = sqs.receive_message(QueueUrl=src_url, VisibilityTimeout=1, WaitTimeSeconds=2)
        assert not again.get("Messages"), (
            f"the source redelivered the message past maxReceiveCount=1: {again.get('Messages')!r}"
        )
        n = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=[
            "ApproximateNumberOfMessages"])["Attributes"]["ApproximateNumberOfMessages"]
        moved = n == "1"
    assert moved, "the message never reached the DLQ per its ApproximateNumberOfMessages attribute"

    # ---- the move is billed to the DLQ's own depth series ------------------------------------ #
    ts_dlq, s_dlq = _poll_joint(
        cw, dlq_name, start, None, {_VIS: lambda v: v == 1.0, _NOTVIS: lambda v: v == 0.0},
        description=f"{_VIS}=1 and {_NOTVIS}=0 for the DLQ QueueName={dlq_name}",
    )
    assert s_dlq[_VIS][ts_dlq][1] == "Count", (
        f"DLQ {_VIS} carries Unit {s_dlq[_VIS][ts_dlq][1]!r}, expected 'Count'"
    )
    _poll_joint(
        cw, src_name, start, None, {_VIS: lambda v: v == 0.0, _NOTVIS: lambda v: v == 0.0},
        description=f"{_VIS}=0 and {_NOTVIS}=0 for the source QueueName={src_name} after the move",
    )
    src_sent = _poll_value(lambda: _sum(cw, src_name, _SENT, start),
                           lambda v: v is not None and v >= 1.0,
                           description=f"{_SENT} Sum for the source {src_name} reaching 1")
    src_recv = _poll_value(lambda: _sum(cw, src_name, _RECV, start), lambda v: v is not None,
                           description=f"{_RECV} Sum for the source {src_name} arriving")
    assert (src_sent, src_recv) == (1.0, 1.0), (
        f"source {src_name} accounted Sent={src_sent!r} Received={src_recv!r}; exactly one "
        f"SendMessage and one message-returning ReceiveMessage were made against it"
    )

    # ---- the redrive is NOT a send on the DLQ: an explicit zero, published after the move ----- #
    # Waiting for a Sent datapoint at or after the gauge timestamp that already shows the moved
    # message means the counter has demonstrably been published for the period containing the
    # move; "absent" does not satisfy it, so this cannot pass on a dead series.
    dlq_sent_series = _poll_value(
        lambda: _series(cw, dlq_name, _SENT, start, stat="Sum"),
        lambda s: any(ts >= ts_dlq for ts in s),
        description=f"a {_SENT} datapoint at or after {ts_dlq.isoformat()} for the DLQ {dlq_name}",
    )
    dlq_sent = sum(v for v, _ in dlq_sent_series.values())
    assert dlq_sent == 0.0, (
        f"the DLQ {dlq_name}'s {_SENT} Sum is {dlq_sent!r} although nothing was sent to it: the "
        f"redrive was counted as a send ({sorted((t.isoformat(), v) for t, (v, _) in dlq_sent_series.items())!r})"
    )

    # ---- positive control: a MANUAL send to the same DLQ is counted ------------------------- #
    sqs.send_message(QueueUrl=dlq_url, MessageBody="manual-body")
    after_sent = _poll_value(lambda: _sum(cw, dlq_name, _SENT, start),
                             lambda v: v is not None and v >= 1.0,
                             description=f"{_SENT} Sum for the DLQ {dlq_name} reaching 1 after a "
                                         f"manual SendMessage")
    assert after_sent == 1.0, f"DLQ {_SENT} Sum after one manual send is {after_sent!r}"
    _poll_joint(
        cw, dlq_name, start, ts_dlq, {_VIS: lambda v: v == 2.0},
        description=f"{_VIS}=2 for the DLQ {dlq_name} after the manual send joined the redriven one",
    )


# ===== helpers =====
def _create_queue(ctx, sqs, label: str, attributes: dict | None = None) -> tuple[str, str]:
    name = ctx.unique_name(f"sim2real-cwsqs-{label}")
    url = sqs.create_queue(
        QueueName=name,
        Attributes=attributes or {},
        tags={"sim2real": "cloudwatch__sqs", "sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return name, url


def _series(cw, queue: str, metric: str, start: datetime, stat: str = "Maximum") -> dict:
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
    deadline = time.monotonic() + timeout_s
    while True:
        series = {m: _series(cw, queue, m, start) for m in preds}
        common = set.intersection(*(set(s) for s in series.values()))
        for ts in sorted(common):
            if after is not None and ts <= after:
                continue
            if all(pred(series[m][ts][0]) for m, pred in preds.items()):
                return ts, series
        if time.monotonic() >= deadline:
            last = {m: sorted((t.isoformat(), v) for t, (v, _) in s.items())[-4:]
                    for m, s in series.items()}
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
