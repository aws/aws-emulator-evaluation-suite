"""metrics-sqs-delayed-message-counted-only-in-delayed-series."""

# On real AWS:
# one message sent with DelaySeconds=900 published ApproximateNumberOfMessagesDelayed=1.0,
# ApproximateNumberOfMessagesVisible=0.0, ApproximateNumberOfMessagesNotVisible=0.0 and
# ApproximateAgeOfOldestMessage=0.0 on the same timestamp, on every sample for 5 minutes; a twin
# queue holding one undelayed message read Visible=1.0 / Delayed=0.0 with Age > 0 (Unit Seconds).

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-sqs-delayed-message-counted-only-in-delayed-series"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "sqs"]

_NS = "AWS/SQS"
_VIS = "ApproximateNumberOfMessagesVisible"
_NOTVIS = "ApproximateNumberOfMessagesNotVisible"
_DELAYED = "ApproximateNumberOfMessagesDelayed"
_AGE = "ApproximateAgeOfOldestMessage"

#: The SQS maximum. The check finishes long before it elapses, so the message is delayed for the
#: whole observation — the delay is the subject, not something the check waits out.
_DELAY_S = 900
_PHASE_BUDGET_S = 600.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """A message sent with DelaySeconds counts only in ApproximateNumberOfMessagesDelayed (Visible,
    NotVisible and Age all 0), while a twin queue's undelayed message reads Visible=1 with a non-zero
    Age: a delayed message is observable only through this gauge."""
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    delayed_name, delayed_url = _create_queue(ctx, sqs, "delayed-")
    ready_name, ready_url = _create_queue(ctx, sqs, "ready-")
    start = datetime.now(timezone.utc) - timedelta(minutes=10)

    sqs.send_message(QueueUrl=delayed_url, MessageBody="delayed-body", DelaySeconds=_DELAY_S)
    sqs.send_message(QueueUrl=ready_url, MessageBody="ready-body")

    # The data plane agrees the delayed message is not yet receivable.
    got = sqs.receive_message(QueueUrl=delayed_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    assert not got.get("Messages"), (
        f"a message sent with DelaySeconds={_DELAY_S} was receivable immediately: "
        f"{got.get('Messages')!r}"
    )

    # ---- positive control: the undelayed twin is counted as visible, with an age -------------- #
    ts_r, s_r = _poll_joint(
        cw, ready_name, start,
        {_VIS: lambda v: v == 1.0, _DELAYED: lambda v: v == 0.0, _AGE: lambda v: v > 0.0},
        description=f"{_VIS}=1, {_DELAYED}=0, {_AGE}>0 on one timestamp for QueueName={ready_name}",
    )
    assert s_r[_AGE][ts_r][1] == "Seconds", (
        f"AWS/SQS {_AGE} for QueueName={ready_name} carries Unit {s_r[_AGE][ts_r][1]!r}, "
        f"expected 'Seconds'"
    )

    # ---- the subject: the delayed message is ONLY in the Delayed gauge ------------------------ #
    ts_d, s_d = _poll_joint(
        cw, delayed_name, start,
        {_DELAYED: lambda v: v == 1.0, _VIS: lambda v: True, _NOTVIS: lambda v: True,
         _AGE: lambda v: True},
        description=f"{_DELAYED}=1 alongside its sibling gauges for QueueName={delayed_name}",
    )
    got_vals = {m: s_d[m][ts_d][0] for m in (_DELAYED, _VIS, _NOTVIS, _AGE)}
    assert got_vals == {_DELAYED: 1.0, _VIS: 0.0, _NOTVIS: 0.0, _AGE: 0.0}, (
        f"on {ts_d.isoformat()} the delayed queue {delayed_name} read {got_vals!r}; a message "
        f"inside its DelaySeconds window belongs to {_DELAYED} alone — Visible, NotVisible and "
        f"the age of the oldest AVAILABLE message must all be 0"
    )
    for metric in (_DELAYED, _VIS, _NOTVIS):
        assert s_d[metric][ts_d][1] == "Count", (
            f"AWS/SQS {metric} for QueueName={delayed_name} carries Unit "
            f"{s_d[metric][ts_d][1]!r}, expected 'Count'"
        )


# ===== helpers =====
def _create_queue(ctx, sqs, label: str) -> tuple[str, str]:
    name = ctx.unique_name(f"sim2real-cwsqs-{label}")
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": "cloudwatch__sqs", "sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return name, url


def _series(cw, queue: str, metric: str, start: datetime) -> dict:
    dps = cw.get_metric_statistics(
        Namespace=_NS,
        MetricName=metric,
        Dimensions=[{"Name": "QueueName", "Value": queue}],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=["Maximum"],
    )["Datapoints"]
    return {d["Timestamp"]: (float(d["Maximum"]), d.get("Unit")) for d in dps}


def _poll_joint(cw, queue, start, preds, *, timeout_s=_PHASE_BUDGET_S, interval_s=20.0,
                description="joint reading"):
    """First timestamp on which EVERY metric in *preds* has a datapoint satisfying its predicate."""
    deadline = time.monotonic() + timeout_s
    while True:
        series = {m: _series(cw, queue, m, start) for m in preds}
        common = set.intersection(*(set(s) for s in series.values()))
        for ts in sorted(common):
            if all(pred(series[m][ts][0]) for m, pred in preds.items()):
                return ts, series
        if time.monotonic() >= deadline:
            last = {m: sorted((t.isoformat(), v) for t, (v, _) in s.items())[-4:]
                    for m, s in series.items()}
            raise AssertionError(
                f"{description} never arrived within {timeout_s}s; last readings {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
