"""sqs-service-metrics-sum-exactly-the-driven-traffic-per-queue."""

# On real AWS:
#   - SQS pushes queue metrics to CloudWatch at one-minute intervals, so the four counters
#     arrive within a few minutes of the traffic and hold one value across two intervals.
#   - Sum == 7 sends, 7 received, 3 empty receives, exactly: a ReceiveMessage returning k messages
#     counts k, not 1.
#   - SentMessageSize Sum == 357.0, the exact UTF-8 byte total of the 7 bodies: no attribute or
#     envelope overhead counted.
#   - Unit is exactly "Count" for the three counters and "Bytes" for SentMessageSize.
#   - The only dimension set ListMetrics reports is {("QueueName",)}.
#   - Three WaitTimeSeconds=0 polls against the drained queue return zero messages every time.
#   - The silent twin (created in the same instant, never sent to or received from) reports no
#     sent or received traffic under its own QueueName: its NumberOfMessagesSent and
#     NumberOfMessagesReceived series hold no datapoint or an explicit Sum == 0.0, never a count.
#     SentMessageSize stays absent, a size statistic with no sample when zero bytes moved. One aggregate account-wide
#     series instead of one per queue would show the busy queue's 7 on the twin.

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "sqs-service-metrics-sum-exactly-the-driven-traffic-per-queue"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "sqs"]

#: Seven bodies of DISTINCT, non-round lengths. The byte total (357) is not a multiple of the
#: count, so a target that publishes "7 * some constant size" cannot land on it by accident.
_BODIES = (
    "s" * 11,
    "s" * 13,
    "s" * 29,
    "s" * 41,
    "s" * 59,
    "s" * 97,
    "s" * 107,
)
_N_SENT = len(_BODIES)
_BYTES_SENT = float(sum(len(b.encode("utf-8")) for b in _BODIES))
_N_EMPTY_POLLS = 3

#: Ceiling on the busy queue's counters arriving and holding steady, not a sleep.
_METRIC_BUDGET_S = 360.0
#: Two of SQS's one-minute publication intervals: a reading that holds this long has seen every
#: interval the traffic can land in, so a later over-count would show.
_STABLE_WINDOW_S = 120.0
#: The silent twin's zero-traffic hold, two publication intervals, entered only AFTER the busy
#: queue has published, so it measures a decision and not a delay.
_ABSENCE_HOLD_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/monitoring-using-cloudwatch.html
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
    """AWS/SQS NumberOfMessagesSent, SentMessageSize, NumberOfMessagesReceived and NumberOfEmptyReceives
    sum to exactly the driven traffic under only QueueName and the documented units, while an idle
    twin reports no traffic and no size, each holding across two one-minute publication intervals.
    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html"""
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    busy = _create_queue(ctx, sqs, "busy-")
    # Created in the SAME instant and never touched: its absence is dated from the same moment as
    # the busy queue's traffic, so "no datapoint" cannot be "the queue is too young".
    silent = _create_queue(ctx, sqs, "silent-")

    # ---- drive exactly the traffic we will demand an account of ------------------------------ #
    for body in _BODIES:
        sqs.send_message(QueueUrl=busy, MessageBody=body)

    received: list[str] = []
    deadline = time.monotonic() + 120.0
    while len(received) < _N_SENT and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=busy, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            received.append(msg["Body"])
            sqs.delete_message(QueueUrl=busy, ReceiptHandle=msg["ReceiptHandle"])
    assert len(received) == _N_SENT, (
        f"the data plane itself did not deliver: received {len(received)} bodies "
        f"{sorted(received)!r} for the {_N_SENT} sent, so no metric total measured below would be "
        f"attributable to this check"
    )
    assert sorted(received) == sorted(_BODIES), (
        f"received bodies {sorted(received)!r} differ from the {_N_SENT} sent {sorted(_BODIES)!r}"
    )

    # Exactly _N_EMPTY_POLLS short polls against a queue we have just drained.
    for i in range(_N_EMPTY_POLLS):
        empty = sqs.receive_message(QueueUrl=busy, MaxNumberOfMessages=10, WaitTimeSeconds=0)
        assert "Messages" not in empty or not empty["Messages"], (
            f"short poll {i + 1} of {_N_EMPTY_POLLS} against the drained queue returned "
            f"{len(empty.get('Messages', []))} message(s); the empty-receive count this check "
            f"demands is then not {_N_EMPTY_POLLS}"
        )

    busy_name = busy.rsplit("/", 1)[-1]
    silent_name = silent.rsplit("/", 1)[-1]
    window_start = datetime.now(timezone.utc) - timedelta(minutes=30)

    def _stat(queue_name: str, metric: str, stat: str = "Sum") -> list[dict]:
        return cw.get_metric_statistics(
            Namespace="AWS/SQS",
            MetricName=metric,
            Dimensions=[{"Name": "QueueName", "Value": queue_name}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=10),
            Period=300,
            Statistics=[stat, "SampleCount", "Maximum"],
        )["Datapoints"]

    def _sum(queue_name: str, metric: str) -> float | None:
        dps = _stat(queue_name, metric)
        if not dps:
            return None
        return float(sum(d["Sum"] for d in dps))

    # ---- the terminal read, at the CONSUMER, behind a stability requirement ------------------- #
    # A one-sided "poll until it reaches 7" can only ever detect an UNDER-count: it stops looking
    # the instant the target is met, so a target that publishes 7 now and 4 more later passes it.
    # Requiring the whole four-metric tuple to hold one value across two publication intervals
    # catches over-count as well. An incomplete reading resets the anchor, so this can never
    # "stabilise" on absence.
    def _tuple() -> tuple[float, float, float, float] | None:
        vals = [
            _sum(busy_name, m)
            for m in (
                "NumberOfMessagesSent",
                "SentMessageSize",
                "NumberOfMessagesReceived",
                "NumberOfEmptyReceives",
            )
        ]
        if any(v is None for v in vals):
            return None
        return tuple(vals)  # type: ignore[return-value]

    sent, size, recv, empties = _poll_until_stable(
        _tuple,
        window_s=_STABLE_WINDOW_S,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=10.0,
        description=(
            f"the four AWS/SQS counters for QueueName={busy_name} settling on one value "
            f"(SQS publishes at one-minute intervals)"
        ),
    )

    assert sent == float(_N_SENT), (
        f"AWS/SQS NumberOfMessagesSent Sum for QueueName={busy_name} settled at {sent!r}; this "
        f"check issued exactly {_N_SENT} SendMessage calls, so the Sum must be {float(_N_SENT)}"
    )
    assert size == _BYTES_SENT, (
        f"AWS/SQS SentMessageSize Sum for QueueName={busy_name} settled at {size!r}, expected "
        f"{_BYTES_SENT} — the byte length of the {_N_SENT} bodies this check sent, whose lengths "
        f"are all distinct and non-round so no per-message constant can reach that total"
    )
    assert recv == float(_N_SENT), (
        f"AWS/SQS NumberOfMessagesReceived Sum for QueueName={busy_name} settled at {recv!r}, "
        f"expected {float(_N_SENT)} — the number of message bodies ReceiveMessage actually "
        f"returned to this check"
    )
    assert empties == float(_N_EMPTY_POLLS), (
        f"AWS/SQS NumberOfEmptyReceives Sum for QueueName={busy_name} settled at {empties!r}, "
        f"expected {float(_N_EMPTY_POLLS)}. This is the one counter here that records a call which "
        f"returned NO payload: a target that emits telemetry only when bytes move cannot produce it"
    )

    # ---- units and the dimension identity ---------------------------------------------------- #
    for metric, want_unit in (
        ("NumberOfMessagesSent", "Count"),
        ("NumberOfMessagesReceived", "Count"),
        ("NumberOfEmptyReceives", "Count"),
        ("SentMessageSize", "Bytes"),
    ):
        dps = _stat(busy_name, metric)
        assert dps, f"AWS/SQS {metric} for QueueName={busy_name} vanished on re-read: {dps!r}"
        units = {d.get("Unit") for d in dps}
        assert units == {want_unit}, (
            f"AWS/SQS {metric} datapoints for QueueName={busy_name} carry Unit(s) {units!r}, "
            f"expected exactly {{{want_unit!r}}} — a count reported as Bytes or a size reported "
            f"as Count is invisible to any assertion on the value alone"
        )

    published = _dimension_sets(cw, "AWS/SQS", busy_name)
    assert published == {("QueueName",)}, (
        f"ListMetrics reports dimension sets {sorted(published)!r} for the AWS/SQS series naming "
        f"QueueName={busy_name}; SQS documents a single dimension, so the only set must be "
        f"('QueueName',). Extra dimensions mean the target invented a series shape"
    )

    # ---- the structural control: the silent twin is billed to ITS OWN dimension, at zero ------ #
    # Entered only now, i.e. after the busy queue's own datapoints have settled, so the pipeline is
    # demonstrably live and this is a decision rather than a delay. SQS reports the twin's
    # NumberOfMessagesSent and NumberOfMessagesReceived either not yet at all (a queue only minutes
    # old) or as an explicit Sum == 0.0; never a count. SentMessageSize has no sample when no bytes
    # moved, so it stays absent. A target that aggregates every queue into one account-wide series
    # fails this: the twin's dimension would then read the busy queue's 7.
    _assert_twin_silent(
        lambda: [
            _sum(silent_name, m)
            for m in ("NumberOfMessagesSent", "NumberOfMessagesReceived", "SentMessageSize")
        ],
        hold_s=_ABSENCE_HOLD_S,
        interval_s=20.0,
        description=(
            f"the silent twin queue {silent_name}, created in the same instant as {busy_name} and "
            f"never sent to or received from, accounts for no sent/received traffic under its "
            f"own QueueName dimension (not the busy queue's 7, and no SentMessageSize sample)"
        ),
    )

    # ---- positive control, after the negative ------------------------------------------------- #
    final = _sum(busy_name, "NumberOfMessagesSent")
    assert final == float(_N_SENT), (
        f"after the twin's absence window the busy queue's NumberOfMessagesSent Sum read {final!r}, "
        f"expected {float(_N_SENT)} — the absence above is only meaningful while the positive "
        f"series is still being served"
    )


# ===== helpers =====
def _create_queue(ctx, sqs, label: str) -> str:
    """Create a tagged queue and register its teardown. No adopt path: a fresh queue is required
    because every count below is dated from its creation."""
    name = ctx.unique_name(f"sim2real-cwsqs-{label}")
    url = sqs.create_queue(
        QueueName=name,
        tags={"sim2real": "cloudwatch__sqs", "sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _dimension_sets(cw, namespace: str, queue_name: str) -> set[tuple[str, ...]]:
    """Every dimension-name set CloudWatch reports for series in *namespace* naming *queue_name*."""
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": "QueueName", "Value": queue_name}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_until_stable(probe, *, window_s, timeout_s, interval_s=20.0, description="reading"):
    """Return probe()'s value once two readings >= window_s apart are EQUAL and complete.

    Raises on its deadline; it never returns a partial or absent reading.
    """
    deadline = time.monotonic() + timeout_s
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if last is None:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never held one complete value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


def _assert_twin_silent(probe, *, hold_s, interval_s=30.0, description="reading"):
    """Assert continuously for hold_s that probe() reads [sent, received, size] with sent and
    received each absent (None) or exactly 0.0, and size absent."""
    deadline = time.monotonic() + hold_s
    while True:
        sent, received, size = probe()
        assert all(v is None or v == 0.0 for v in (sent, received)) and size is None, (
            f"{description}: read sent={sent!r} received={received!r} size={size!r}, expected no "
            f"count other than 0.0 and no size sample for the whole {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
