"""out-of-order-cross-batch-writes-are-read-back-in-timestamp-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "out-of-order-cross-batch-writes-are-read-back-in-timestamp-order"
GROUP = 'log-events'
SERVICES = ['logs']

#: Batches are submitted in this order; each entry is (offset_s, label). The offsets
#: are 10s apart so no two events can share a millisecond -- AWS guarantees no order
#: between events with equal timestamps, and asserting one would be asserting more
#: than the contract.
_BATCHES = [
    (20, "third-in-time"),
    (0, "first-in-time"),
    (10, "second-in-time"),
]
_EVENTS_PER_BATCH = 3


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")




@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Batches submitted in an order that contradicts their timestamps are read back as one stream
    ordered by timestamp, not arrival, with every event present.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
    """
    svc = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-lg-order-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    # A batch may not span more than 24h and no timestamp may be more than 2h in the
    # future or older than the retention window, so the whole spread sits in the last
    # 60 seconds.
    base = _now_ms() - 60_000

    expected: list[tuple[int, str]] = []
    for offset_s, label in _BATCHES:
        batch = []
        for i in range(_EVENTS_PER_BATCH):
            ts = base + offset_s * 1000 + i * 100
            msg = f"sim2real-{label}-{i}"
            batch.append({"timestamp": ts, "message": msg})
            expected.append((ts, msg))
        resp = svc.put_log_events(
            logGroupName=group, logStreamName=stream, logEvents=batch
        )
        assert "rejectedLogEventsInfo" not in resp, (
            f"batch {label!r} was partially rejected, so the ordering property below would be "
            f"asserted over an incomplete stream: {resp!r}"
        )

    all_written = [msg for _, msg in expected]
    timestamp_sorted_messages = [msg for _, msg in sorted(expected, key=lambda p: p[0])]
    assert timestamp_sorted_messages != all_written, (
        "fixture sanity: the submission order must differ from the timestamp order, otherwise "
        f"this check cannot distinguish the two; got {all_written!r}"
    )

    def _read():
        events: list[dict] = []
        token = None
        while True:
            kwargs = {
                "logGroupName": group,
                "logStreamName": stream,
                "startFromHead": True,
            }
            if token is not None:
                kwargs["nextToken"] = token
            resp = svc.get_log_events(**kwargs)
            events.extend(resp.get("events", []))
            new_token = resp.get("nextForwardToken")
            if new_token == token or not resp.get("events"):
                break
            token = new_token
        return events

    events = _poll_until(
        _read,
        lambda evs: len(evs) == len(all_written),
        timeout_s=120,
        interval_s=3.0,
        description=f"all {len(all_written)} events across the three out-of-order batches become readable",
    )

    returned_messages = [e["message"] for e in events]
    timestamps = [e["timestamp"] for e in events]

    assert returned_messages == timestamp_sorted_messages, (
        f"events came back in arrival order rather than timestamp order: got "
        f"{returned_messages!r}, expected {timestamp_sorted_messages!r} (submission order was "
        f"{all_written!r})"
    )
    assert timestamps == sorted(timestamps), (
        f"GetLogEvents returned non-monotonic timestamps: {timestamps!r}"
    )
    assert len(returned_messages) == len(all_written), (
        f"{len(returned_messages)!r} events recovered from {len(all_written)!r} written across "
        f"three out-of-order batches"
    )
    assert set(returned_messages) == set(all_written), (
        "the recovered set differs from the written set; missing "
        f"{sorted(set(all_written) - set(returned_messages))!r}, unexpected "
        f"{sorted(set(returned_messages) - set(all_written))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
