"""put-log-events-rejects-out-of-window-events."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-rejects-out-of-window-events"
GROUP = 'log-events'
SERVICES = ['logs']

_DAY_MS = 24 * 60 * 60 * 1000
_HOUR_MS = 60 * 60 * 1000


# ===== helpers =====
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


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents reports out-of-window events in ``rejectedLogEventsInfo`` on a 200 response
    (``tooOldLogEventEndIndex`` exclusive, ``tooNewLogEventStartIndex`` inclusive) and the rejected
    events are genuinely not ingested.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-outofwindow-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    now = _now_ms()

    # --- 1. Too old: 20 days in the past, well past the 14-day boundary.
    too_old = svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now - 20 * _DAY_MS, "message": "too-old-event"}],
    )
    rejected_old = too_old.get("rejectedLogEventsInfo")
    assert rejected_old is not None, (
        "PutLogEvents with a 20-day-old event must return rejectedLogEventsInfo, got "
        f"{too_old!r}"
    )
    assert rejected_old.get("tooOldLogEventEndIndex") == 1, (
        "tooOldLogEventEndIndex is EXCLUSIVE, so a single too-old event at index 0 must "
        f"report 1, got {rejected_old!r}"
    )
    assert "tooNewLogEventStartIndex" not in rejected_old, (
        f"a too-OLD event must not also be reported as too new: {rejected_old!r}"
    )

    # --- 2. Too new: 4 hours in the future, past the 2-hour boundary.
    too_new = svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now + 4 * _HOUR_MS, "message": "too-new-event"}],
    )
    rejected_new = too_new.get("rejectedLogEventsInfo")
    assert rejected_new is not None, (
        "PutLogEvents with an event 4 hours in the future must return rejectedLogEventsInfo, "
        f"got {too_new!r}"
    )
    assert rejected_new.get("tooNewLogEventStartIndex") == 0, (
        "tooNewLogEventStartIndex is INCLUSIVE, so a single too-new event at index 0 must "
        f"report 0, got {rejected_new!r}"
    )
    assert "tooOldLogEventEndIndex" not in rejected_new, (
        f"a too-NEW event must not also be reported as too old: {rejected_new!r}"
    )

    # --- 3. Control: an in-window batch is accepted with NO rejection report.
    accepted = svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now, "message": "in-window-event"}],
    )
    assert "rejectedLogEventsInfo" not in accepted, (
        f"an entirely valid batch must omit rejectedLogEventsInfo, got {accepted!r}"
    )

    # --- 4. Effect absent: only the in-window event is readable, over a query
    # window wide enough to have surfaced BOTH rejected events had they landed.
    def _messages():
        resp = svc.get_log_events(
            logGroupName=group,
            logStreamName=stream,
            startFromHead=True,
            startTime=now - 30 * _DAY_MS,
            endTime=now + 8 * _HOUR_MS,
        )
        return [e["message"] for e in resp.get("events", [])]

    _poll_until(
        _messages,
        lambda msgs: "in-window-event" in msgs,
        timeout_s=60,
        interval_s=2.0,
        description="the in-window event becomes readable",
    )

    # Hold the invariant across a bounded settle window so a late-arriving
    # rejected event cannot slip past a single-shot read.
    for _ in range(6):
        msgs = _messages()
        assert msgs == ["in-window-event"], (
            "rejected events must never be ingested; GetLogEvents over "
            f"[now-30d, now+8h] returned {msgs!r}"
        )
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
