"""log-events-time-window-boundary-semantics."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "log-events-time-window-boundary-semantics"
GROUP = 'log-events'
SERVICES = ['logs']


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
    """GetLogEvents' time window is [startTime, endTime): startTime inclusive, endTime EXCLUSIVE, while
    FilterLogEvents' endTime is inclusive, as the API reference documents; an off-by-one boundary
    re-delivers the boundary event on every poll of a resumable tail.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-timewindow-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    # 1-second spacing so no boundary depends on sub-millisecond behaviour.
    t0 = _now_ms()
    t1 = t0 + 1000
    t2 = t0 + 2000
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": t0, "message": "window-t0"},
            {"timestamp": t1, "message": "window-t1"},
            {"timestamp": t2, "message": "window-t2"},
        ],
    )

    _poll_until(
        lambda: [
            e["message"]
            for e in svc.get_log_events(
                logGroupName=group, logStreamName=stream, startFromHead=True
            ).get("events", [])
        ],
        lambda msgs: msgs == ["window-t0", "window-t1", "window-t2"],
        timeout_s=60,
        interval_s=2.0,
        description="all 3 events readable in order",
    )

    def _get(start, end):
        resp = svc.get_log_events(
            logGroupName=group,
            logStreamName=stream,
            startFromHead=True,
            startTime=start,
            endTime=end,
        )
        return [e["message"] for e in resp.get("events", [])]

    def _filter(start, end):
        resp = svc.filter_log_events(logGroupName=group, startTime=start, endTime=end)
        return sorted(e["message"] for e in resp.get("events", []))

    # --- 1. GetLogEvents: startTime inclusive, endTime exclusive.
    got = _get(t1, t2)
    assert got == ["window-t1"], (
        "GetLogEvents(startTime=t1, endTime=t2) must include the event AT startTime and "
        f"exclude the event AT endTime, got {got!r}"
    )

    # --- 2. Widening endTime by 1ms pulls the boundary event in, proving the
    # exclusion above was the endTime rule and not a missing event.
    got_wide = _get(t1, t2 + 1)
    assert got_wide == ["window-t1", "window-t2"], (
        "GetLogEvents(startTime=t1, endTime=t2+1) must include both events, got "
        f"{got_wide!r}"
    )

    # --- 3. startTime is inclusive at the head of the stream.
    got_all = _get(t0, t2 + 1)
    assert got_all == ["window-t0", "window-t1", "window-t2"], (
        f"GetLogEvents(startTime=t0, endTime=t2+1) must include all three, got {got_all!r}"
    )

    # --- 4. Moving startTime 1ms past t0 drops exactly that event.
    got_trimmed = _get(t0 + 1, t2 + 1)
    assert got_trimmed == ["window-t1", "window-t2"], (
        f"GetLogEvents(startTime=t0+1, ...) must drop only window-t0, got {got_trimmed!r}"
    )

    # --- 5. FilterLogEvents over the SAME window: endTime is inclusive, so the
    # boundary event at t2 IS returned. This is the documented asymmetry.
    filtered = _filter(t1, t2)
    assert filtered == ["window-t1", "window-t2"], (
        "FilterLogEvents(startTime=t1, endTime=t2) must include the event AT endTime "
        "(inclusive), unlike GetLogEvents which excludes it; got "
        f"{filtered!r} while GetLogEvents over the same window gave {got!r}"
    )

    # --- 6. FilterLogEvents startTime is inclusive-of-later: an event strictly
    # before startTime is dropped.
    filtered_trimmed = _filter(t0 + 1, t2)
    assert filtered_trimmed == ["window-t1", "window-t2"], (
        f"FilterLogEvents(startTime=t0+1, ...) must drop only window-t0, got {filtered_trimmed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
