"""deep-cwlogs-semantics-put-log-events-mixed-window-batch-partially-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-put-log-events-mixed-window-batch-partially-accepted"
GROUP = "ingestion"
SERVICES = ["logs"]

_MINUTE_MS = 60 * 1000
_HOUR_MS = 60 * _MINUTE_MS
_DAY_MS = 24 * _HOUR_MS


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """One PutLogEvents batch holding too-old, in-window and too-new events is partially accepted:
    both rejection indices are reported, exactly the in-window events are stored, and a second
    batch straddling the 14-day floor rejects only the event past it."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-mixwin-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    mixed = "mixed"
    floor = "floor"
    logs.create_log_stream(logGroupName=group, logStreamName=mixed)
    logs.create_log_stream(logGroupName=group, logStreamName=floor)

    # The 24h span rule applies to the events that survive the window filter, so this batch's
    # 15-day raw span is accepted with both indices in one rejectedLogEventsInfo.
    now = int(time.time() * 1000)
    batch = [
        {"timestamp": now - 15 * _DAY_MS, "message": "reject-old-15d"},
        {"timestamp": now - 14 * _DAY_MS - _HOUR_MS, "message": "reject-old-14d1h"},
        {"timestamp": now - _HOUR_MS, "message": "keep-minus-1h"},
        {"timestamp": now, "message": "keep-now"},
        {"timestamp": now + _HOUR_MS, "message": "keep-plus-1h"},
        {"timestamp": now + 3 * _HOUR_MS, "message": "reject-new-3h"},
        {"timestamp": now + 4 * _HOUR_MS, "message": "reject-new-4h"},
    ]
    resp = logs.put_log_events(logGroupName=group, logStreamName=mixed, logEvents=batch)
    info = resp.get("rejectedLogEventsInfo")
    assert info == {"tooOldLogEventEndIndex": 2, "tooNewLogEventStartIndex": 5}, (
        "a batch of [2 too-old, 3 in-window, 2 too-new] must be accepted with BOTH indices "
        "reported: tooOldLogEventEndIndex=2 (exclusive) and tooNewLogEventStartIndex=5 "
        f"(inclusive), and no expiredLogEventEndIndex; got rejectedLogEventsInfo={info!r} "
        f"(full response keys {sorted(resp)!r})"
    )

    floor_batch = [
        {"timestamp": now - 14 * _DAY_MS - 30 * _MINUTE_MS, "message": "reject-floor-14d30m"},
        {"timestamp": now - 14 * _DAY_MS + _HOUR_MS, "message": "keep-floor-13d23h"},
    ]
    floor_resp = logs.put_log_events(
        logGroupName=group, logStreamName=floor, logEvents=floor_batch
    )
    assert floor_resp.get("rejectedLogEventsInfo") == {"tooOldLogEventEndIndex": 1}, (
        "an event 14 days + 30 minutes old is past the 14-day floor and the one 13 days 23 "
        "hours old is inside it, so exactly index 0 must be rejected as too old; got "
        f"{floor_resp.get('rejectedLogEventsInfo')!r}"
    )

    window = (now - 16 * _DAY_MS, now + 5 * _HOUR_MS)
    kept_mixed = ["keep-minus-1h", "keep-now", "keep-plus-1h"]
    kept_floor = ["keep-floor-13d23h"]

    # Events with OLD timestamps become readable much later than current ones (48-110 s,
    # not monotonic in age), so all three reads are polled together under one bound.
    def _observe():
        return {
            "mixed": _read_stream(logs, group, mixed, window),
            "floor": _read_stream(logs, group, floor, window),
            "group": _filter_all(logs, group, window),
        }

    seen = _poll_until(
        _observe,
        lambda o: (len(o["mixed"]) >= len(kept_mixed) and len(o["floor"]) >= len(kept_floor)
                   and len(o["group"]) >= len(kept_mixed) + len(kept_floor)),
        timeout_s=240.0,
        interval_s=5.0,
        description="every accepted event to be readable via GetLogEvents and FilterLogEvents",
    )
    stored = seen["mixed"]
    assert [e["message"] for e in stored] == kept_mixed, (
        f"the stream must hold EXACTLY the in-window events {kept_mixed!r} in timestamp order; "
        f"read back {[e['message'] for e in stored]!r}"
    )
    assert [e["timestamp"] for e in stored] == [now - _HOUR_MS, now, now + _HOUR_MS], (
        f"stored timestamps were {[e['timestamp'] for e in stored]!r}; the accepted events must "
        "keep the exact millisecond timestamps they were submitted with"
    )
    assert [e["message"] for e in seen["floor"]] == kept_floor, (
        "the floor stream must hold only the event inside the 14-day floor; read back "
        f"{[e['message'] for e in seen['floor']]!r}"
    )

    # Effect absent across the whole group, via the second read path.
    everything = seen["group"]
    rejected = sorted(e["message"] for e in everything if e["message"].startswith("reject-"))
    assert rejected == [], (
        f"events reported as rejected must never be stored, but FilterLogEvents found {rejected!r}"
    )
    assert sorted(e["message"] for e in everything) == sorted(kept_mixed + kept_floor), (
        f"FilterLogEvents over the group returned {sorted(e['message'] for e in everything)!r}; "
        "expected exactly the four accepted events"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """Bounded retry that RAISES on timeout, quoting the last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


def _read_stream(logs, group, stream, window):
    """Page GetLogEvents forward until the forward token repeats (end of stream)."""
    events, token = [], None
    for _ in range(100):
        kwargs = dict(logGroupName=group, logStreamName=stream, startFromHead=True,
                      startTime=window[0], endTime=window[1])
        if token:
            kwargs["nextToken"] = token
        resp = logs.get_log_events(**kwargs)
        events.extend(resp.get("events", []))
        nxt = resp.get("nextForwardToken")
        if not nxt or nxt == token:
            return events
        token = nxt
    raise AssertionError(f"GetLogEvents on {stream!r} never repeated its forward token")


def _filter_all(logs, group, window):
    events, token = [], None
    for _ in range(200):
        kwargs = dict(logGroupName=group, startTime=window[0], endTime=window[1])
        if token:
            kwargs["nextToken"] = token
        resp = logs.filter_log_events(**kwargs)
        events.extend(resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            return events
    raise AssertionError("FilterLogEvents pagination did not terminate within 200 pages")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
