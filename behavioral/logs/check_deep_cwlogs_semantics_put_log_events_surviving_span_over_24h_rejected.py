"""deep-cwlogs-semantics-put-log-events-surviving-span-over-24h-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-put-log-events-surviving-span-over-24h-rejected"
GROUP = "ingestion"
SERVICES = ["logs"]

_HOUR_MS = 60 * 60 * 1000
_DAY_MS = 24 * _HOUR_MS


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents' 24-hour span limit applies to the events surviving the 14-day/2-hour window:
    a batch whose in-window events span two days is refused whole and stores nothing, while one
    whose raw span is 15 days but whose survivors span one hour is accepted."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-span-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = "span"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    now = int(time.time() * 1000)
    refused_batch = [
        {"timestamp": now - 15 * _DAY_MS, "message": "refused-too-old"},
        {"timestamp": now - 13 * _DAY_MS, "message": "refused-in-window-13d"},
        {"timestamp": now - 11 * _DAY_MS, "message": "refused-in-window-11d"},
    ]
    code, message = _error(lambda: logs.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=refused_batch))
    assert code == "InvalidParameterException", (
        "a batch whose in-window events (13d and 11d old) span 2 days must be refused with "
        f"InvalidParameterException, got {code!r}"
    )
    expected = "The batch of log events in a single PutLogEvents request cannot span more than 24 hours."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The control's survivors are current events: old-timestamped events take 48-110 s to
    # become readable, which would overrun the check's time budget.
    control_batch = [
        {"timestamp": now - 15 * _DAY_MS, "message": "control-too-old"},
        {"timestamp": now - _HOUR_MS, "message": "control-in-window-a"},
        {"timestamp": now, "message": "control-in-window-b"},
    ]
    accepted = logs.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=control_batch)
    assert accepted.get("rejectedLogEventsInfo") == {"tooOldLogEventEndIndex": 1}, (
        "the control batch spans 15 days raw but only 1 hour over its in-window events, so it "
        "must be ACCEPTED with only index 0 reported too old; got "
        f"{accepted.get('rejectedLogEventsInfo')!r} — an emulator measuring the raw span would "
        "have refused it"
    )

    window = (now - 16 * _DAY_MS, now + _HOUR_MS)
    stored = _poll_until(
        lambda: _read_stream(logs, group, stream, window),
        lambda evs: len(evs) >= 2,
        timeout_s=120.0,
        interval_s=5.0,
        description="the control batch's two in-window events to be readable",
    )
    messages = [e["message"] for e in stored]
    assert messages == ["control-in-window-a", "control-in-window-b"], (
        "the stream must hold exactly the control's two in-window events; the refused batch "
        f"must have stored nothing (all-or-nothing). Read back {messages!r}"
    )


def _error(fn) -> tuple[str, str | None]:
    """The AWS error (code, message). An unexpected SUCCESS raises rather than returning a falsy value."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
