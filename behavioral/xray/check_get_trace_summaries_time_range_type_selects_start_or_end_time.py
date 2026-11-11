"""get-trace-summaries-time-range-type-selects-start-or-end-time."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "get-trace-summaries-time-range-type-selects-start-or-end-time"
GROUP = "trace-data-plane"
SERVICES = ["xray"]

_INDEX_TIMEOUT_S = 300.0
_INDEX_INTERVAL_S = 10.0
#: How far back the segment starts: wide enough for disjoint windows, far inside trace retention.
_SPAN_S = 1800.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """TimeRangeType=TraceId returns a long segment only from the window covering its start_time
    and Service only from the window covering its end_time; Event answers for a spanning window.

    Reference: https://docs.aws.amazon.com/xray/latest/api/API_GetTraceSummaries.html
    """
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()
    marker = "w" + _hex(12)
    scope = f'annotation.probe_run = "{marker}"'
    trace_id = _new_trace_id(now)
    start_time = now - _SPAN_S
    end_time = now - 30.0

    # Disjoint by construction, and each covers exactly one of the two timestamps.
    start_window = (now - _SPAN_S - 300.0, now - _SPAN_S + 300.0)
    end_window = (now - 300.0, now + 120.0)
    span_window = (now - _SPAN_S - 300.0, now + 120.0)
    assert start_window[1] < end_window[0], (
        f"the two windows must be disjoint or neither exclusion means anything: start window "
        f"ends {_utc(start_window[1])}, end window begins {_utc(end_window[0])}"
    )
    assert start_window[0] < start_time < start_window[1], (
        f"the start window must cover the submitted start_time {_utc(start_time)}: "
        f"{_utc(start_window[0])}..{_utc(start_window[1])}"
    )
    assert not start_window[0] < end_time < start_window[1], (
        f"the start window must NOT cover the submitted end_time {_utc(end_time)}"
    )
    assert end_window[0] < end_time < end_window[1], (
        f"the end window must cover the submitted end_time {_utc(end_time)}: "
        f"{_utc(end_window[0])}..{_utc(end_window[1])}"
    )
    assert not end_window[0] < start_time < end_window[1], (
        f"the end window must NOT cover the submitted start_time {_utc(start_time)}"
    )

    before = _summary_ids(xr, scope, *span_window, time_range_type="TraceId")
    assert trace_id not in before, (
        f"the freshly minted probe trace id {trace_id} was already reported by X-Ray before it "
        f"was submitted; the spanning window returned {len(before)} ids"
    )

    document = {
        "id": _new_segment_id(),
        "name": f"sim2real-behav-xray-trt-{marker}",
        "trace_id": trace_id,
        "start_time": start_time,
        "end_time": end_time,
        # Traces cannot be tagged; the per-run annotation scopes every query below.
        "annotations": {"probe_run": marker},
        "http": {"request": {"method": "GET", "url": "https://example.invalid/trt"},
                 "response": {"status": 200}},
    }
    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(document)])
    assert put["UnprocessedTraceSegments"] == [], (
        f"a segment spanning {_SPAN_S:.0f}s and ending 30s ago must be accepted; X-Ray reported "
        f"{put['UnprocessedTraceSegments']!r}"
    )

    _poll_until(
        lambda: _summary_ids(xr, scope, *span_window, time_range_type="TraceId"),
        lambda ids: trace_id in ids,
        timeout_s=_INDEX_TIMEOUT_S,
        interval_s=_INDEX_INTERVAL_S,
        description=(
            f"probe trace {trace_id} indexed and reported by a window spanning both its "
            f"start_time and its end_time -- the control every exclusion below rests on"
        ),
    )

    _poll_until(
        lambda: _summary_ids(xr, scope, *start_window, time_range_type="TraceId"),
        lambda ids: trace_id in ids,
        timeout_s=_INDEX_TIMEOUT_S,
        interval_s=_INDEX_INTERVAL_S,
        description=(
            f"TimeRangeType=TraceId reporting probe trace {trace_id} from the window covering "
            f"only its start_time {_utc(start_time)}"
        ),
    )
    # Twin control: the other type on the same window excludes it while this type still returns it.
    service_on_start = _summary_ids(xr, scope, *start_window, time_range_type="Service")
    traceid_on_start = _summary_ids(xr, scope, *start_window, time_range_type="TraceId")
    assert trace_id not in service_on_start, (
        f"TimeRangeType=Service selects on the segment's END time, so the window covering only "
        f"the start_time ({_utc(start_window[0])}..{_utc(start_window[1])}) must NOT report "
        f"{trace_id}; it returned {len(service_on_start)} ids including it"
    )
    assert trace_id in traceid_on_start, (
        f"the twin control failed: TimeRangeType=TraceId must still report {trace_id} from the "
        f"start-time window in the same instant the Service query excluded it, or the exclusion "
        f"above is about the window rather than the type; it returned "
        f"{sorted(traceid_on_start)[:5]}"
    )

    _poll_until(
        lambda: _summary_ids(xr, scope, *end_window, time_range_type="Service"),
        lambda ids: trace_id in ids,
        timeout_s=_INDEX_TIMEOUT_S,
        interval_s=_INDEX_INTERVAL_S,
        description=(
            f"TimeRangeType=Service reporting probe trace {trace_id} from the window covering "
            f"only its end_time {_utc(end_time)}"
        ),
    )
    traceid_on_end = _summary_ids(xr, scope, *end_window, time_range_type="TraceId")
    service_on_end = _summary_ids(xr, scope, *end_window, time_range_type="Service")
    assert trace_id not in traceid_on_end, (
        f"TimeRangeType=TraceId selects on the trace's START time, so the window covering only "
        f"the end_time ({_utc(end_window[0])}..{_utc(end_window[1])}) must NOT report "
        f"{trace_id}; it returned {len(traceid_on_end)} ids including it"
    )
    assert trace_id in service_on_end, (
        f"the twin control failed: TimeRangeType=Service must still report {trace_id} from the "
        f"end-time window in the same instant the TraceId query excluded it; it returned "
        f"{sorted(service_on_end)[:5]}"
    )

    # Event means "trace update time" (ingestion-relative), so it is asserted only on the spanning
    # window. A single read: the trace is already proven indexed, so a poll could never fail.
    event_on_span = _summary_ids(xr, scope, *span_window, time_range_type="Event")
    assert trace_id in event_on_span, (
        f"all three TimeRangeType values must be accepted and must answer for a window spanning "
        f"the trace's whole life; Event returned {sorted(event_on_span)[:5]}"
    )


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _new_trace_id(epoch_seconds: float) -> str:
    return f"1-{int(epoch_seconds):08x}-{_hex(24)}"


def _new_segment_id() -> str:
    return _hex(16)


def _utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} was still not true {timeout_s:.0f}s after the segment was "
                f"accepted; last observation: {last!r}"
            )
        time.sleep(interval_s)


def _summary_ids(xr, expression, start_ts, end_ts, *, time_range_type, max_pages=20):
    """Every trace id for one expression, window and TimeRangeType, raising rather than truncating.

    ``Sampling=False`` makes the scan exhaustive, so exclusions are real and not sampling artefacts.
    """
    ids = set()
    token = None
    for _ in range(max_pages):
        kw = {
            "StartTime": _utc(start_ts),
            "EndTime": _utc(end_ts),
            "FilterExpression": expression,
            "TimeRangeType": time_range_type,
            "Sampling": False,
        }
        if token:
            kw["NextToken"] = token
        page = xr.get_trace_summaries(**kw)
        ids.update(s["Id"] for s in page["TraceSummaries"])
        token = page.get("NextToken")
        if not token:
            return ids
    raise AssertionError(
        f"GetTraceSummaries still offered a NextToken after {max_pages} pages for "
        f"{expression!r} / TimeRangeType={time_range_type}; the result set is too large for an "
        f"assertion about one probe trace to mean anything"
    )


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Pins the account-wide trace-segment destination to `want` and returns the original.

    A switch takes minutes to go PENDING -> ACTIVE, so the restore is registered before switching.
    """
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    original = _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"]
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xray, original, timeout_s=timeout_s))
    if original == want:
        return original
    deadline = time.monotonic() + 120.0
    while True:
        try:
            xray.update_trace_segment_destination(Destination=want)
            break
        except ClientError as err:
            # A just-put logs resource policy takes a while to reach X-Ray, which until then
            # refuses CloudWatchLogs naming the PutLogEvents permission it cannot yet see.
            message = err.response["Error"].get("Message", "")
            if "PutLogEvents" not in message or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    current = _settled_trace_segment_destination(xray, timeout_s=timeout_s)
    assert current["Destination"] == want, (
        f"trace-segment destination settled on {current!r} instead of {want}/ACTIVE"
    )
    return original


def _settled_trace_segment_destination(xray, *, timeout_s: float) -> dict:
    # AWS refuses UpdateTraceSegmentDestination while a previous switch is still PENDING.
    deadline = time.monotonic() + timeout_s
    while True:
        current = xray.get_trace_segment_destination()
        if current.get("Status") == "ACTIVE":
            return current
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"trace-segment destination still not ACTIVE after {timeout_s}s: {current!r}"
            )
        time.sleep(2.0)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Restores the destination and waits until it is ACTIVE, so no PENDING switch is left behind."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
