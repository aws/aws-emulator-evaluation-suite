"""get-time-series-service-statistics-buckets-two-segments-into-two-periods."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "get-time-series-service-statistics-buckets-two-segments-into-two-periods"
GROUP = "trace-data-plane"
SERVICES = ["xray"]

_TIMESERIES_TIMEOUT_S = 600.0
_TIMESERIES_INTERVAL_S = 15.0
#: Bucket width, and the wall-clock spacing between the two PutTraceSegments calls. Spacing
#: above _PERIOD_S means the two submissions cannot share a bucket wherever boundaries fall.
_PERIOD_S = 60
_SPACING_S = 120.0

#: Slack between the local submission clock and when X-Ray considers a segment received.
_TIMESTAMP_TOLERANCE_S = 30.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/xray/latest/api/API_GetTimeSeriesServiceStatistics.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:xray-trace-segment-destination",
      "timing:real-time")
def run(ctx) -> None:
    """Two segments for one service submitted _SPACING_S apart in wall-clock time land in two
    Period=60 datapoints, each counting one OK request, with timestamps ~_SPACING_S apart; a
    never-submitted service name returns no statistics, so the selector is applied."""
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    marker = "b" + _hex(12)
    service_name = f"sim2real-behav-xray-bucket-{marker}"
    absent_name = f"sim2real-behav-xray-bucket-absent-{marker}"

    pre_write_now = time.time()
    win_start = pre_write_now - 300.0

    # Read first: after the write, aggregation latency would make this pass vacuously.
    stale = _counted(_datapoints(xr, service_name, pre_write_now - 5400.0, pre_write_now - 3600.0))
    assert stale == [], (
        f"a window that ended an hour before anything was submitted already reported statistics "
        f"for the freshly generated unique service name {service_name!r}: {stale!r}"
    )

    # X-Ray buckets by when PutTraceSegments is called, not by the payload's start_time, so the
    # two submissions are spaced apart in real time across two separate calls.
    first_submit = time.time()
    trace_id_1 = _new_trace_id(first_submit)
    put1 = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps({
        "id": _new_segment_id(),
        "name": service_name,
        "trace_id": trace_id_1,
        "start_time": first_submit,
        "end_time": first_submit + 0.5,
        "annotations": {"probe_run": marker},
        "http": {"request": {"method": "GET", "url": "https://example.invalid/bucket"},
                 "response": {"status": 200}},
    })])
    assert put1["UnprocessedTraceSegments"] == [], (
        f"the first probe segment must be accepted before any bucketing is judged; X-Ray "
        f"reported {put1['UnprocessedTraceSegments']!r}"
    )

    _sleep_until(first_submit + _SPACING_S)

    second_submit = time.time()
    trace_id_2 = _new_trace_id(second_submit)
    assert trace_id_1 != trace_id_2, "the two probe trace ids must differ"
    put2 = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps({
        "id": _new_segment_id(),
        "name": service_name,
        "trace_id": trace_id_2,
        "start_time": second_submit,
        "end_time": second_submit + 0.5,
        "annotations": {"probe_run": marker},
        "http": {"request": {"method": "GET", "url": "https://example.invalid/bucket"},
                 "response": {"status": 200}},
    })])
    assert put2["UnprocessedTraceSegments"] == [], (
        f"the second probe segment must be accepted before any bucketing is judged; X-Ray "
        f"reported {put2['UnprocessedTraceSegments']!r}"
    )

    submitted_gap = second_submit - first_submit
    assert submitted_gap > _PERIOD_S, (
        f"the two PutTraceSegments calls must land more than one Period={_PERIOD_S}s apart in "
        f"real wall-clock time -- that is what guarantees they cannot share a bucket regardless "
        f"of where the service anchors its boundaries -- but they landed only "
        f"{submitted_gap:.1f}s apart"
    )
    win_end = second_submit + 120.0

    points = _poll_until(
        lambda: _counted(_datapoints(xr, service_name, win_start, win_end)),
        lambda pts: sum(p["ServiceSummaryStatistics"]["TotalCount"] for p in pts) >= 2,
        timeout_s=_TIMESERIES_TIMEOUT_S,
        interval_s=_TIMESERIES_INTERVAL_S,
        description=(
            f"both submitted requests counted in Period={_PERIOD_S} datapoints CARRYING "
            f"ServiceSummaryStatistics for the unique service {service_name!r}"
        ),
    )

    total = sum(p["ServiceSummaryStatistics"]["TotalCount"] for p in points)
    assert total == 2, (
        f"exactly two requests were submitted under the unique service name {service_name!r}, so "
        f"the Period={_PERIOD_S} datapoints must sum to 2; they summed to {total} over "
        f"{[(p['Timestamp'], p['ServiceSummaryStatistics']['TotalCount']) for p in points]!r}"
    )
    assert len(points) == 2, (
        f"the two requests were submitted {submitted_gap:.0f}s apart in real wall-clock time, "
        f"more than Period={_PERIOD_S}s, so they must occupy TWO distinct Period={_PERIOD_S} "
        f"buckets rather than being folded into one aggregate; X-Ray returned {len(points)} "
        f"datapoints carrying statistics: "
        f"{[(p['Timestamp'], p['ServiceSummaryStatistics']['TotalCount']) for p in points]!r}"
    )
    for point in points:
        stats = point["ServiceSummaryStatistics"]
        assert stats["TotalCount"] == 1, (
            f"each of the two buckets holds exactly one of the two submitted requests, so each "
            f"must count 1; the bucket at {point['Timestamp']!r} counted "
            f"{stats['TotalCount']!r}"
        )
        assert stats["OkCount"] == 1, (
            f"each submitted segment declared http.response.status 200 and carried no "
            f"error/fault/throttle member, so each bucket must count it OK; the bucket at "
            f"{point['Timestamp']!r} reported {stats!r}"
        )
        assert stats["ErrorStatistics"]["TotalCount"] == 0, (
            f"a clean segment must contribute no errors: {stats!r}"
        )
        assert stats["FaultStatistics"]["TotalCount"] == 0, (
            f"a clean segment must contribute no faults: {stats!r}"
        )
        stamp = point["Timestamp"].timestamp()
        assert win_start <= stamp <= win_end, (
            f"a datapoint Timestamp fell outside the requested window "
            f"{_utc(win_start)}..{_utc(win_end)}: {point['Timestamp']!r}"
        )

    stamps = sorted(p["Timestamp"].timestamp() for p in points)
    observed = stamps[1] - stamps[0]
    assert abs(observed - submitted_gap) <= _TIMESTAMP_TOLERANCE_S, (
        f"the two bucket Timestamps must be about as far apart as the two PutTraceSegments calls "
        f"were in real wall-clock time ({submitted_gap:.1f}s, which exceeds Period={_PERIOD_S} so "
        f"this holds whatever offset the service uses when assigning a segment to a bucket); they "
        f"were {observed:.1f}s apart ({_utc(stamps[0])} and {_utc(stamps[1])})"
    )

    # Without this control the counts above could be an account-wide aggregate in a quiet account.
    unrelated = _counted(_datapoints(xr, absent_name, win_start, win_end))
    mine_again = _counted(_datapoints(xr, service_name, win_start, win_end))
    assert unrelated == [], (
        f"the identical window narrowed to a service name that was never submitted "
        f"({absent_name!r}) must return no datapoint carrying statistics, or "
        f"EntitySelectorExpression is being ignored and every count above is an account-wide "
        f"aggregate: {unrelated!r}"
    )
    assert sum(p["ServiceSummaryStatistics"]["TotalCount"] for p in mine_again) == 2, (
        f"the twin control failed: the submitted service must still report both requests in the "
        f"same instant the never-submitted name reported none; it reported "
        f"{[(p['Timestamp'], p['ServiceSummaryStatistics']['TotalCount']) for p in mine_again]!r}"
    )


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _new_trace_id(epoch_seconds: float) -> str:
    return f"1-{int(epoch_seconds):08x}-{_hex(24)}"


def _new_segment_id() -> str:
    return _hex(16)


def _utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _sleep_until(deadline: float) -> None:
    """Blocks until the wall clock reaches *deadline*, so the gap holds whatever the first call took."""
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 5.0))


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} was still not true {timeout_s:.0f}s after the probe segments "
                f"were accepted; last observation: {last!r}"
            )
        time.sleep(interval_s)


def _counted(points):
    """Only datapoints carrying statistics: X-Ray returns placeholder datapoints without
    ServiceSummaryStatistics for periods with any account traffic, even for an unknown service."""
    return [p for p in points if "ServiceSummaryStatistics" in p]


def _datapoints(xr, service_name, start_ts, end_ts, max_pages=20):
    """Every per-period datapoint for one service; raises rather than truncating pagination."""
    out = []
    token = None
    for _ in range(max_pages):
        kw = {
            "StartTime": _utc(start_ts),
            "EndTime": _utc(end_ts),
            "Period": _PERIOD_S,
            "EntitySelectorExpression": f'service(id(name: "{service_name}"))',
        }
        if token:
            kw["NextToken"] = token
        page = xr.get_time_series_service_statistics(**kw)
        out.extend(page["TimeSeriesServiceStatistics"])
        token = page.get("NextToken")
        if not token:
            return out
    raise AssertionError(
        f"GetTimeSeriesServiceStatistics still offered a NextToken after {max_pages} pages for "
        f"{service_name!r}; the result set is too large for an assertion about two buckets to "
        f"mean anything"
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
            time.sleep(10.0)
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
        time.sleep(10.0)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Restores the destination and waits until it is ACTIVE, so no PENDING switch is left behind."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
