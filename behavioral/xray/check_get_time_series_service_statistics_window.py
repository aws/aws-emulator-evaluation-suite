"""get-time-series-service-statistics-window."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "get-time-series-service-statistics-window"
GROUP = 'trace-data-plane'
SERVICES = ['xray']

#: Time-series aggregation shares the service-graph pipeline's undocumented latency; a generous
#: bounded poll for eventual presence, no deadline assumed beyond this.
_TIMESERIES_TIMEOUT_S = 600


# ===== helpers =====
def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=180, interval_s=10, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _counted(points):
    """Only the datapoints that actually carry statistics.

    Load-bearing: for a window whose periods hold traffic from ANY service, real X-Ray returns a
    placeholder datapoint per period -- a Timestamp and an empty ServiceForecastStatistics, with no
    ServiceSummaryStatistics member at all -- even for an EntitySelectorExpression naming a service
    that was never submitted. A ``bool(points)`` predicate is therefore satisfied by rows counting
    nothing.
    """
    return [p for p in points if "ServiceSummaryStatistics" in p]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTimeSeriesServiceStatistics honours a raw POSIX-epoch StartTime/EndTime and a
    non-default Period: the window counts a just-submitted trace in datapoints that carry
    statistics, bucketed on the requested Period boundary.
    """
    xr = ctx.client("xray")
    now = time.time()
    service_name = "sim2real-behav-xray-tsw-" + _hex(6)
    period = 300

    # Read the stale window BEFORE the write, expressed in bare epoch floats: thirty minutes wide
    # and thirty minutes old, so no plausible aggregation latency can contaminate it.
    stale = xr.get_time_series_service_statistics(
        StartTime=now - 3600, EndTime=now - 1800, Period=period,
        EntitySelectorExpression=f'service(id(name: "{service_name}"))',
    )
    assert "TimeSeriesServiceStatistics" in stale, f"missing key: {list(stale)}"
    assert _counted(stale["TimeSeriesServiceStatistics"]) == [], (
        f"a window that ended thirty minutes before the segment was submitted already reported "
        f"statistics for a freshly generated unique service name: "
        f"{_counted(stale['TimeSeriesServiceStatistics'])!r}"
    )

    trace_id = new_trace_id(now)
    start_time, end_time = now - 1.5, now
    segment = {
        "id": new_segment_id(), "name": service_name, "trace_id": trace_id,
        "start_time": start_time, "end_time": end_time,
        "http": {"request": {"method": "GET", "url": "https://example.invalid/tsw"},
                 "response": {"status": 200}},
    }
    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"the segment was not accepted, so nothing below is about time-series statistics: {put!r}"
    )

    win_start, win_end = now - 300, now + 600  # bare epoch floats -- the thing under test

    def _fetch():
        resp = xr.get_time_series_service_statistics(
            StartTime=win_start, EndTime=win_end, Period=period,
            EntitySelectorExpression=f'service(id(name: "{service_name}"))',
        )
        assert "TimeSeriesServiceStatistics" in resp, f"missing key: {list(resp)}"
        return _counted(resp["TimeSeriesServiceStatistics"])

    points = _poll_until(
        _fetch, lambda pts: bool(pts), timeout_s=_TIMESERIES_TIMEOUT_S, interval_s=15,
        description=(
            f"at least one Period={period} datapoint carrying ServiceSummaryStatistics for the "
            f"service whose trace was demonstrably accepted, queried with a bare epoch-float window"
        ),
    )

    # The segment's own Period bucket can start before the unaligned win_start, so the lower
    # bound is that bucket's aligned start, wherever now falls in the period.
    lo = (start_time // period) * period
    for p in points:
        ts = p["Timestamp"].timestamp()
        assert lo <= ts <= win_end, (
            f"a datapoint Timestamp falls outside the Period-aligned bare-epoch-float window "
            f"[{lo!r}, {win_end!r}]: {p['Timestamp']!r}"
        )
        assert ts % period == 0, (
            f"a datapoint Timestamp is not aligned to the requested explicit Period={period}s "
            f"boundary: {p['Timestamp']!r} ({ts % period}s off)"
        )

    total = sum(p["ServiceSummaryStatistics"]["TotalCount"] for p in points)
    assert total == 1, (
        f"a bare-epoch-float StartTime/EndTime must be interpreted as the same window a datetime "
        f"would express; exactly one request was submitted under this unique service name, so the "
        f"datapoints must sum to 1: got {total} over {points!r}"
    )
    ok = sum(p["ServiceSummaryStatistics"]["OkCount"] for p in points)
    assert ok == 1, f"a clean segment must be counted OK: {points!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
