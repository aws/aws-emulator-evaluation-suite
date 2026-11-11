"""time-series-service-statistics-counts-the-submitted-trace."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "time-series-service-statistics-counts-the-submitted-trace"
GROUP = 'trace-data-plane'
SERVICES = ['xray']

#: Time-series aggregation shares the service-graph pipeline's undocumented latency, so this is a
#: generous bounded poll for eventual presence and asserts no deadline whatsoever.
_TIMESERIES_TIMEOUT_S = 600


# ===== helpers =====
# _datapoints is paginated and scoped to one service by EntitySelectorExpression.
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


def _utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _counted(points):
    """Only the datapoints that actually carry statistics.

    Load-bearing, and the reason this check does not read ``points`` directly: for a window whose
    periods hold traffic from ANY service, real X-Ray returns a placeholder datapoint per period --
    a Timestamp and an empty ServiceForecastStatistics, with no ServiceSummaryStatistics member at
    all -- even for an EntitySelectorExpression naming a service that was never submitted. A
    ``bool(points)`` predicate is therefore satisfied by rows that count nothing.
    """
    return [p for p in points if "ServiceSummaryStatistics" in p]


def _datapoints(xr, service_name, start_ts, end_ts, max_pages=25):
    """Every per-period datapoint for exactly one service, following NextToken.

    ``EntitySelectorExpression`` is what narrows the response from account-wide to this one
    service; without it the counts below would be a shared-pool aggregate and flaky by
    construction.
    """
    out = []
    token = None
    for _ in range(max_pages):
        kw = {"StartTime": _utc(start_ts), "EndTime": _utc(end_ts), "Period": 60,
              "EntitySelectorExpression": f'service(id(name: "{service_name}"))'}
        if token:
            kw["NextToken"] = token
        page = xr.get_time_series_service_statistics(**kw)
        out.extend(page.get("TimeSeriesServiceStatistics", []))
        token = page.get("NextToken")
        if not token:
            break
    return out


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetTimeSeriesServiceStatistics at Period=60 yields a datapoint inside the requested window
    counting exactly the one OK request submitted, while an earlier window and a never-submitted
    service name yield no datapoint carrying statistics.
    """
    xr = ctx.client("xray")
    now = time.time()
    service_name = "sim2real-behav-xray-ts-" + _hex(6)
    absent_name = "sim2real-behav-xray-ts-absent-" + _hex(6)

    # Read the stale window BEFORE the write: thirty minutes wide and thirty minutes old, so no
    # plausible aggregation latency can contaminate it.
    stale = _datapoints(xr, service_name, now - 3600, now - 1800)
    assert _counted(stale) == [], (
        f"a window that ended thirty minutes before the segment was submitted already reported "
        f"statistics for a freshly generated unique service name: "
        f"{_counted(stale)!r} (of {len(stale)} datapoints returned)"
    )

    trace_id = new_trace_id(now)
    start_time, end_time = now - 1.5, now
    segment = {
        "id": new_segment_id(), "name": service_name, "trace_id": trace_id,
        "start_time": start_time, "end_time": end_time,
        "http": {"request": {"method": "GET", "url": "https://example.invalid/ts"},
                 "response": {"status": 200}},
    }
    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"the segment was not accepted, so nothing below is about time-series statistics: {put!r}"
    )

    win_start = now - 300
    win_end = now + 600
    points = _poll_until(
        lambda: _counted(_datapoints(xr, service_name, win_start, win_end)),
        lambda pts: bool(pts),
        timeout_s=_TIMESERIES_TIMEOUT_S,
        interval_s=15,
        description=(
            "at least one Period=60 datapoint CARRYING ServiceSummaryStatistics for the service "
            "whose trace was demonstrably accepted"
        ),
    )

    for p in points:
        ts = p["Timestamp"].timestamp()
        assert win_start <= ts <= win_end, (
            f"a datapoint Timestamp falls outside the requested window "
            f"[{_utc(win_start)!r}, {_utc(win_end)!r}]: {p['Timestamp']!r}"
        )
    total = sum(p["ServiceSummaryStatistics"]["TotalCount"] for p in points)
    assert total == 1, (
        f"exactly one request was submitted under this unique service name, so the datapoints must "
        f"sum to 1; a constant [] satisfies the one shipped check of this operation and an "
        f"account-wide aggregate would report someone else's traffic: got {total} over {points!r}"
    )
    ok = sum(p["ServiceSummaryStatistics"]["OkCount"] for p in points)
    assert ok == 1, f"a clean segment must be counted OK: {points!r}"
    for p in points:
        stats = p["ServiceSummaryStatistics"]
        assert stats["ErrorStatistics"]["TotalCount"] == 0, (
            f"a clean segment must contribute no errors: {stats!r}"
        )
        assert stats["FaultStatistics"]["TotalCount"] == 0, (
            f"a clean segment must contribute no faults: {stats!r}"
        )
        assert stats["TotalResponseTime"] > 0, (
            f"the bucket must carry the response time derived from the segment's own span: "
            f"{stats!r}"
        )

    # The selector is applied, not ignored: the identical window narrowed to a name that was never
    # submitted is empty. Without this leg, TotalCount == 1 could be a quiet account rather than a
    # working filter.
    unrelated = _datapoints(xr, absent_name, win_start, win_end)
    assert _counted(unrelated) == [], (
        f"the same window selected on a service name that was never submitted returned datapoints "
        f"carrying statistics, so EntitySelectorExpression is being ignored and the count above is "
        f"an account-wide aggregate rather than this service's: {_counted(unrelated)!r} (of "
        f"{len(unrelated)} placeholder datapoints)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
