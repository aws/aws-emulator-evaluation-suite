"""get-service-graph-returns-window."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "get-service-graph-returns-window"
GROUP = 'trace-data-plane'
SERVICES = ['xray']

#: Service-graph aggregation latency on real AWS is undocumented. Nothing here asserts a deadline:
#: the poll expiring becomes an assertion failure about the graph's content, never a claim that
#: X-Ray was too slow.
_GRAPH_TIMEOUT_S = 900


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


def _poll_until(probe, predicate, timeout_s=180, interval_s=15, description="condition"):
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetServiceGraph for an explicit window, once a submitted segment is aggregated, returns the
    submitted service with StartTime/EndTime inside the requested window.
    """
    xr = ctx.client("xray")
    now = time.time()
    name = "sim2real-behav-xray-window-" + _hex(6)

    segment = {
        "id": new_segment_id(), "name": name, "trace_id": new_trace_id(now),
        "start_time": now - 1.5, "end_time": now,
        "http": {"request": {"method": "GET", "url": "https://example.invalid/window"},
                 "response": {"status": 200}},
    }
    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"the segment must be accepted, or the graph below is guaranteed empty for a reason "
        f"unrelated to windowing: {put!r}"
    )

    start, end = now - 600, now + 300
    resp = _poll_until(
        lambda: xr.get_service_graph(StartTime=_utc(start), EndTime=_utc(end)),
        lambda r: name in {s.get("Name") for s in r.get("Services", [])},
        timeout_s=_GRAPH_TIMEOUT_S,
        interval_s=15,
        description="the submitted service present in the requested window's graph",
    )
    assert "Services" in resp, f"missing Services key: {list(resp)}"
    assert isinstance(resp["Services"], list) and resp["Services"], (
        f"Services must be a non-empty list once a segment has been aggregated: "
        f"{resp['Services']!r}"
    )

    assert resp.get("StartTime") is not None, (
        f"StartTime must be echoed once the graph is genuinely populated, got {resp!r}"
    )
    assert resp.get("EndTime") is not None, (
        f"EndTime must be echoed once the graph is genuinely populated, got {resp!r}"
    )
    assert resp["StartTime"].timestamp() >= start - 60, (
        f"echoed StartTime {resp['StartTime']!r} predates the requested window start {start!r} "
        f"by more than the allowed clock-skew tolerance"
    )
    assert resp["EndTime"].timestamp() <= end + 60, (
        f"echoed EndTime {resp['EndTime']!r} exceeds the requested window end {end!r} by more "
        f"than the allowed clock-skew tolerance"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
