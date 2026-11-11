"""get-trace-summaries-fault-flag-reflects-segment."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "get-trace-summaries-fault-flag-reflects-segment"
GROUP = 'trace-data-plane'
SERVICES = ['xray']


# ===== helpers =====
# _summaries is paginated, since GetTraceSummaries returns an account-wide page for the window.
def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=180, interval_s=5, description="condition"):
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


def _summaries(xr, start_ts, max_pages=25):
    """All TraceSummaries in [start_ts, now], following NextToken with a bounded page count."""
    out = []
    token = None
    for _ in range(max_pages):
        kw = {"StartTime": _utc(start_ts), "EndTime": _utc(time.time())}
        if token:
            kw["NextToken"] = token
        page = xr.get_trace_summaries(**kw)
        out.extend(page.get("TraceSummaries", []))
        token = page.get("NextToken")
        if not token:
            break
    return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """TraceSummary.HasFault/HasError/HasThrottle are derived from the segment: a `fault: true`
    segment summarises as HasFault true and HasError false, and a clean segment from the same
    call as neither.
    """
    xr = ctx.client("xray")
    now = time.time()
    window_start = now - 120

    faulty_trace = new_trace_id(now)
    clean_trace = new_trace_id(now)
    docs = [
        json.dumps({
            "id": new_segment_id(),
            "name": "sim2real-behav-xray-faulty",
            "trace_id": faulty_trace,
            "start_time": now - 1.0,
            "end_time": now,
            "fault": True,
            "http": {"request": {"method": "GET", "url": "https://example.invalid/boom"},
                     "response": {"status": 500}},
        }),
        json.dumps({
            "id": new_segment_id(),
            "name": "sim2real-behav-xray-clean",
            "trace_id": clean_trace,
            "start_time": now - 1.0,
            "end_time": now,
            "http": {"request": {"method": "GET", "url": "https://example.invalid/ok"},
                     "response": {"status": 200}},
        }),
    ]
    put = xr.put_trace_segments(TraceSegmentDocuments=docs)
    assert put.get("UnprocessedTraceSegments", []) == [], put

    wanted = {faulty_trace, clean_trace}
    indexed = _poll_until(
        lambda: {s["Id"]: s for s in _summaries(xr, window_start)},
        lambda by_id: wanted <= set(by_id),
        timeout_s=180,
        interval_s=5,
        description="both the faulty and the clean trace indexed in GetTraceSummaries",
    )

    faulty = indexed[faulty_trace]
    clean = indexed[clean_trace]

    assert faulty.get("HasFault") is True, (
        f"segment with fault=true must summarise as HasFault true, got {faulty!r}"
    )
    assert faulty.get("HasError") is not True, (
        f"a fault is not an error -- HasError must not be true, got {faulty!r}"
    )
    assert faulty.get("HasThrottle") is not True, (
        f"HasThrottle must not be true for a non-throttled segment, got {faulty!r}"
    )

    assert clean.get("HasFault") is not True, (
        f"clean sibling submitted in the same call must not summarise as HasFault, got {clean!r}"
    )
    assert clean.get("HasError") is not True, clean
    assert clean.get("HasThrottle") is not True, clean

    # The two summaries are genuinely distinct records, not one echoed twice.
    assert faulty["Id"] != clean["Id"]
    for summary in (faulty, clean):
        assert summary.get("Duration") is not None, summary
        entry = summary.get("EntryPoint") or {}
        assert entry.get("Name"), (
            f"TraceSummary.EntryPoint must name the submitted segment, got {summary!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
