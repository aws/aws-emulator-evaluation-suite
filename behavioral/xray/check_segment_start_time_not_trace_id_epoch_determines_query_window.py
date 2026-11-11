"""segment-start-time-not-trace-id-epoch-determines-query-window."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "segment-start-time-not-trace-id-epoch-determines-query-window"
GROUP = 'trace-data-plane'
SERVICES = ['xray']

#: Indexing lag on both windows, bounded and well under the harness ceiling.
_WINDOW_TIMEOUT_S = 300

#: Two hours and five minutes back: far enough that the old window cannot overlap the recent one,
#: and three orders of magnitude inside X-Ray's 30-day trace retention, so an exclusion can never
#: be attributed to expiry.
_OLD_OFFSET_S = 7500


# ===== helpers =====
# _summary_ids takes an explicit window.
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


def _summary_ids(xr, start_ts, end_ts, max_pages=25):
    """Every trace id GetTraceSummaries reports for [start_ts, end_ts].

    Paginated because the result is ACCOUNT-WIDE: in a shared account other traces
    can fill page one, and a membership assertion read off a single page fails for a reason that
    has nothing to do with fidelity.
    """
    ids = set()
    token = None
    for _ in range(max_pages):
        kw = {"StartTime": _utc(start_ts), "EndTime": _utc(end_ts)}
        if token:
            kw["NextToken"] = token
        page = xr.get_trace_summaries(**kw)
        ids.update(s["Id"] for s in page.get("TraceSummaries", []))
        token = page.get("NextToken")
        if not token:
            break
    return ids


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetTraceSummaries selects traces by the segment's start_time, not the trace ID's epoch: two
    traces with crossed timestamps are each returned only by the window covering their start_time,
    and a window spanning both returns both.
    """
    xr = ctx.client("xray")
    now = time.time()
    t_old = now - _OLD_OFFSET_S

    # Crossed timestamps: the id says one thing, the segment says the other.
    old_id_recent_start = new_trace_id(t_old)
    recent_id_old_start = new_trace_id(now)
    assert old_id_recent_start != recent_id_old_start

    docs = [
        json.dumps({
            "id": new_segment_id(), "name": "sim2real-behav-xray-win-newstart-" + _hex(6),
            "trace_id": old_id_recent_start,
            "start_time": now - 1.0, "end_time": now,
            "http": {"request": {"method": "GET", "url": "https://example.invalid/newstart"},
                     "response": {"status": 200}},
        }),
        json.dumps({
            "id": new_segment_id(), "name": "sim2real-behav-xray-win-oldstart-" + _hex(6),
            "trace_id": recent_id_old_start,
            "start_time": t_old, "end_time": t_old + 1.0,
            "http": {"request": {"method": "GET", "url": "https://example.invalid/oldstart"},
                     "response": {"status": 200}},
        }),
    ]
    put = xr.put_trace_segments(TraceSegmentDocuments=docs)
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"a segment whose trace-ID epoch disagrees with its start_time must still be accepted, "
        f"and so must one whose start_time is two hours in the past: {put!r}"
    )

    recent_start, recent_end = now - 900, now + 120
    old_start, old_end = t_old - 900, t_old + 900
    assert old_end < recent_start, (
        f"the two windows must be disjoint or the exclusions below mean nothing: "
        f"old ends {old_end!r}, recent starts {recent_start!r}"
    )

    recent_window = _poll_until(
        lambda: _summary_ids(xr, recent_start, recent_end),
        lambda ids: old_id_recent_start in ids,
        timeout_s=_WINDOW_TIMEOUT_S,
        interval_s=5,
        description=(
            "the trace whose start_time is now indexed in the window around now (its trace-ID "
            "epoch is two hours earlier)"
        ),
    )
    old_window = _poll_until(
        lambda: _summary_ids(xr, old_start, old_end),
        lambda ids: recent_id_old_start in ids,
        timeout_s=_WINDOW_TIMEOUT_S,
        interval_s=5,
        description=(
            "the trace whose start_time is two hours old indexed in the window around that "
            "start_time (its trace-ID epoch is now)"
        ),
    )
    wide_window = _summary_ids(xr, old_start, recent_end)

    assert recent_id_old_start not in recent_window, (
        f"a trace whose SEGMENT starts two hours ago was returned by a window around now, even "
        f"though only its trace ID is recent -- the emulator is indexing on the trace-ID epoch "
        f"instead of on the segment's start_time: saw {len(recent_window)} ids, "
        f"{sorted(recent_window)[:5]!r}"
    )
    assert old_id_recent_start not in old_window, (
        f"a trace whose SEGMENT starts now was returned by a window two hours in the past, "
        f"matching only its trace-ID epoch: saw {len(old_window)} ids, "
        f"{sorted(old_window)[:5]!r}"
    )
    assert {old_id_recent_start, recent_id_old_start} <= wide_window, (
        f"a window spanning both start_times must return both traces, which is what makes the two "
        f"exclusions above about the WINDOW rather than about a trace that was dropped: saw "
        f"{len(wide_window)} ids, missing "
        f"{sorted({old_id_recent_start, recent_id_old_start} - wide_window)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
