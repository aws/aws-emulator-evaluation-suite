"""get-trace-summaries-filter-expression-excludes-non-matching."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "get-trace-summaries-filter-expression-excludes-non-matching"
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


def _summaries(xr, start_ts, filter_expression=None, max_pages=25):
    """All TraceSummaries in [start_ts, now], following NextToken with a bounded page count."""
    out = []
    token = None
    for _ in range(max_pages):
        kw = {"StartTime": _utc(start_ts), "EndTime": _utc(time.time())}
        if filter_expression is not None:
            kw["FilterExpression"] = filter_expression
        if token:
            kw["NextToken"] = token
        page = xr.get_trace_summaries(**kw)
        out.extend(page.get("TraceSummaries", []))
        token = page.get("NextToken")
        if not token:
            break
    return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GetTraceSummaries annotation-equality FilterExpression returns the matching trace and
    excludes a non-matching trace that the unfiltered window already shows as indexed.
    """
    xr = ctx.client("xray")
    now = time.time()
    window_start = now - 120

    tag_match = "m" + _hex(12)
    tag_other = "o" + _hex(12)
    trace_match = new_trace_id(now)
    trace_other = new_trace_id(now)

    docs = []
    for tid, value in ((trace_match, tag_match), (trace_other, tag_other)):
        docs.append(json.dumps({
            "id": new_segment_id(),
            "name": "sim2real-behav-xray-filter",
            "trace_id": tid,
            "start_time": now - 1.0,
            "end_time": now,
            "annotations": {"probe_tag": value},
        }))
    put = xr.put_trace_segments(TraceSegmentDocuments=docs)
    assert put.get("UnprocessedTraceSegments", []) == [], put

    # Both traces indexed for summary search before any filtering happens.
    both = _poll_until(
        lambda: {s["Id"] for s in _summaries(xr, window_start)},
        lambda ids: {trace_match, trace_other} <= ids,
        timeout_s=180,
        interval_s=5,
        description="both submitted traces indexed in the unfiltered GetTraceSummaries window",
    )
    assert {trace_match, trace_other} <= both, both

    # Now the filter must select one and exclude the other.
    expression = f'annotation.probe_tag = "{tag_match}"'
    selected = _summaries(xr, window_start, filter_expression=expression)
    selected_ids = {s["Id"] for s in selected}
    assert trace_match in selected_ids, (
        f"filter {expression!r} must return the matching trace {trace_match}; "
        f"got {sorted(selected_ids)!r}"
    )
    assert trace_other not in selected_ids, (
        f"filter {expression!r} must EXCLUDE the non-matching trace {trace_other} "
        f"(it is indexed -- it appeared in the unfiltered window); got {sorted(selected_ids)!r}"
    )

    # The returned summary carries the annotation that satisfied the filter.
    hit = next(s for s in selected if s["Id"] == trace_match)
    annotations = hit.get("Annotations") or {}
    assert "probe_tag" in annotations, (
        f"TraceSummary for a filtered-on annotation must expose Annotations['probe_tag'], "
        f"got {annotations!r}"
    )
    values = [v.get("AnnotationValue", {}).get("StringValue") for v in annotations["probe_tag"]]
    assert tag_match in values, f"expected annotation value {tag_match!r} in {values!r}"

    # Control: the complementary filter selects exactly the other trace, proving the filter is
    # evaluated per-trace rather than the emulator having memorised one answer.
    complement = {s["Id"] for s in _summaries(
        xr, window_start, filter_expression=f'annotation.probe_tag = "{tag_other}"'
    )}
    assert trace_other in complement and trace_match not in complement, (
        f"complementary filter must select only {trace_other}; got {sorted(complement)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
