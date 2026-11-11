"""put-trace-segments-high-precision-timestamp-preserved."""
from __future__ import annotations

import json
import os
import time

from behavioral_harness import tags

CHECK = "put-trace-segments-high-precision-timestamp-preserved"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sub-millisecond precision start_time/end_time values submitted in a segment document
    are returned exactly (not rounded to whole seconds or milliseconds) by BatchGetTraces."""
    xray = ctx.client("xray")
    trace_id = _make_trace_id()
    segment_id = _make_segment_id()

    # Build timestamps with an explicit, non-trivial sub-millisecond fractional component.
    base = float(int(time.time()))
    start_time = base + 0.123456
    end_time = base + 0.987654

    document = {
        "trace_id": trace_id,
        "id": segment_id,
        "name": ctx.unique_name("sim2real-xray-behav"),
        "start_time": start_time,
        "end_time": end_time,
    }
    resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(document)])
    assert resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment must be accepted, got unprocessed: {resp.get('UnprocessedTraceSegments')!r}"
    )

    fetched = _wait_for_trace_document(ctx, trace_id, timeout_s=90.0)
    assert fetched["start_time"] == start_time, f"start_time mutated: sent {start_time!r} got {fetched['start_time']!r}"
    assert fetched["end_time"] == end_time, f"end_time mutated: sent {end_time!r} got {fetched['end_time']!r}"


def _make_trace_id() -> str:
    return f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"


def _make_segment_id() -> str:
    return os.urandom(8).hex()


def _wait_for_trace_document(ctx, trace_id: str, timeout_s: float = 90.0) -> dict:
    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = xray.batch_get_traces(TraceIds=[trace_id])
        traces = resp.get("Traces", [])
        if traces:
            segments = traces[0].get("Segments", [])
            if segments:
                return json.loads(segments[0]["Document"])
        time.sleep(2.0)
    raise AssertionError(f"trace {trace_id} never became retrievable via BatchGetTraces within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
