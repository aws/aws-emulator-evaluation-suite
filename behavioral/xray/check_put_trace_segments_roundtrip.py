"""put-trace-segments-roundtrip."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "put-trace-segments-roundtrip"
GROUP = 'trace-data-plane'
SERVICES = ['xray']


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=30, interval_s=2, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A well-formed segment submitted via PutTraceSegments is retrievable via BatchGetTraces."""
    xr = ctx.client("xray")
    now = time.time()
    trace_id = new_trace_id(now)
    seg = {
        "id": new_segment_id(),
        "name": "fidelity-check-service",
        "trace_id": trace_id,
        "start_time": now - 1.0,
        "end_time": now,
    }
    resp = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)])
    assert resp.get("UnprocessedTraceSegments", []) == [], resp

    result = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[trace_id]),
        lambda r: len(r.get("Traces", [])) == 1,
        timeout_s=120,
        interval_s=2,
        description="submitted trace retrievable via BatchGetTraces",
    )
    trace = result["Traces"][0]
    assert trace["Id"] == trace_id, trace
    assert result.get("UnprocessedTraceIds", []) == [], result

    segments = trace.get("Segments", [])
    assert len(segments) == 1, (
        f"submitted exactly one segment with no subsegments, expected exactly one stored "
        f"segment back, got {segments!r}"
    )
    stored = segments[0]
    assert stored.get("Id") == seg["id"], (
        f"returned segment must be the one submitted, expected id {seg['id']!r}, got "
        f"{stored.get('Id')!r}"
    )
    raw = stored.get("Document")
    assert raw, f"Segment.Document must be populated with the submitted payload, got {stored!r}"
    doc = json.loads(raw)
    assert doc["id"] == seg["id"], doc
    assert doc["trace_id"] == trace_id, doc
    assert doc["name"] == seg["name"], doc
    assert abs(float(doc["start_time"]) - seg["start_time"]) < 0.001, (
        f"stored start_time {doc['start_time']!r} must match submitted {seg['start_time']!r}"
    )
    assert abs(float(doc["end_time"]) - seg["end_time"]) < 0.001, (
        f"stored end_time {doc['end_time']!r} must match submitted {seg['end_time']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
