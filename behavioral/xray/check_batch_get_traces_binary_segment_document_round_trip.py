"""batch-get-traces-binary-segment-document-round-trip."""
from __future__ import annotations

import base64
import json
import os
import time

from behavioral_harness import tags

CHECK = "batch-get-traces-binary-segment-document-round-trip"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A large base64-encoded binary blob embedded in a segment's metadata is returned
    with the exact same content by BatchGetTraces (no truncation, corruption, or
    re-encoding of the blob)."""
    xray = ctx.client("xray")
    trace_id = _make_trace_id()
    segment_id = _make_segment_id()
    now = time.time()

    blob = base64.b64encode(os.urandom(8000)).decode("ascii")
    document = {
        "trace_id": trace_id,
        "id": segment_id,
        "name": ctx.unique_name("sim2real-xray-behav"),
        "start_time": now,
        "end_time": now + 0.1,
        "metadata": {"payload": {"blob": blob, "length": len(blob)}},
    }
    resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(document)])
    assert resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment with an 8000-byte base64 blob must be accepted outright, got "
        f"UnprocessedTraceSegments={resp.get('UnprocessedTraceSegments')!r}"
    )

    fetched = _wait_for_trace_document(ctx, trace_id, timeout_s=90.0)
    returned_blob = fetched["metadata"]["payload"]["blob"]
    assert len(returned_blob) == len(blob), (
        f"round-tripped blob length {len(returned_blob)} != submitted length {len(blob)} "
        f"(base64 truncated or padded across BatchGetTraces)"
    )
    assert returned_blob == blob, (
        "round-tripped blob content diverges from the submitted base64 payload "
        "(corruption or re-encoding across PutTraceSegments/BatchGetTraces)"
    )


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
