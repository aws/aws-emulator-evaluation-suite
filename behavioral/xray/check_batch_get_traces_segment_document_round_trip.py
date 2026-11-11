"""batch-get-traces-segment-document-round-trip."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "batch-get-traces-segment-document-round-trip"
GROUP = 'trace-data-plane'
SERVICES = ['xray']


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


def _poll_until(probe, predicate, timeout_s=90, interval_s=3, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetTraces returns the submitted segment Document (subsegments, annotations, http)
    with a Duration derived from its start/end times, and a `namespace: "remote"` subsegment
    makes X-Ray add an `inferred` segment parented to it that is absent without the namespace.
    """
    xr = ctx.client("xray")
    now = time.time()
    trace_id = new_trace_id(now)
    seg_id = new_segment_id()
    sub_id = new_segment_id()
    marker = _hex(10)
    start_time = now - 1.5
    end_time = now
    segment = {
        "id": seg_id,
        "name": "sim2real-behav-xray-doc",
        "trace_id": trace_id,
        "start_time": start_time,
        "end_time": end_time,
        "annotations": {"probe_marker": marker, "probe_count": 7},
        "http": {
            "request": {"method": "GET", "url": "https://example.invalid/probe", "client_ip": "127.0.0.1"},
            "response": {"status": 200},
        },
        "subsegments": [
            {
                "id": sub_id,
                "name": "sim2real-behav-xray-subseg",
                "start_time": start_time + 0.2,
                "end_time": end_time - 0.2,
                "namespace": "remote",
            }
        ],
    }

    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"a segment with annotations/http/subsegments must be accepted, got {put!r}"
    )

    result = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[trace_id]),
        lambda r: len(r.get("Traces", [])) == 1
        and len(r["Traces"][0].get("Segments") or []) >= 2,
        timeout_s=90,
        interval_s=3,
        description=(
            "trace retrievable with both the submitted segment and the segment inferred from "
            "the remote-namespace subsegment"
        ),
    )
    trace = result["Traces"][0]
    assert trace["Id"] == trace_id, trace
    assert result.get("UnprocessedTraceIds", []) == [], result

    segments = trace["Segments"]
    assert len(segments) == 2, (
        f"expected the submitted segment plus exactly one inferred segment for the single "
        f"remote-namespace subsegment, got {segments!r}"
    )
    by_id = {s.get("Id"): s for s in segments}
    assert seg_id in by_id, (
        f"the submitted segment must be returned under its own id {seg_id!r}, got "
        f"{sorted(by_id)}"
    )
    stored = by_id[seg_id]
    inferred_id = next(sid for sid in by_id if sid != seg_id)
    raw = stored.get("Document")
    assert raw, f"Segment.Document must be populated, got {stored!r}"
    doc = json.loads(raw)

    assert doc["id"] == seg_id, doc
    assert doc["trace_id"] == trace_id, doc
    assert doc["name"] == "sim2real-behav-xray-doc", doc
    assert abs(float(doc["start_time"]) - start_time) < 0.001, doc["start_time"]
    assert abs(float(doc["end_time"]) - end_time) < 0.001, doc["end_time"]

    assert doc["annotations"]["probe_marker"] == marker, doc["annotations"]
    assert doc["annotations"]["probe_count"] == 7, doc["annotations"]
    assert doc["http"]["response"]["status"] == 200, doc["http"]
    assert doc["http"]["request"]["method"] == "GET", doc["http"]

    subs = doc.get("subsegments")
    assert isinstance(subs, list) and len(subs) == 1, f"subsegments not round-tripped: {doc!r}"
    assert subs[0]["id"] == sub_id, subs[0]
    assert subs[0]["name"] == "sim2real-behav-xray-subseg", subs[0]
    assert subs[0]["namespace"] == "remote", subs[0]
    assert doc.get("inferred") is None, (
        f"the segment the client actually submitted must not be marked inferred, got {doc!r}"
    )

    # The second segment is the one X-Ray INVENTED for the remote callee: it is not a copy of
    # anything submitted, it hangs off the subsegment, and it carries the inferred flag.
    inferred_doc = json.loads(by_id[inferred_id]["Document"])
    assert inferred_doc["inferred"] is True, (
        f"the extra segment must declare itself inferred, got {inferred_doc!r}"
    )
    assert inferred_doc["parent_id"] == sub_id, (
        f"the inferred segment stands in for the callee of the remote subsegment, so its "
        f"parent_id must be the SUBSEGMENT id {sub_id!r}, got {inferred_doc.get('parent_id')!r}"
    )
    assert inferred_doc["id"] == inferred_id, inferred_doc
    assert inferred_doc["id"] not in (seg_id, sub_id), (
        f"the inferred segment gets a fresh service-assigned id, not the id of the segment or "
        f"subsegment it was derived from, got {inferred_doc['id']!r}"
    )
    assert inferred_doc["trace_id"] == trace_id, inferred_doc
    assert inferred_doc["name"] == "sim2real-behav-xray-subseg", (
        f"the inferred segment is named after the remote subsegment that produced it, got "
        f"{inferred_doc.get('name')!r}"
    )
    assert abs(float(inferred_doc["start_time"]) - (start_time + 0.2)) < 0.001, inferred_doc
    assert abs(float(inferred_doc["end_time"]) - (end_time - 0.2)) < 0.001, inferred_doc
    assert "subsegments" not in inferred_doc and "annotations" not in inferred_doc, (
        f"the inferred segment is synthesised from the subsegment alone and must not inherit the "
        f"parent segment's payload, got {inferred_doc!r}"
    )

    # Trace.Duration is computed by the service from the segment's own span (1.5s here), not
    # echoed from the request. Tolerance covers float serialisation and the service's rounding.
    duration = trace.get("Duration")
    assert duration is not None, f"Trace.Duration must be populated, got {trace!r}"
    assert abs(float(duration) - (end_time - start_time)) <= 0.25, (
        f"Trace.Duration {duration!r} must reflect the submitted span "
        f"{end_time - start_time:.3f}s"
    )

    # Control -- attribute the extra segment to the namespace, not to segment duplication: the
    # identical document with "namespace" dropped from the subsegment comes back as ONE segment,
    # with the subsegment still nested inside the document where it was submitted.
    plain_trace_id = new_trace_id(now)
    plain_seg_id = new_segment_id()
    plain_sub_id = new_segment_id()
    plain = dict(
        segment,
        id=plain_seg_id,
        trace_id=plain_trace_id,
        subsegments=[
            {
                "id": plain_sub_id,
                "name": "sim2real-behav-xray-subseg",
                "start_time": start_time + 0.2,
                "end_time": end_time - 0.2,
            }
        ],
    )
    put_plain = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(plain)])
    assert put_plain.get("UnprocessedTraceSegments", []) == [], put_plain
    plain_result = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[plain_trace_id]),
        lambda r: len(r.get("Traces", [])) == 1 and bool(r["Traces"][0].get("Segments")),
        timeout_s=90,
        interval_s=3,
        description="control trace (subsegment without a namespace) retrievable",
    )
    plain_segments = plain_result["Traces"][0]["Segments"]
    assert len(plain_segments) == 1, (
        f"a subsegment with no namespace names no downstream service, so X-Ray must infer "
        f"nothing and the trace must hold only the submitted segment, got {plain_segments!r}"
    )
    assert plain_segments[0]["Id"] == plain_seg_id, plain_segments[0]
    plain_doc = json.loads(plain_segments[0]["Document"])
    assert plain_doc.get("inferred") is None, plain_doc
    assert [s["id"] for s in plain_doc["subsegments"]] == [plain_sub_id], (
        f"the subsegment must stay nested in the submitted document, got {plain_doc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
