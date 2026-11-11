"""put-trace-segments-binary-document-base64-roundtrip."""
from __future__ import annotations

import base64
import json
import os
import time

from behavioral_harness import tags

CHECK = "put-trace-segments-binary-document-base64-roundtrip"
GROUP = "representation"
SERVICES = ["xray"]


def _new_trace_id() -> str:
    epoch_hex = format(int(time.time()), "x")
    rand_hex = os.urandom(12).hex()
    return f"1-{epoch_hex}-{rand_hex}"


def _poll_for_segment(xray, trace_id: str, segment_id: str, *, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = xray.batch_get_traces(TraceIds=[trace_id])
        for trace in resp.get("Traces", []):
            for segment in trace.get("Segments", []):
                parsed = json.loads(segment["Document"])
                if parsed.get("id") == segment_id:
                    return parsed
        time.sleep(interval_s)
    return None


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A segment whose metadata holds a base64 blob comes back from BatchGetTraces with the
    payload unchanged character for character and decoding to the original 37 bytes."""
    xray = ctx.client("xray")

    trace_id = _new_trace_id()
    segment_id = os.urandom(8).hex()
    blob = os.urandom(37)
    blob_b64 = base64.b64encode(blob).decode("ascii")
    now = time.time()

    document = {
        "id": segment_id,
        "trace_id": trace_id,
        "name": "sim2real-xray-check",
        "start_time": now - 1.0,
        "end_time": now,
        "metadata": {
            "default": {
                "payload_b64": blob_b64,
            }
        },
    }

    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(document)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment rejected outright: {put_resp.get('UnprocessedTraceSegments')}"
    )

    parsed = _poll_for_segment(xray, trace_id, segment_id)
    if parsed is None:
        raise AssertionError(
            f"segment {segment_id} on trace {trace_id} never became queryable via BatchGetTraces within 90s"
        )

    round_tripped_b64 = parsed["metadata"]["default"]["payload_b64"]
    assert round_tripped_b64 == blob_b64, (
        f"base64 payload changed across the PutTraceSegments/BatchGetTraces round trip: "
        f"{round_tripped_b64!r} != {blob_b64!r}"
    )
    assert base64.b64decode(round_tripped_b64) == blob, (
        f"decoded round-tripped payload does not match the original {len(blob)}-byte blob"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
