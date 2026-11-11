"""put-trace-segments-partial-failure-preserves-valid-members."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "put-trace-segments-partial-failure-preserves-valid-members"
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


def _poll_until(probe, predicate, timeout_s=60, interval_s=2, description="condition"):
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
    """In a batch of two valid segments and one missing the required `name`, only the invalid one
    is reported unprocessed (as MissingName) and is not stored, while both valid segments land.
    """
    xr = ctx.client("xray")
    now = time.time()

    valid_ids = [new_trace_id(now), new_trace_id(now)]
    docs = []
    for i, tid in enumerate(valid_ids):
        docs.append(json.dumps({
            "id": new_segment_id(),
            "name": f"sim2real-behav-xray-valid-{i}",
            "trace_id": tid,
            "start_time": now - 1.0,
            "end_time": now,
        }))

    # Invalid: `name` is a required member of the segment document. The document is well-formed
    # JSON and carries a valid id/trace_id, so the service can attribute the rejection.
    bad_trace_id = new_trace_id(now)
    bad_seg_id = new_segment_id()
    docs.insert(1, json.dumps({
        "id": bad_seg_id,
        "trace_id": bad_trace_id,
        "start_time": now - 1.0,
        "end_time": now,
    }))

    resp = xr.put_trace_segments(TraceSegmentDocuments=docs)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"PutTraceSegments must report per-document failure in the body, not as an HTTP error: "
        f"{resp!r}"
    )
    unprocessed = resp.get("UnprocessedTraceSegments", [])
    assert len(unprocessed) == 1, (
        f"exactly the one invalid document must be unprocessed, got {unprocessed!r}"
    )
    assert unprocessed[0].get("Id") == bad_seg_id, (
        f"unprocessed entry must identify the offending segment {bad_seg_id!r}, "
        f"got {unprocessed[0]!r}"
    )
    assert unprocessed[0].get("ErrorCode") == "MissingName", (
        f"expected the per-segment ErrorCode to identify the missing `name` member as "
        f"'MissingName', got {unprocessed[0].get('ErrorCode')!r} on {unprocessed[0]!r}"
    )
    assert unprocessed[0].get("Message") == "Invalid segment. ErrorCode: MissingName", (
        f"expected the per-segment Message to restate the error code, got "
        f"{unprocessed[0].get('Message')!r}"
    )

    for tid in valid_ids:
        got = _poll_until(
            lambda t=tid: xr.batch_get_traces(TraceIds=[t]),
            lambda r: len(r.get("Traces", [])) == 1,
            timeout_s=60,
            interval_s=2,
            description=f"valid batch member {tid} retrievable",
        )
        assert got["Traces"][0]["Id"] == tid, got

    # A single read suffices: the valid siblings from the same call are already visible.
    absent = xr.batch_get_traces(TraceIds=[bad_trace_id])
    assert absent.get("Traces", []) == [], (
        f"segment rejected for a missing required member must not be stored, got {absent!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
