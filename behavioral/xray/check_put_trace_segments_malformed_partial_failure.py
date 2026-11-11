"""put-trace-segments-malformed-partial-failure."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "put-trace-segments-malformed-partial-failure"
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
    """PutTraceSegments with one valid and one unparseable document answers HTTP 200 with one
    UnprocessedTraceSegments entry (ErrorCode ParseError, no Id, its fixed Message), and the
    valid trace is retrievable."""
    xr = ctx.client("xray")
    now = time.time()
    good_trace_id = new_trace_id(now)
    good_seg = {
        "id": new_segment_id(),
        "name": "good-service",
        "trace_id": good_trace_id,
        "start_time": now - 1.0,
        "end_time": now,
    }
    bad_doc = "{not-valid-json"

    resp = xr.put_trace_segments(
        TraceSegmentDocuments=[json.dumps(good_seg), bad_doc]
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"PutTraceSegments must report per-document failure in the body, not as an HTTP error: {resp!r}"
    )
    unprocessed = resp.get("UnprocessedTraceSegments", [])
    assert len(unprocessed) == 1, f"expected exactly one unprocessed segment, got {unprocessed}"
    entry = unprocessed[0]
    assert entry.get("ErrorCode") == "ParseError", (
        f"expected the unparseable document to be reported as ErrorCode 'ParseError', got {entry!r}"
    )
    assert entry.get("Id") is None, (
        f"an unparseable document carries no id to attribute the failure to, expected Id=None, got {entry!r}"
    )
    assert entry.get("Message") == "Invalid segment. ErrorCode: ParseError", (
        f"expected the per-segment Message to restate the error code, got {entry!r}"
    )

    result = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[good_trace_id]),
        lambda r: len(r.get("Traces", [])) == 1,
        timeout_s=30,
        interval_s=2,
        description="good segment retrievable via BatchGetTraces",
    )
    assert result["Traces"][0]["Id"] == good_trace_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
