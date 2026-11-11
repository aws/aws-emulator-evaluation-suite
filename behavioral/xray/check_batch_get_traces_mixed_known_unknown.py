"""batch-get-traces-mixed-known-unknown."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "batch-get-traces-mixed-known-unknown"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetTraces with a known and a well-formed unknown trace ID returns only the known trace and an
    empty UnprocessedTraceIds.
    """
    xr = ctx.client("xray")
    now = time.time()
    known_trace_id = new_trace_id(now)
    seg = {
        "id": new_segment_id(),
        "name": "known-service",
        "trace_id": known_trace_id,
        "start_time": now - 1.0,
        "end_time": now,
    }
    xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)])
    unknown_trace_id = new_trace_id()

    result = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[known_trace_id, unknown_trace_id]),
        lambda r: any(t["Id"] == known_trace_id for t in r.get("Traces", [])),
        timeout_s=60,
        interval_s=3,
        description="known trace present in BatchGetTraces",
    )

    trace_ids = [t["Id"] for t in result.get("Traces", [])]
    assert known_trace_id in trace_ids, result
    assert unknown_trace_id not in trace_ids, "unknown trace ID must not materialize a trace"
    assert result.get("UnprocessedTraceIds", []) == [], (
        f"unknown trace IDs must be silently omitted, not reported: {result.get('UnprocessedTraceIds')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
