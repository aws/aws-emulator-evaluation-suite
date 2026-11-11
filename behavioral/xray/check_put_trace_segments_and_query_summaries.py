"""put-trace-segments-and-query-summaries."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "put-trace-segments-and-query-summaries"
GROUP = 'trace-data-plane'
SERVICES = ['xray']


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds=None) -> str:
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=180, interval_s=10, description="condition"):
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
    """A segment submitted via PutTraceSegments is retrievable end-to-end via GetTraceSummaries.

    Real X-Ray indexes segments asynchronously, so the summaries query is polled until the
    submitted trace appears — on both the real backend and an emulator, with the same assertion.
    """
    xr = ctx.client("xray")
    now = time.time()
    trace_id = new_trace_id(now)
    seg = {
        "id": new_segment_id(),
        "name": "checkout-service",
        "trace_id": trace_id,
        "start_time": now - 2.0,
        "end_time": now,
    }
    resp = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)])
    assert resp.get("UnprocessedTraceSegments", []) == [], resp

    start = now - 60
    end = now + 60

    def query():
        r = xr.get_trace_summaries(StartTime=start, EndTime=end)
        assert "TraceSummaries" in r, f"missing TraceSummaries key: {list(r)}"
        assert isinstance(r["TraceSummaries"], list)
        return r

    result = _poll_until(
        query,
        lambda r: any(s.get("Id") == trace_id for s in r.get("TraceSummaries", [])),
        timeout_s=180,
        interval_s=10,
        description="submitted trace retrievable via GetTraceSummaries",
    )
    assert any(s.get("Id") == trace_id for s in result["TraceSummaries"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
