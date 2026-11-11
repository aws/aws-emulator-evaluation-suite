"""get-trace-graph-unknown-trace-fails."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-trace-graph-unknown-trace-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error_code(fn):
    """The AWS error (code, message) raised by fn(). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused but it succeeded: {result!r}")


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds=None) -> str:
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
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


def _trace_graph_or_empty(xr, trace_ids):
    """The trace graph's Services, or [] while the trace is not yet indexed.

    GetTraceGraph raises 'Trace id not found' for a not-yet-indexed trace too."""
    try:
        return xr.get_trace_graph(TraceIds=list(trace_ids)).get("Services", [])
    except ClientError:
        return []


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTraceGraph on an unknown TraceId fails with InvalidRequestException "Trace id not found"
    (BatchGetTraces returns an empty list), after a just-submitted trace's graph populates."""
    xr = ctx.client("xray")
    now = time.time()
    known_trace_id = new_trace_id(now)
    service_name = "sim2real-behav-xray-tg-" + _hex(6)
    segment = {
        "id": new_segment_id(), "name": service_name, "trace_id": known_trace_id,
        "start_time": now - 1.0, "end_time": now,
    }
    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"the positive control's own segment must be accepted, or the refusal below proves "
        f"nothing: {put!r}"
    )

    services = _poll_until(
        lambda: _trace_graph_or_empty(xr, [known_trace_id]),
        lambda svcs: any(s.get("Name") == service_name for s in svcs),
        description="the submitted trace's graph populated (positive control)",
    )
    assert any(s.get("Name") == service_name for s in services), services

    code, message = _error_code(lambda: xr.get_trace_graph(TraceIds=[new_trace_id()]))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}: {message!r}"
    assert message == "Trace id not found", f"expected 'Trace id not found', got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
