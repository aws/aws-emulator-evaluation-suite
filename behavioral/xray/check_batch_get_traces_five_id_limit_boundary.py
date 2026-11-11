"""batch-get-traces-five-id-limit-boundary."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-get-traces-five-id-limit-boundary"
GROUP = 'overly-permissive'
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetTraces accepts at most 5 trace ids: 5 succeeds, 6 fails InvalidRequestException
    naming the limit, and the 5-id read still works afterwards."""
    xr = ctx.client("xray")
    now = time.time()

    # One real trace so the accepted call has something to return -- an all-empty 200 would not
    # distinguish "accepted the 5-id request" from "returned nothing for any reason".
    real_trace_id = new_trace_id(now)
    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps({
        "id": new_segment_id(),
        "name": "sim2real-behav-xray-limit-probe",
        "trace_id": real_trace_id,
        "start_time": now - 1.0,
        "end_time": now,
    })])
    assert put.get("UnprocessedTraceSegments", []) == [], put
    _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[real_trace_id]),
        lambda r: len(r.get("Traces", [])) == 1,
        timeout_s=60,
        interval_s=2,
        description="probe trace retrievable before exercising the id-count boundary",
    )

    filler = [new_trace_id(now) for _ in range(5)]

    # At the limit: 5 ids, one of them real.
    at_limit = [real_trace_id] + filler[:4]
    ok = xr.batch_get_traces(TraceIds=at_limit)
    assert ok["ResponseMetadata"]["HTTPStatusCode"] == 200, ok
    returned = [t["Id"] for t in ok.get("Traces", [])]
    assert returned == [real_trace_id], (
        f"5-id read must return exactly the one existing trace, got {returned!r}"
    )

    # One over the limit: refused.
    over_limit = [real_trace_id] + filler
    assert len(over_limit) == 6, f"test setup must request exactly 6 ids, got {len(over_limit)}"
    try:
        bad = xr.batch_get_traces(TraceIds=over_limit)
    except ClientError as exc:
        err = exc.response["Error"]
        code = err.get("Code")
        message = err.get("Message") or ""
        assert code == "InvalidRequestException", (
            f"6 trace ids must be refused as InvalidRequestException, got {code!r}: {message!r}"
        )
        # Distinguishing detail: the refusal names the id-count limit.
        assert message == "Exceeding maximum query size: 5", (
            f"rejection must name the id-count limit, got {message!r}"
        )
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc.response
    else:
        raise AssertionError(
            f"BatchGetTraces accepted 6 trace ids (limit is 5) and returned {bad!r}"
        )

    # Control: the boundary-legal call is unaffected by the refused one.
    again = xr.batch_get_traces(TraceIds=at_limit)
    assert [t["Id"] for t in again.get("Traces", [])] == [real_trace_id], again


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
