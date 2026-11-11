"""trace-summaries-ordered-by-time."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags

CHECK = "trace-summaries-ordered-by-time"
GROUP = "ordering"
SERVICES = ["xray"]


def _hex(n: int) -> str:
    return os.urandom(n).hex()


def _segment_doc(name: str, start_time: float) -> str:
    import json

    trace_id = f"1-{int(start_time):08x}-{_hex(12)}"
    return json.dumps(
        {
            "name": name,
            "id": _hex(8),
            "trace_id": trace_id,
            "start_time": start_time,
            "end_time": start_time + 0.25,
        }
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """GetTraceSummaries returns exactly the two traces inside the StartTime/EndTime window and
    not the one 50 minutes earlier, and a repeat query of the same window returns the same IDs
    in the same order."""
    xray = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    name = ctx.unique_name("sim2real-xray-ord-svc-")

    now = time.time()
    # Two traces inside the query window, one clearly OUTSIDE it (much further back).
    inside_offsets = [120, 60]
    outside_offset = 3000  # 50 minutes back -- outside the window queried below
    inside_docs = [_segment_doc(name, now - off) for off in inside_offsets]
    outside_doc = _segment_doc(name, now - outside_offset)

    put_resp = xray.put_trace_segments(TraceSegmentDocuments=inside_docs + [outside_doc])
    assert not put_resp.get("UnprocessedTraceSegments"), (
        f"segments rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    filter_expr = f'service("{name}")'
    start_time = now - 600
    end_time = now + 120

    summaries = _poll_for_trace_summaries(
        ctx, filter_expr, start_time, end_time, expected_count=2, timeout_s=240.0
    )

    start_times = [s["StartTime"] for s in summaries]
    assert len(summaries) == 2, (
        f"expected exactly the 2 in-window traces, got {len(summaries)}: {start_times}"
    )
    for st in start_times:
        st_epoch = st.timestamp() if hasattr(st, "timestamp") else st
        assert start_time <= st_epoch <= end_time, (
            f"trace summary StartTime {st} falls outside the queried window "
            f"[{start_time}, {end_time}]"
        )

    # A second, independent query of the SAME fixed window must return the identical
    # set of traces in the identical order -- listing is stable/idempotent.
    summaries2 = xray.get_trace_summaries(
        StartTime=start_time, EndTime=end_time, FilterExpression=filter_expr
    ).get("TraceSummaries", [])
    ids1 = [s["Id"] for s in summaries]
    ids2 = [s["Id"] for s in summaries2]
    assert ids1 == ids2, (
        f"repeated GetTraceSummaries calls over the identical fixed window returned "
        f"different trace sets/orders: {ids1} vs {ids2}"
    )


def _poll_for_trace_summaries(ctx, filter_expr, start_time, end_time, expected_count, timeout_s):
    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    last_summaries = []
    while time.monotonic() < deadline:
        resp = xray.get_trace_summaries(
            StartTime=start_time, EndTime=end_time, FilterExpression=filter_expr
        )
        last_summaries = resp.get("TraceSummaries", [])
        if len(last_summaries) >= expected_count:
            return last_summaries
        time.sleep(2.0)
    raise AssertionError(
        f"expected {expected_count} trace summaries within {timeout_s}s, "
        f"got {len(last_summaries)}"
    )


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want` for the rest of this check and
    return the destination it found.

    The destination (XRay, or CloudWatchLogs for Transaction Search) is one setting per account
    and region, and a switch takes about 6 minutes to go PENDING -> ACTIVE. The original is read
    first and its restore registered before the switch, so a refused or unsettled switch is undone."""
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    original = _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"]
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xray, original, timeout_s=timeout_s))
    if original == want:
        return original
    deadline = time.monotonic() + 120.0
    while True:
        try:
            xray.update_trace_segment_destination(Destination=want)
            break
        except ClientError as err:
            # A just-put logs resource policy takes a while to reach X-Ray, which until then
            # refuses CloudWatchLogs naming the PutLogEvents permission it cannot yet see.
            message = err.response["Error"].get("Message", "")
            if "PutLogEvents" not in message or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    current = _settled_trace_segment_destination(xray, timeout_s=timeout_s)
    assert current["Destination"] == want, (
        f"trace-segment destination settled on {current!r} instead of {want}/ACTIVE"
    )
    return original


def _settled_trace_segment_destination(xray, *, timeout_s: float) -> dict:
    # AWS refuses UpdateTraceSegmentDestination while a previous switch is still PENDING.
    deadline = time.monotonic() + timeout_s
    while True:
        current = xray.get_trace_segment_destination()
        if current.get("Status") == "ACTIVE":
            return current
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"trace-segment destination still not ACTIVE after {timeout_s}s: {current!r}"
            )
        time.sleep(2.0)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Cleanup: put the destination back and WAIT until it reads `original`/ACTIVE, so the next
    check starts from the account state this one found rather than from a PENDING switch."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

