"""get-trace-summaries-returns-time-descending-order."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-trace-summaries-returns-time-descending-order"
GROUP = "state-machine"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """GetTraceSummaries filtered by a unique annotation returns exactly the three ingested
    trace IDs, and a filter on a never-ingested value matches nothing; AWS guarantees no order,
    so membership is asserted."""
    xray = ctx.client("xray")
    tag_value = ctx.unique_name("sim2real-xray-summ-")
    now = datetime.now(timezone.utc)

    # Three distinct traces, each started at a different, known offset in the past,
    # all tagged with the same unique annotation so we can isolate them from any other
    # traffic in the account.
    offsets_seconds = [90, 60, 30]  # oldest to newest
    trace_ids = []
    documents = []
    for offset in offsets_seconds:
        start_dt = now - timedelta(seconds=offset)
        trace_id = _trace_id(int(start_dt.timestamp()))
        trace_ids.append(trace_id)
        segment = {
            "name": "sim2real-xray-ordering-check",
            "id": _segment_id(),
            "trace_id": trace_id,
            "start_time": start_dt.timestamp(),
            "end_time": start_dt.timestamp() + 0.5,
            "annotations": {"sim2real_tag": tag_value},
        }
        documents.append(json.dumps(segment))

    # The trace-segment destination is account-wide and can be switched concurrently, so the
    # destination pin and the put are retried as one unit: a transient "no resource-based policy
    # allows logs:PutLogEvents" is that race, not a rejection of these segments.
    put_resp = _put_segments_on_classic_destination(
        xray, ctx, documents, timeout_s=240.0, interval_s=10.0
    )
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segments were rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    window_start = now - timedelta(minutes=10)
    window_end = now + timedelta(minutes=5)
    filter_expression = f'annotation.sim2real_tag = "{tag_value}"'

    summaries = _poll_for_summaries(
        xray,
        window_start,
        window_end,
        filter_expression,
        expected_ids=set(trace_ids),
        timeout_s=150.0,
        interval_s=5.0,
    )

    returned_ids = {s["Id"] for s in summaries}
    assert returned_ids == set(trace_ids), (
        f"GetTraceSummaries did not return exactly the ingested traces: "
        f"missing={set(trace_ids) - returned_ids}, extra={returned_ids - set(trace_ids)}"
    )

    # Overly-permissive guard: a filter naming a tag value that was never ingested
    # must match none of our just-created traces (or anything else).
    never_used_tag = ctx.unique_name("sim2real-xray-summ-unused-")
    unmatched = xray.get_trace_summaries(
        StartTime=window_start,
        EndTime=window_end,
        FilterExpression=f'annotation.sim2real_tag = "{never_used_tag}"',
        Sampling=False,
    )
    assert unmatched.get("TraceSummaries", []) == [], (
        "GetTraceSummaries matched traces for a tag value that was never ingested"
    )


def _trace_id(epoch_seconds: int) -> str:
    return f"1-{epoch_seconds:08x}-{random.getrandbits(96):024x}"


def _segment_id() -> str:
    return f"{random.getrandbits(64):016x}"


def _put_segments_on_classic_destination(xray, ctx, documents, *, timeout_s, interval_s):
    """Re-pin the destination to classic XRay and attempt PutTraceSegments, retrying
    the whole unit while a concurrently-running check's CloudWatchLogs toggle is the
    cause of failure (a transient cross-account logs:PutLogEvents rejection), rather
    than retrying the API call in isolation."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_message = None
    while time.monotonic() < deadline:
        _pin_trace_segment_destination(ctx, "XRay")
        try:
            return xray.put_trace_segments(TraceSegmentDocuments=documents)
        except ClientError as err:
            message = err.response["Error"].get("Message", "")
            if "PutLogEvents" not in message and "resource-based policy" not in message:
                raise
            last_message = message
            time.sleep(interval_s)
    raise AssertionError(
        f"PutTraceSegments kept hitting the CloudWatchLogs delivery race within {timeout_s}s "
        f"(last: {last_message})"
    )


def _poll_for_summaries(
    xray, start_time, end_time, filter_expression, *, expected_ids, timeout_s, interval_s
):
    deadline = time.monotonic() + timeout_s
    last_seen = []
    while time.monotonic() < deadline:
        resp = xray.get_trace_summaries(
            StartTime=start_time,
            EndTime=end_time,
            FilterExpression=filter_expression,
            Sampling=False,
        )
        last_seen = resp.get("TraceSummaries", [])
        seen_ids = {s["Id"] for s in last_seen}
        if expected_ids.issubset(seen_ids):
            # Keep only ours, preserving the service's returned order.
            return [s for s in last_seen if s["Id"] in expected_ids]
        time.sleep(interval_s)
    raise AssertionError(
        f"GetTraceSummaries never indexed all 3 tagged traces within {timeout_s}s "
        f"(last saw {len(last_seen)} summaries)"
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
