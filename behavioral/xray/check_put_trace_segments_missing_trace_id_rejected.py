"""put-trace-segments-missing-trace-id-rejected."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "put-trace-segments-missing-trace-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A segment missing trace_id is reported in UnprocessedTraceSegments as MissingTraceId and
    never becomes queryable, while a well-formed sibling in the same call is ingested and found.
    """
    xray = ctx.client("xray")
    now = time.time()

    # GetTraceSummaries only sees segments delivered to the XRay destination.
    _pin_trace_segment_destination(ctx, "XRay")

    good_marker = ctx.unique_name("good-")[:20]

    bad_marker = ctx.unique_name("bad-")[:20]

    good_trace_id = _new_trace_id()
    bad_seg_id = _hex(16)
    good_seg = {
        "name": "sim2ray-good-svc",
        "id": _hex(16),
        "trace_id": good_trace_id,
        "start_time": now,
        "end_time": now + 0.05,
        "annotations": {"marker": good_marker},
    }
    bad_seg = {
        # intentionally missing "trace_id"
        "name": "sim2ray-bad-svc",
        "id": bad_seg_id,
        "start_time": now,
        "end_time": now + 0.05,
        "annotations": {"marker": bad_marker},
    }

    resp = xray.put_trace_segments(
        TraceSegmentDocuments=[json.dumps(good_seg), json.dumps(bad_seg)]
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"PutTraceSegments must report per-document failure in the body, not as an HTTP error: {resp!r}"
    )
    unprocessed = resp.get("UnprocessedTraceSegments", [])
    assert len(unprocessed) == 1, f"expected exactly 1 unprocessed segment, got {unprocessed}"
    bad_entry = unprocessed[0]
    assert bad_entry.get("Id") == bad_seg_id, (
        f"UnprocessedTraceSegments entry must be keyed by the rejected segment's own id "
        f"{bad_seg_id!r}, got {bad_entry!r}"
    )
    assert bad_entry.get("ErrorCode") == "MissingTraceId", (
        f"expected the per-segment ErrorCode to identify the missing trace_id member as "
        f"'MissingTraceId', got {bad_entry.get('ErrorCode')!r} on {bad_entry!r}"
    )
    assert bad_entry.get("Message") == "Invalid segment. ErrorCode: MissingTraceId", (
        f"expected the per-segment Message to restate the error code, got "
        f"{bad_entry.get('Message')!r}"
    )

    # Sampling=False makes the scan exhaustive, so one specific trace is reliably found or not.
    start = now - 300
    end = now + 300
    bad_summaries = xray.get_trace_summaries(
        StartTime=start,
        EndTime=end,
        FilterExpression=f'annotation.marker = "{bad_marker}"',
        Sampling=False,
    )["TraceSummaries"]
    assert bad_summaries == [], f"malformed segment unexpectedly produced trace summaries: {bad_summaries}"

    # GetTraceSummaries indexing can lag well behind BatchGetTraces visibility, so poll generously.
    good_summaries = _poll_until(
        lambda: xray.get_trace_summaries(
            StartTime=start,
            EndTime=end,
            FilterExpression=f'annotation.marker = "{good_marker}"',
            Sampling=False,
        )["TraceSummaries"],
        lambda summaries: len(summaries) >= 1,
        timeout_s=900,
        interval_s=20,
    )
    assert any(s["Id"] == good_trace_id for s in good_summaries), (
        f"expected trace {good_trace_id} among summaries, got {good_summaries}"
    )

    # Re-confirm absence now that the pipeline is proven to be indexing promptly.
    bad_summaries_again = xray.get_trace_summaries(
        StartTime=start,
        EndTime=end,
        FilterExpression=f'annotation.marker = "{bad_marker}"',
        Sampling=False,
    )["TraceSummaries"]
    assert bad_summaries_again == [], (
        f"malformed segment unexpectedly appeared after indexing settled: {bad_summaries_again}"
    )


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _new_trace_id() -> str:
    return f"1-{int(time.time()):08x}-{_hex(24)}"


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")
        time.sleep(interval_s)


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Pins the account-wide trace-segment destination to `want` and returns the original.

    A switch takes minutes to go PENDING -> ACTIVE, so the restore is registered before switching.
    """
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
    """Restores the destination and waits until it is ACTIVE, so no PENDING switch is left behind."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
