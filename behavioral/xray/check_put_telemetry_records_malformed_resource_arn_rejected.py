"""put-telemetry-records-malformed-resource-arn-rejected."""
from __future__ import annotations

import json
import os
import time

from behavioral_harness import tags

CHECK = "put-telemetry-records-malformed-resource-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["xray"]


def _hex(n: int) -> str:
    return os.urandom(n).hex()


def _segment_doc(name: str, start_time: float) -> str:
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


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """PutTelemetryRecords refuses an over-length EC2InstanceId with ValidationException naming
    the 20-character limit and accepts a valid one; a telemetry-only hostname never enters
    GetServiceGraph while a traced service does."""
    xray = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()

    # --- overly-permissive boundary: an EC2InstanceId longer than the documented
    # 20-character maximum must be rejected ---
    over_length_id = "i-" + "0" * 40  # far exceeds the 20-character maximum
    code, message = _error(
        lambda: xray.put_telemetry_records(
            TelemetryRecords=[
                {
                    "Timestamp": now,
                    "SegmentsReceivedCount": 1,
                    "SegmentsSentCount": 1,
                    "SegmentsSpilloverCount": 0,
                    "SegmentsRejectedCount": 0,
                }
            ],
            EC2InstanceId=over_length_id,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an over-length EC2InstanceId, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{over_length_id}' at 'eC2InstanceId' failed to "
        "satisfy constraint: Member must have length less than or equal to 20"
    ), f"unexpected message: {message!r}"

    # Positive control for the boundary above: an EC2InstanceId that is well-formed and
    # within the 20-character maximum must be accepted, or the rejection above cannot be
    # told apart from "rejects every EC2InstanceId".
    valid_resp = xray.put_telemetry_records(
        TelemetryRecords=[
            {
                "Timestamp": now,
                "SegmentsReceivedCount": 1,
                "SegmentsSentCount": 1,
                "SegmentsSpilloverCount": 0,
                "SegmentsRejectedCount": 0,
            }
        ],
        EC2InstanceId="i-0123456789abcdef0",  # 19 chars, within the 20-char maximum
    )
    assert valid_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected an in-limit EC2InstanceId to be accepted, got {valid_resp!r}"
    )

    traced_name = ctx.unique_name("sim2real-xray-tel-traced-")
    telemetry_only_host = ctx.unique_name("sim2real-xray-tel-only-")

    # Positive control: a real segment for `traced_name` must surface in the graph.
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[_segment_doc(traced_name, now)])
    assert not put_resp.get("UnprocessedTraceSegments"), (
        f"expected the positive-control segment to be fully accepted, got unprocessed "
        f"entries: {put_resp!r}"
    )

    start_time = now - 300
    end_time = now + 120

    def _graph_names():
        resp = xray.get_service_graph(StartTime=start_time, EndTime=end_time)
        names = set()
        for svc in resp.get("Services", []):
            names.add(svc.get("Name"))
            names.update(svc.get("Names", []) or [])
        return names

    positive_control_start = time.monotonic()
    deadline = positive_control_start + 240.0
    seen = set()
    while time.monotonic() < deadline:
        seen = _graph_names()
        if traced_name in seen:
            break
        time.sleep(2.0)
    assert traced_name in seen, (
        f"expected segment-derived service {traced_name!r} to appear in GetServiceGraph "
        f"within 240s, never did"
    )
    positive_control_latency_s = time.monotonic() - positive_control_start

    # Now submit a WELL-FORMED telemetry record (daemon health counters) tagged only
    # with a hostname that was NEVER used in any trace segment.
    xray.put_telemetry_records(
        TelemetryRecords=[
            {
                "Timestamp": now,
                "SegmentsReceivedCount": 12,
                "SegmentsSentCount": 12,
                "SegmentsSpilloverCount": 0,
                "SegmentsRejectedCount": 0,
            }
        ],
        Hostname=telemetry_only_host,
    )

    # Poll for a bounded window: the telemetry-only hostname must never leak into the service graph
    # as a fabricated node. Hold for >= 3x the positive control's measured latency, so a slower
    # target that would show the node later still gets the time to show it.
    hold_s = max(30.0, 3.0 * (positive_control_latency_s + 10.0))
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        seen = _graph_names()
        assert telemetry_only_host not in seen, (
            f"telemetry-only hostname {telemetry_only_host!r} leaked into "
            f"GetServiceGraph as a service node -- PutTelemetryRecords must not "
            f"feed the trace-segment-derived service graph"
        )
        time.sleep(5.0)


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


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected with a ClientError, it succeeded: {resp!r}")


