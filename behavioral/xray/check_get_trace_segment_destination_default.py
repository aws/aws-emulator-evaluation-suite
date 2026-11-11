"""get-trace-segment-destination-default."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-trace-segment-destination-default"
GROUP = 'trace-segment-destination'
SERVICES = ['xray']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """After pinning the trace segment destination to XRay, it reads back XRay with Status ACTIVE.

    The destination is per account and region, so it is pinned and restored afterwards."""
    _pin_trace_segment_destination(ctx, "XRay")
    resp = ctx.client("xray").get_trace_segment_destination()
    assert resp["Destination"] == "XRay", resp
    assert resp["Status"] == "ACTIVE", resp


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want`; return the one it found.

    A switch takes ~6 minutes PENDING -> ACTIVE; the restore is registered before switching."""
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
    """Put the destination back and wait until it reads `original`/ACTIVE."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
