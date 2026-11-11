"""update-trace-segment-destination-invalid-value-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-trace-segment-destination-invalid-value-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _wait_for_settled(xr, *, timeout_s: float = 120.0, interval_s: float = 5.0) -> dict:
    """Read-only wait for Status == ACTIVE. The destination is one setting per account, and a
    call made mid-transition (PENDING) would be refused as "update already in progress" instead."""
    deadline = time.monotonic() + timeout_s
    cfg = xr.get_trace_segment_destination()
    while cfg.get("Status") != "ACTIVE":
        if time.monotonic() >= deadline:
            raise AssertionError(f"trace segment destination never settled to ACTIVE: {cfg}")
        time.sleep(interval_s)
        cfg = xr.get_trace_segment_destination()
    return cfg


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """UpdateTraceSegmentDestination refuses the current value with InvalidRequestException "The
    destination is already set to ..." and an out-of-enum value with ValidationException listing
    the enum, and the destination stays unchanged."""
    xr = ctx.client("xray")
    baseline = _wait_for_settled(xr)
    current_destination = baseline["Destination"]

    same_value_code, same_value_message = _error_code(
        lambda: xr.update_trace_segment_destination(Destination=current_destination)
    )
    assert same_value_code == "InvalidRequestException", (
        f"expected InvalidRequestException for a same-value update, got {same_value_code}"
    )
    expected_same = f"The destination is already set to {current_destination}"
    assert same_value_message == expected_same, (
        f"expected message {expected_same!r}, got {same_value_message!r}"
    )

    code, message = _error_code(
        lambda: xr.update_trace_segment_destination(Destination="NotARealDestination")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "1 validation error detected: Value 'NotARealDestination' at 'destination' failed to "
        "satisfy constraint: Member must satisfy enum value set: [Composite, CloudWatchLogs, XRay]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected change must not have taken effect.
    resp = xr.get_trace_segment_destination()
    assert resp["Destination"] == current_destination, (
        f"destination unexpectedly changed from {current_destination} to {resp['Destination']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
