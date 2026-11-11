"""device-position-history-rejects-inverted-time-window."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-position-history-rejects-inverted-time-window"
GROUP = 'tracking'
SERVICES = ['location']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """GetDevicePositionHistory rejects a window whose end is not after its start,
    and the device's history is unaffected by the rejected call.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_GetDevicePositionHistory.html
    """
    loc = ctx.client("location")
    tracker = ctx.unique_name("sim2real-behav-location-tracker-")
    loc.create_tracker(TrackerName=tracker)
    ctx.on_cleanup(_teardown(lambda: loc.delete_tracker(TrackerName=tracker), "ResourceNotFoundException"))

    device = "sim2real-device-1"
    t0 = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    loc.batch_update_device_position(TrackerName=tracker, Updates=[
        {"DeviceId": device, "SampleTime": t0, "Position": [-122.33, 47.60]}])

    deadline = time.monotonic() + 30
    before = []
    while time.monotonic() < deadline:
        before = loc.get_device_position_history(TrackerName=tracker, DeviceId=device)["DevicePositions"]
        if before:
            break
        time.sleep(2)
    assert before, "the positive control update never became visible in history within 30s"

    try:
        loc.get_device_position_history(
            TrackerName=tracker, DeviceId=device,
            StartTimeInclusive=t0 + datetime.timedelta(seconds=120),
            EndTimeExclusive=t0 + datetime.timedelta(seconds=60),
        )
        raise AssertionError("expected an inverted time window to be rejected")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
        expected = "'EndTimeExclusive' must be after 'StartTimeInclusive'."
        assert err["Message"] == expected, f"unexpected message {err['Message']!r}"

    after = loc.get_device_position_history(TrackerName=tracker, DeviceId=device)["DevicePositions"]
    assert len(after) == len(before), (
        f"history changed after the rejected call: {len(before)} samples before, {len(after)} after"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
