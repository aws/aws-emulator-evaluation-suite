"""distance-based-position-filtering-suppresses-near-duplicate."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distance-based-position-filtering-suppresses-near-duplicate"
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


def _wait_for_position(loc, tracker: str, device: str, expected, *, budget_s: float = 30.0):
    """Poll GetDevicePosition until it reports ``expected``, tolerating read lag."""
    deadline = time.monotonic() + budget_s
    seen = None
    while time.monotonic() < deadline:
        try:
            seen = loc.get_device_position(TrackerName=tracker, DeviceId=device)["Position"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            seen = None
        if seen == expected:
            return
        time.sleep(2)
    raise AssertionError(f"device position never converged to {expected!r}; last seen {seen!r}")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A tracker with DistanceBased filtering drops an update within meters of the last
    recorded position, but keeps one far enough away.

    Reference: https://docs.aws.amazon.com/location/previous/developerguide/update-device-position.html
    """
    loc = ctx.client("location")
    tracker = ctx.unique_name("sim2real-behav-location-tracker-")
    loc.create_tracker(TrackerName=tracker, PositionFiltering="DistanceBased")
    ctx.on_cleanup(_teardown(lambda: loc.delete_tracker(TrackerName=tracker),
                              "ResourceNotFoundException"))

    device = "sim2real-device-1"
    far_point_1 = [-122.3321, 47.6062]
    near_point = [-122.332101, 47.606201]  # ~1.5m from far_point_1
    far_point_2 = [-122.4321, 47.7062]  # ~10km from far_point_1

    loc.batch_update_device_position(TrackerName=tracker, Updates=[
        {"DeviceId": device, "SampleTime": datetime.datetime.now(datetime.timezone.utc),
         "Position": far_point_1}])
    _wait_for_position(loc, tracker, device, far_point_1)

    time.sleep(5)
    loc.batch_update_device_position(TrackerName=tracker, Updates=[
        {"DeviceId": device, "SampleTime": datetime.datetime.now(datetime.timezone.utc),
         "Position": near_point}])

    time.sleep(5)
    loc.batch_update_device_position(TrackerName=tracker, Updates=[
        {"DeviceId": device, "SampleTime": datetime.datetime.now(datetime.timezone.utc),
         "Position": far_point_2}])
    _wait_for_position(loc, tracker, device, far_point_2)

    history = loc.get_device_position_history(TrackerName=tracker, DeviceId=device)
    positions = [p["Position"] for p in history["DevicePositions"]]
    assert positions == [far_point_1, far_point_2], (
        f"expected only the two far positions (near-duplicate filtered), got {positions!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
