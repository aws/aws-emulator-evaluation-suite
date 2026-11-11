"""device-position-history-time-window-filters-results."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-position-history-time-window-filters-results"
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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """GetDevicePositionHistory's StartTimeInclusive/EndTimeExclusive select only the
    sample in that half-open window, not the whole device history.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_GetDevicePositionHistory.html
    """
    loc = ctx.client("location")
    tracker = ctx.unique_name("sim2real-behav-location-tracker-")
    loc.create_tracker(TrackerName=tracker)
    ctx.on_cleanup(_teardown(lambda: loc.delete_tracker(TrackerName=tracker),
                              "ResourceNotFoundException"))

    device = "sim2real-device-1"
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    t0, t1, t2 = base, base + datetime.timedelta(seconds=60), base + datetime.timedelta(seconds=120)
    p0, p1, p2 = [-122.33, 47.60], [-122.43, 47.70], [-122.53, 47.80]

    for sample_time, position in ((t0, p0), (t1, p1), (t2, p2)):
        loc.batch_update_device_position(TrackerName=tracker, Updates=[
            {"DeviceId": device, "SampleTime": sample_time, "Position": position}])
        time.sleep(3)

    deadline = time.monotonic() + 30
    full_positions: list = []
    while time.monotonic() < deadline:
        full_positions = [p["Position"] for p in
                           loc.get_device_position_history(TrackerName=tracker, DeviceId=device)["DevicePositions"]]
        if len(full_positions) == 3:
            break
        time.sleep(2)
    assert full_positions == [p0, p1, p2], (
        f"unfiltered history was {full_positions!r}, expected all 3 samples"
    )

    windowed = loc.get_device_position_history(
        TrackerName=tracker, DeviceId=device,
        StartTimeInclusive=t0 + datetime.timedelta(seconds=30),
        EndTimeExclusive=t2,
    )
    positions = [p["Position"] for p in windowed["DevicePositions"]]
    assert positions == [p1], (
        f"windowed history was {positions!r}, expected only the middle sample {p1!r} "
        "(t0 before the window start, t2 at the exclusive end)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
