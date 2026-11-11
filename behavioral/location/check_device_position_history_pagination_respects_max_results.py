"""device-position-history-pagination-respects-max-results."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-position-history-pagination-respects-max-results"
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
    """GetDevicePositionHistory with MaxResults=1 pages through every sample via
    NextToken, in sample-time order, rather than truncating the history.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_GetDevicePositionHistory.html
    """
    loc = ctx.client("location")
    tracker = ctx.unique_name("sim2real-behav-location-tracker-")
    loc.create_tracker(TrackerName=tracker)
    ctx.on_cleanup(_teardown(lambda: loc.delete_tracker(TrackerName=tracker), "ResourceNotFoundException"))

    device = "sim2real-device-1"
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    samples = [
        (base + datetime.timedelta(seconds=i * 60), [-122.33 - i * 0.1, 47.60 + i * 0.1])
        for i in range(3)
    ]
    for sample_time, position in samples:
        loc.batch_update_device_position(TrackerName=tracker, Updates=[
            {"DeviceId": device, "SampleTime": sample_time, "Position": position}])
        time.sleep(3)

    pages = list(loc.get_paginator("get_device_position_history").paginate(
        TrackerName=tracker, DeviceId=device, PaginationConfig={"PageSize": 1}))
    assert len(pages) == 3, f"expected 3 pages of 1 result each, got {len(pages)} pages"
    for page in pages:
        assert len(page["DevicePositions"]) == 1, (
            f"expected exactly 1 result per page, got {len(page['DevicePositions'])}"
        )

    paged_positions = [p["DevicePositions"][0]["Position"] for p in pages]
    assert paged_positions == [pos for _, pos in samples], (
        f"paginated order was {paged_positions!r}, expected sample-time order {[pos for _, pos in samples]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
