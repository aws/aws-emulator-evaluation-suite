"""batch-update-device-position-partial-failure-only-valid-persists."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-update-device-position-partial-failure-only-valid-persists"
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


def _error_code(fn) -> str:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A batch update with one invalid entry reports that entry's error and still
    commits every other entry in the same batch.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_BatchUpdateDevicePosition.html
    """
    loc = ctx.client("location")
    tracker = ctx.unique_name("sim2real-behav-location-tracker-")
    loc.create_tracker(TrackerName=tracker)
    ctx.on_cleanup(_teardown(lambda: loc.delete_tracker(TrackerName=tracker),
                              "ResourceNotFoundException"))

    good_device, bad_device = "sim2real-good", "sim2real-bad"
    now = datetime.datetime.now(datetime.timezone.utc)
    result = loc.batch_update_device_position(TrackerName=tracker, Updates=[
        {"DeviceId": good_device, "SampleTime": now, "Position": [-122.33, 47.60]},
        {"DeviceId": bad_device, "SampleTime": now, "Position": [200.0, 47.60]},
    ])

    errors = result["Errors"]
    assert len(errors) == 1, f"expected exactly 1 batch error, got {len(errors)}: {errors!r}"
    assert errors[0]["DeviceId"] == bad_device, (
        f"the error named device {errors[0]['DeviceId']!r}, expected {bad_device!r}"
    )
    assert errors[0]["Error"]["Code"] == "ValidationError", (
        f"expected ValidationError, got {errors[0]['Error']['Code']!r}"
    )
    assert errors[0]["Error"]["Message"] == "longitude must be between -180 and 180 degrees", (
        f"unexpected error message {errors[0]['Error']['Message']!r}"
    )

    deadline = time.monotonic() + 30
    good = None
    while time.monotonic() < deadline:
        try:
            good = loc.get_device_position(TrackerName=tracker, DeviceId=good_device)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(2)
    assert good is not None, "the valid entry never became visible within 30s"
    assert good["Position"] == [-122.33, 47.60], (
        f"the valid entry's position was {good['Position']!r}, expected [-122.33, 47.6]"
    )

    code = _error_code(lambda: loc.get_device_position(TrackerName=tracker, DeviceId=bad_device))
    assert code == "ResourceNotFoundException", (
        f"expected the rejected entry to have never been stored, got code {code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
