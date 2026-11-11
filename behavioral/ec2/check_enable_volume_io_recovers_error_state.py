"""enable-volume-io-recovers-error-state."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "enable-volume-io-recovers-error-state"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableVolumeIO on a volume whose I/O is already enabled fails IncorrectState with "Volume
    <id> already has IO enabled." twice in a row, and the volume stays available with an ok or
    insufficient-data status.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-volio-")
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=_tag_spec("volume", name),
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
    )

    def _io_status():
        statuses = ec2.describe_volume_status(VolumeIds=[vol_id])["VolumeStatuses"]
        if not statuses:
            return None
        # The top-level VolumeStatus.Status ('ok' | 'impaired' | 'insufficient-data') is
        # the I/O health signal; the nested Details[].Status values are per-check results.
        return statuses[0]["VolumeStatus"].get("Status")

    # A freshly created, unattached volume is healthy: DescribeVolumeStatus
    # reports it as 'ok' (or 'insufficient-data' before the first check-up
    # runs) -- never 'impaired'.
    initial_status = _poll_until(
        _io_status, lambda s: s in ("ok", "insufficient-data"), timeout_s=60, interval_s=3
    )
    assert initial_status in ("ok", "insufficient-data"), (
        f"expected a freshly created volume's I/O health to be 'ok' or 'insufficient-data', "
        f"got {initial_status!r}"
    )

    # EnableVolumeIO on a volume whose IO is already enabled is rejected with
    # IncorrectState rather than succeeding as a no-op, and the volume stays
    # healthy and 'available' afterward.
    code, message = _error(lambda: ec2.enable_volume_io(VolumeId=vol_id))
    assert code == "IncorrectState", f"unexpected code: {code!r}"
    assert message == f"Volume {vol_id} already has IO enabled.", f"unexpected IncorrectState message: {message!r}"

    after_first = _poll_until(
        _io_status, lambda s: s in ("ok", "insufficient-data"), timeout_s=60, interval_s=3
    )
    assert after_first in ("ok", "insufficient-data"), (
        f"rejected EnableVolumeIO must not degrade I/O health; expected 'ok' or "
        f"'insufficient-data', got {after_first!r}"
    )
    state_after_first = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"]
    assert state_after_first == "available", (
        f"expected volume state to remain 'available' after the rejected call, got {state_after_first!r}"
    )

    # Calling it again on the same, still-healthy volume produces the
    # identical rejection (deterministic precondition check, not flaky) and
    # must not regress the volume's reported health.
    code2, message2 = _error(lambda: ec2.enable_volume_io(VolumeId=vol_id))
    assert code2 == "IncorrectState", f"unexpected code on retry: {code2!r}"
    assert message2 == f"Volume {vol_id} already has IO enabled.", f"unexpected IncorrectState message on retry: {message2!r}"
    after_second = _poll_until(
        _io_status, lambda s: s in ("ok", "insufficient-data"), timeout_s=60, interval_s=3
    )
    assert after_second in ("ok", "insufficient-data"), (
        f"the identical rejection on retry must not degrade I/O health either; expected 'ok' or "
        f"'insufficient-data', got {after_second!r}"
    )
    state_after_second = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"]
    assert state_after_second == "available", (
        f"expected volume state to remain 'available' after the second rejected call, got {state_after_second!r}"
    )


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
