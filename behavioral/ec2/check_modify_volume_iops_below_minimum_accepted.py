"""modify-volume-iops-below-minimum-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "modify-volume-iops-below-minimum-accepted"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyVolume accepts an Iops value below the gp3 minimum of 3000 and clamps it up to the
    floor, so the below-minimum value is never applied."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vol-")

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=10,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=60,
    )

    # The call is accepted synchronously; clamping is only observable in the modification's
    # terminal state.
    ec2.modify_volume(VolumeId=volume_id, Iops=100)

    final = _poll_until(
        lambda: ec2.describe_volumes_modifications(VolumeIds=[volume_id])["VolumesModifications"][0],
        lambda m: m["ModificationState"] in ("completed", "optimizing", "failed"),
        timeout_s=180,
    )
    # The volume is already at the 3000 floor, so the clamped modification completes as a no-op.
    assert final["ModificationState"] in ("completed", "optimizing"), final
    assert final.get("TargetIops") != 100, final
    assert final.get("TargetIops", 0) >= 3000, final

    vol = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert vol.get("Iops") != 100, vol
    assert vol.get("Iops", 0) >= 3000, vol


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
