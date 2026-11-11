"""check-modify-volume-size-decrease-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "check-modify-volume-size-decrease-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyVolume rejects shrinking an EBS volume's size; DescribeVolumesModifications never
    records a phantom modification for the rejected request.
    """
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2)
    tag = [{"Key": "Name", "Value": ctx.unique_name("sim2real-volshrink-")}]

    # positive control: ModifyVolume must actually work, and DescribeVolumesModifications must
    # actually report a real modification -- otherwise a target that rejects every ModifyVolume
    # call, or one that always answers NotFound regardless of history, would pass the negative
    # below for the wrong reason.
    ctrl_id = ec2.create_volume(
        AvailabilityZone=az, Size=10, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": tag}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, ctrl_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[ctrl_id])["Volumes"][0]["State"],
        lambda state: state == "available",
        timeout_s=90,
    )
    ctrl_mod = ec2.modify_volume(VolumeId=ctrl_id, Size=12)["VolumeModification"]
    assert ctrl_mod["TargetSize"] == 12, (
        f"positive control: expected ModifyVolume to accept a legal grow 10->12, got {ctrl_mod}"
    )
    ctrl_listed = ec2.describe_volumes_modifications(VolumeIds=[ctrl_id])["VolumesModifications"]
    assert ctrl_listed and ctrl_listed[0]["VolumeId"] == ctrl_id, (
        f"positive control: expected DescribeVolumesModifications to report the accepted grow "
        f"for {ctrl_id}, got {ctrl_listed!r}"
    )

    vol = ec2.create_volume(
        AvailabilityZone=az, Size=10, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": tag}],
    )
    volume_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, volume_id))

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state == "available",
        timeout_s=90,
    )

    code, code_msg = _client_error(lambda: ec2.modify_volume(VolumeId=volume_id, Size=5))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert code_msg == "New size cannot be smaller than existing size", code_msg

    # a rejected shrink must not leave a modification record behind. Real AWS doesn't return
    # an empty list for a volume that has never been modified -- it raises NotFound for the
    # modification lookup itself, which is the actual "no modification record" signal here.
    mods_code, mods_code_msg = _client_error(
        lambda: ec2.describe_volumes_modifications(VolumeIds=[volume_id])["VolumesModifications"]
    )
    assert mods_code == "InvalidVolumeModification.NotFound", (
        f"expected no modification record (InvalidVolumeModification.NotFound), got {mods_code}"
    )
    assert mods_code_msg == f"Modification for volume '{volume_id}' does not exist.", mods_code_msg

    # the volume's real size must be unchanged
    size = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["Size"]
    assert size == 10, f"volume size changed despite rejected request: {size}"


def _first_available_az(ec2) -> str:
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert azs, "no available AZs found"
    return azs[0]["ZoneName"]


def _delete_volume(ec2, volume_id: str) -> None:
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state in ("available", "error"),
        timeout_s=90,
    )
    ec2.delete_volume(VolumeId=volume_id)


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
