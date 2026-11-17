"""get-image-findings-invalid-image-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-image-findings-invalid-image-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetImageFindings refuses a malformed image id, and a real id after the AMI is
    deregistered, each with its exact code and message."""
    ec2 = ctx.client("ec2")

    code, message = _error(lambda: ec2.get_image_findings(ImageId="ami-00000000000000000"))
    assert code == "InvalidAMIID.Malformed", f"expected InvalidAMIID.Malformed, got {code!r}"
    assert message == "The image ID 'ami-00000000000000000' is malformed", (
        f"unexpected InvalidAMIID.Malformed message {message!r}"
    )

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-gif-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _wait_for(lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"] == "available", 60, 3)

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id, Description=ctx.unique_name("sim2real-gif-snap-")
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _wait_for(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"] == "completed",
        180,
        5,
    )

    image_id = ec2.register_image(
        Name=ctx.unique_name("sim2real-gif-ami-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id}}],
    )["ImageId"]
    ctx.on_cleanup(
        _teardown(
            lambda: ec2.deregister_image(ImageId=image_id),
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
        )
    )
    ec2.deregister_image(ImageId=image_id)

    gone_code, gone_message = _error(lambda: ec2.get_image_findings(ImageId=image_id))
    assert gone_code == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {gone_code!r}"
    assert gone_message == f"The image id '[{image_id}]' does not exist", (
        f"unexpected InvalidAMIID.NotFound message {gone_message!r}"
    )


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_for(probe, timeout_s, interval_s) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(interval_s)
    assert probe(), "condition never became true within the deadline"


def _error(fn):
    """The (code, message) ``fn``'s ClientError carries; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
