"""register-image-missing-source-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-image-missing-source-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterImage refuses a request with neither ImageLocation nor RootDeviceName, with the
    exact code and message, while the identical request naming a snapshot succeeds."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-regimg-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _wait_for(lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"] == "available", 60, 3)

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id, Description=ctx.unique_name("sim2real-regimg-snap-")
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _wait_for(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"] == "completed",
        180,
        5,
    )

    rejected_name = ctx.unique_name("sim2real-regimg-ami-")

    code, message = _error(lambda: ec2.register_image(Name=rejected_name))
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    assert message == "Either imageLocation or rootDeviceName must be set.", (
        f"unexpected InvalidParameterCombination message {message!r}"
    )

    no_leak = ec2.describe_images(Owners=["self"], Filters=[{"Name": "name", "Values": [rejected_name]}])["Images"]
    assert no_leak == [], f"expected no image registered under the rejected name, found {no_leak}"

    accepted_name = ctx.unique_name("sim2real-regimg-ami-")
    image_id = ec2.register_image(
        Name=accepted_name,
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id}}],
    )["ImageId"]
    ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=image_id))

    registered = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    assert registered["Name"] == accepted_name, f"expected name {accepted_name!r}, got {registered['Name']!r}"


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
