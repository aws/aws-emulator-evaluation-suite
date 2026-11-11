"""op-contract-register-image."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-register-image"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterImage creates an AMI from an EBS snapshot with the given name, root device, mapping
    and architecture; a nonexistent snapshot is rejected with InvalidSnapshotID.NotFound and no
    image is created."""
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]

    volume = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}],
            }
        ],
    )
    volume_id = volume["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    assert _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"] == "available",
        timeout_s=60,
        interval_s=3,
    ), "volume never became available"

    snapshot = ec2.create_snapshot(
        VolumeId=volume_id, Description=ctx.unique_name("sim2real-behav-snap-")
    )
    snapshot_id = snapshot["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    assert _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]
        == "completed",
        timeout_s=180,
        interval_s=5,
    ), "snapshot never completed"

    image_name = ctx.unique_name("sim2real-behav-ami-")
    registered = ec2.register_image(
        Name=image_name,
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        EnaSupport=True,
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id}}],
    )
    image_id = registered["ImageId"]
    ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=image_id))

    described = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    assert described["Name"] == image_name, f"expected image name {image_name!r}, got {described['Name']!r}"
    assert described["RootDeviceName"] == "/dev/xvda", (
        f"expected root device /dev/xvda, got {described['RootDeviceName']!r}"
    )
    assert described["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"] == snapshot_id, (
        f"expected block device snapshot {snapshot_id!r}, "
        f"got {described['BlockDeviceMappings'][0]['Ebs'].get('SnapshotId')!r}"
    )
    assert described["Architecture"] == "x86_64", f"expected architecture x86_64, got {described['Architecture']!r}"

    bad_image_name = ctx.unique_name("sim2real-behav-ami-bad-")
    err, err_message = _client_error(
        ctx,
        ec2,
        lambda: ec2.register_image(
            Name=bad_image_name,
            Architecture="x86_64",
            RootDeviceName="/dev/xvda",
            VirtualizationType="hvm",
            BlockDeviceMappings=[
                {"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": "snap-00000000000000000"}}
            ],
        ),
    )
    assert err == "InvalidSnapshotID.NotFound", f"expected InvalidSnapshotID.NotFound, got {err}"
    expected_message = "The snapshot ID 'snap-00000000000000000' does not exist"
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"

    leftover = ec2.describe_images(Owners=["self"], Filters=[{"Name": "name", "Values": [bad_image_name]}])[
        "Images"
    ]
    assert not leftover, f"expected no image registered under the rejected name, found {leftover}"


def _poll_until(probe, *, timeout_s=60.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _client_error(ctx, ec2, fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    leaked_id = result.get("ImageId")
    if leaked_id:
        ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=leaked_id))
    raise AssertionError(
        f"expected RegisterImage against a nonexistent snapshot to be rejected, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
