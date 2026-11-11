"""image-register-describe-deregister-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _get_az(ec2, instance_type="t3.micro"):
    """An available AZ that actually offers *instance_type* (falls back to any)."""
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    try:
        offerings = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        ).get("InstanceTypeOfferings", [])
        offered = {o["Location"] for o in offerings}
        for z in zones:
            if z in offered:
                return z
    except Exception:
        pass
    return zones[0]


def _wait_volume_state(ec2, volume_id, state, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidVolume.NotFound":
                last = "__not_yet_visible__"
                time.sleep(2)
                continue
            raise
        if last == state:
            return last
        time.sleep(2)
    raise AssertionError(f"volume {volume_id} did not reach {state!r} within {timeout_s}s (last {last!r})")


def _wait_snapshot_completed(ec2, snapshot_id, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSnapshot.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        if last == "completed":
            return last
        time.sleep(3)
    raise AssertionError(f"snapshot {snapshot_id} did not complete within {timeout_s}s (last {last!r})")


def _cleanup_volume(ec2, volume_id):
    """Best-effort teardown: force-detach, wait available, delete."""
    try:
        ec2.detach_volume(VolumeId=volume_id, Force=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "InvalidVolume.NotFound"
            and not (err["Code"] == "IncorrectState" and "is in the 'available' state" in err.get("Message", ""))
        ):
            raise
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
                raise
            return
        if state == "available":
            break
        time.sleep(2)
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


def _deregister_image(ec2, image_id):
    """Teardown: the body deregisters the image itself; a deregistered id answers
    InvalidAMIID.Unavailable (or InvalidAMIID.NotFound once purged), which is done."""
    try:
        ec2.deregister_image(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"):
            raise

CHECK = "image-register-describe-deregister-lifecycle"
GROUP = 'ami'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterImage from a snapshot -> DescribeImages(available) -> DeregisterImage removes it."""
    ec2 = ctx.client("ec2")
    az = _get_az(ec2)
    volume_id = ec2.create_volume(AvailabilityZone=az, Size=1, TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["VolumeId"]
    ctx.on_cleanup(lambda: _cleanup_volume(ec2, volume_id))
    _wait_volume_state(ec2, volume_id, "available")
    snapshot_id = ec2.create_snapshot(VolumeId=volume_id, Description="behavioral check snapshot", TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _wait_snapshot_completed(ec2, snapshot_id)

    name = ctx.unique_name("sim2real-behav-ami-")
    resp = ec2.register_image(
        Name=name,
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id}}],
        TagSpecifications=[{"ResourceType": "image", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    image_id = resp["ImageId"]
    ctx.on_cleanup(lambda: _deregister_image(ec2, image_id))

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"] == "available":
            break
        time.sleep(3)
    image = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    assert image["Name"] == name, f"expected registered image name {name!r}, got {image['Name']!r}"
    assert image["Architecture"] == "x86_64", (
        f"expected Architecture 'x86_64', got {image['Architecture']!r}"
    )
    assert image["RootDeviceName"] == "/dev/xvda", (
        f"expected RootDeviceName '/dev/xvda', got {image['RootDeviceName']!r}"
    )
    assert image["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"] == snapshot_id, (
        f"expected root device snapshot {snapshot_id!r}, got "
        f"{image['BlockDeviceMappings'][0]['Ebs'].get('SnapshotId')!r}"
    )

    ec2.deregister_image(ImageId=image_id)

    # DeregisterImage is eventually consistent: the AMI can still resolve for a
    # short window afterwards, so poll a read until it no longer lists. Once the
    # AMI is purged the read refuses the id as not found, which is gone too.
    def lookup():
        try:
            images = ec2.describe_images(ImageIds=[image_id]).get("Images", [])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "InvalidAMIID.NotFound":
                return []
            return (err.get("Code"), err.get("Message"))
        return [image.get("State") for image in images]

    deadline = time.monotonic() + 40
    while True:
        final = lookup()
        if final == [] or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert final == [], f"expected DescribeImages to list no deregistered image, got {final!r}"

    # a mutation on the now-dead id also fails, not just a read
    try:
        ec2.deregister_image(ImageId=image_id)
        mutate_code = mutate_message = None
    except ClientError as exc:
        mutate_code = exc.response.get("Error", {}).get("Code")
        mutate_message = exc.response.get("Error", {}).get("Message")
    assert mutate_code == "InvalidAMIID.Unavailable", (
        f"expected a second DeregisterImage on the deregistered id to be refused, got {mutate_code!r}"
    )
    unavailable = f"The image ID '{image_id}' is no longer available"
    assert mutate_message == unavailable, mutate_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
