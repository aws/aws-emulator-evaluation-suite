"""snapshot-in-use-by-registered-image-delete-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-in-use-by-registered-image-delete-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

ERR_SNAPSHOT_IN_USE = 'InvalidSnapshot.InUse'
ERR_SNAPSHOT_NOT_FOUND = 'InvalidSnapshot.NotFound'
ERR_AMI_MALFORMED = 'InvalidAMIID.Malformed'
ROOT_DEVICE = '/dev/xvda'


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _an_az(ec2):
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    return zones[0]


def _wait_volume_state(ec2, volume_id, state, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                last = "__not_yet_visible__"
                time.sleep(2)
                continue
            raise
        if last == state:
            return
        time.sleep(2)
    raise AssertionError(f"volume {volume_id} never reached {state!r} in {timeout_s}s (last {last!r})")


def _snapshot(ec2, snapshot_id):
    return ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]


def _wait_snapshot_completed(ec2, snapshot_id, timeout_s=900):
    """CreateSnapshot is async: pending -> completed (or error). A snapshot cannot back an AMI
    until it completes, so this must be a real poll, not a sleep."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            snap = _snapshot(ec2, snapshot_id)
        except ClientError as exc:
            if _code(exc) == ERR_SNAPSHOT_NOT_FOUND:
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        last = snap["State"]
        if last == "completed":
            return snap
        assert last != "error", f"snapshot {snapshot_id} entered state 'error': {snap}"
        time.sleep(5)
    raise AssertionError(f"snapshot {snapshot_id} never completed in {timeout_s}s (last {last!r})")


def _delete_volume(ec2, volume_id):
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


def _deregister_image(ec2, image_id):
    try:
        ec2.deregister_image(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
        ):
            raise


def _delete_snapshot(ec2, snapshot_id):
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSnapshot on a snapshot backing a registered AMI fails InvalidSnapshot.InUse and the
    snapshot survives; after deregistration the delete succeeds. A volume restored from the
    snapshot reports its SnapshotId and size, and outlives the snapshot.
    """
    ec2 = ctx.client("ec2")
    az = _an_az(ec2)
    tag = [{"Key": "sim2real", "Value": "1"}]

    # --- setup: volume -> completed snapshot ---
    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=1, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": tag}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, volume_id))
    _wait_volume_state(ec2, volume_id, "available")

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id, Description="sim2real snapshot in-use check",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": tag}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, snapshot_id))
    snap = _wait_snapshot_completed(ec2, snapshot_id)
    assert snap["VolumeId"] == volume_id, (
        f"the snapshot must record its source volume {volume_id}, got {snap.get('VolumeId')!r}"
    )
    assert snap["VolumeSize"] == 1, f"expected VolumeSize 1, got {snap['VolumeSize']}"
    assert snap.get("Progress") == "100%", (
        f"a completed snapshot must report Progress 100%, got {snap.get('Progress')!r}"
    )

    # --- the snapshot restores into a new volume that remembers where it came from ---
    restored_id = ec2.create_volume(
        AvailabilityZone=az, SnapshotId=snapshot_id,
        TagSpecifications=[{"ResourceType": "volume", "Tags": tag}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, restored_id))
    _wait_volume_state(ec2, restored_id, "available")
    restored = ec2.describe_volumes(VolumeIds=[restored_id])["Volumes"][0]
    assert restored["SnapshotId"] == snapshot_id, (
        f"a restored volume must report SnapshotId {snapshot_id}, got {restored.get('SnapshotId')!r}"
    )
    assert restored["Size"] == 1, (
        f"a restored volume must inherit the snapshot's 1GiB size, got {restored['Size']}"
    )

    # --- register an AMI backed by that snapshot: now the snapshot is REFERENCED ---
    image_id = ec2.register_image(
        Name=ctx.unique_name("sim2real-behav-ami-"),
        Description="sim2real image backed by a test snapshot",
        Architecture="x86_64",
        RootDeviceName=ROOT_DEVICE,
        VirtualizationType="hvm",
        EnaSupport=True,
        BlockDeviceMappings=[
            {"DeviceName": ROOT_DEVICE, "Ebs": {"SnapshotId": snapshot_id, "DeleteOnTermination": True}}
        ],
    )["ImageId"]
    ctx.on_cleanup(lambda: _deregister_image(ec2, image_id))
    assert image_id.startswith("ami-"), f"RegisterImage must mint an ami- id, got {image_id!r}"

    image = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    assert image["RootDeviceName"] == ROOT_DEVICE, (
        f"expected RootDeviceName {ROOT_DEVICE}, got {image.get('RootDeviceName')!r}"
    )
    assert image["RootDeviceType"] == "ebs", (
        f"a snapshot-backed image must be RootDeviceType 'ebs', got {image.get('RootDeviceType')!r}"
    )
    mapped = [
        m for m in image.get("BlockDeviceMappings", [])
        if m.get("Ebs", {}).get("SnapshotId") == snapshot_id
    ]
    assert mapped, (
        f"the image's BlockDeviceMappings must reference {snapshot_id}, got {image.get('BlockDeviceMappings')}"
    )

    # --- break exactly one thing: delete the snapshot the image depends on ---
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        assert _code(exc) == ERR_SNAPSHOT_IN_USE, (
            f"expected {ERR_SNAPSHOT_IN_USE} deleting a snapshot backing AMI {image_id}, got {_code(exc)}"
        )
        msg = exc.response.get("Error", {}).get("Message", "")
        assert msg == f"The snapshot {snapshot_id} is currently in use by {image_id}", (
            f"the rejection must name the referencing image {image_id}, message was {msg!r}"
        )
    else:
        raise AssertionError(
            f"DeleteSnapshot on {snapshot_id} must be rejected while AMI {image_id} references it "
            "— allowing it produces a registered but unlaunchable image"
        )

    # effect absent: the snapshot is still there and still complete
    survivor = _snapshot(ec2, snapshot_id)
    assert survivor["State"] == "completed", (
        f"the rejected delete must leave the snapshot completed, got {survivor['State']!r}"
    )
    # and the image still resolves its backing snapshot
    assert [
        m for m in ec2.describe_images(ImageIds=[image_id])["Images"][0]["BlockDeviceMappings"]
        if m.get("Ebs", {}).get("SnapshotId") == snapshot_id
    ], "the rejected delete must leave the image's snapshot reference intact"

    # --- control: drop the reference, and the very same delete now succeeds ---
    ec2.deregister_image(ImageId=image_id)
    # A deregistered image id is NOT InvalidAMIID.NotFound: DescribeImages answers with an empty
    # Images list, immediately and durably. NotFound is reserved for an id that never existed.
    gone = ec2.describe_images(ImageIds=[image_id])
    assert gone.get("Images", []) == [], (
        f"deregistered image {image_id} is still returned by DescribeImages: {gone['Images']}"
    )
    self_owned = {
        i["ImageId"]
        for page in ec2.get_paginator("describe_images").paginate(Owners=["self"])
        for i in page.get("Images", [])
    }
    assert image_id not in self_owned, (
        f"deregistered image {image_id} still appears in the account's own image list"
    )
    # Control for that empty list: an id DescribeImages cannot parse is refused outright.
    # NotFound is not asserted: EC2 ids carry a checksum, so a synthesised id is usually Malformed.
    unparseable = "ami-not-a-valid-image-id"
    try:
        ec2.describe_images(ImageIds=[unparseable])
    except ClientError as exc:
        assert _code(exc) == ERR_AMI_MALFORMED, (
            f"expected {ERR_AMI_MALFORMED} for the unparseable id {unparseable!r}, got "
            f"{_code(exc)}"
        )
        msg = exc.response.get("Error", {}).get("Message", "")
        assert msg == f'Invalid id: "{unparseable}"', msg
    else:
        raise AssertionError(
            f"DescribeImages returned 200 for {unparseable!r}; if an unparseable id also "
            f"produces an empty page then the empty page proves nothing about the deregistered "
            f"image {image_id}"
        )

    ec2.delete_snapshot(SnapshotId=snapshot_id)
    try:
        _snapshot(ec2, snapshot_id)
    except ClientError as exc:
        assert _code(exc) == ERR_SNAPSHOT_NOT_FOUND, (
            f"expected {ERR_SNAPSHOT_NOT_FOUND} after deleting {snapshot_id}, got {_code(exc)}"
        )
        msg = exc.response.get("Error", {}).get("Message", "")
        assert msg == f"The snapshot '{snapshot_id}' does not exist.", msg
    else:
        raise AssertionError(f"deleted snapshot {snapshot_id} is still describable")

    # the restored volume outlives its source snapshot: deleting a snapshot must not cascade
    assert ec2.describe_volumes(VolumeIds=[restored_id])["Volumes"][0]["State"] == "available", (
        "deleting the snapshot must NOT delete or degrade the volume restored from it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
