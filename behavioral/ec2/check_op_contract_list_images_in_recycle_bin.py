"""op-contract-list-images-in-recycle-bin."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-list-images-in-recycle-bin"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deregistered, tag-matched AMI lands in ListImagesInRecycleBin and can be restored."""
    ec2 = ctx.client("ec2")
    rbin = ctx.client("rbin")
    tag_key = "sim2real-rbin-marker"
    tag_value = ctx.unique_name("ami-")
    az = _first_available_az(ctx)

    rule = rbin.create_rule(
        Description="sim2real behavioral check retention rule (AMIs)",
        ResourceType="EC2_IMAGE",
        RetentionPeriod={"RetentionPeriodValue": 1, "RetentionPeriodUnit": "DAYS"},
        ResourceTags=[{"ResourceTagKey": tag_key, "ResourceTagValue": tag_value}],
    )
    rule_id = rule["Identifier"]
    volume_id = ec2.create_volume(AvailabilityZone=az, Size=1, VolumeType="gp3")["VolumeId"]
    state = {"rule_id": rule_id, "volume_id": volume_id, "snapshot_id": None, "image_id": None}
    ctx.on_cleanup(lambda: _final_cleanup(ec2, rbin, state))

    # A freshly created Recycle Bin rule starts out "pending" and only applies to resources
    # deleted/deregistered once it becomes "available" — deregistering before then bypasses the
    # bin entirely (the AMI is purged for good, so it never shows up in ListImagesInRecycleBin).
    _poll_until(
        lambda: rbin.get_rule(Identifier=rule_id)["Status"],
        lambda s: s == "available",
        timeout_s=60.0,
        interval_s=3.0,
    )

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    snapshot_id = ec2.create_snapshot(VolumeId=volume_id, Description="sim2real-rbin-ami-src")[
        "SnapshotId"
    ]
    state["snapshot_id"] = snapshot_id
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180.0,
        interval_s=5.0,
    )

    image_name = ctx.unique_name("sim2real-rbin-ami-")
    image_id = ec2.register_image(
        Name=image_name,
        Description="sim2real-rbin-image-contract",
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        EnaSupport=True,
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id}}],
    )["ImageId"]
    state["image_id"] = image_id
    ec2.create_tags(Resources=[image_id], Tags=[{"Key": tag_key, "Value": tag_value}])

    # --- error boundary: DryRun must reject before listing anything ---
    code, message = _error(lambda: ec2.list_images_in_recycle_bin(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", f"unexpected DryRunOperation message {message!r}"

    # deregistering a tag-matched AMI sends it to the Recycle Bin instead of purging it
    ec2.deregister_image(ImageId=image_id)

    entry = _poll_until(
        lambda: _find_image_in_bin(ec2, image_id),
        lambda e: e is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert entry["ImageId"] == image_id, f"expected {image_id!r} in bin entry, got {entry['ImageId']!r}"
    assert entry["Name"] == image_name, f"expected name {image_name!r}, got {entry['Name']!r}"
    assert "RecycleBinEnterTime" in entry, f"expected RecycleBinEnterTime in entry, got keys {sorted(entry)}"
    assert "RecycleBinExitTime" in entry, f"expected RecycleBinExitTime in entry, got keys {sorted(entry)}"

    # a deregistered AMI is not describable as a normal image while in the bin
    described = ec2.describe_images(ImageIds=[image_id], Owners=["self"])["Images"]
    assert described == [], "deregistered/recycled AMI should not appear in DescribeImages"

    ec2.restore_image_from_recycle_bin(ImageId=image_id)
    _poll_until(
        lambda: len(ec2.describe_images(ImageIds=[image_id])["Images"]) == 1,
        lambda ok: ok,
        timeout_s=60.0,
    )
    assert _find_image_in_bin(ec2, image_id) is None, (
        "AMI still listed in Recycle Bin after restore"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator answering a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _first_available_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not azs:
        raise AssertionError("no available Availability Zones found")
    return azs[0]["ZoneName"]


def _find_image_in_bin(ec2, image_id: str):
    from botocore.exceptions import ClientError

    try:
        resp = ec2.list_images_in_recycle_bin(ImageIds=[image_id])
    except ClientError as e:
        # Right after deregistration the image may not have landed in the bin yet; AWS
        # rejects an ImageIds filter for an id it doesn't (yet) recognize as bin-resident
        # instead of returning an empty list — treat that the same as "not there yet".
        if e.response["Error"]["Code"] in {
            "InvalidAMIID.NotFound",
            "ImageNotInRecycleBin",
        }:
            return None
        raise
    items = resp.get("Images", [])
    return items[0] if items else None


def _final_cleanup(ec2, rbin, state: dict) -> None:
    try:
        rbin.delete_rule(Identifier=state["rule_id"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    image_id = state.get("image_id")
    if image_id:
        try:
            ec2.restore_image_from_recycle_bin(ImageId=image_id)
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] != "InvalidAMIID.NotFound"
                and not (err["Code"] == "InvalidRequest" and "is no longer in the Recycle Bin" in err.get("Message", ""))
            ):
                raise
        _delete_or_gone(
            lambda: ec2.deregister_image(ImageId=image_id),
            ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"),
            (),
        )
    snapshot_id = state.get("snapshot_id")
    if snapshot_id:
        _delete_or_gone(
            lambda: ec2.delete_snapshot(SnapshotId=snapshot_id),
            ("InvalidSnapshot.NotFound",),
            ("InvalidSnapshot.InUse", "IncorrectState"),
        )
    volume_id = state.get("volume_id")
    if volume_id:
        _delete_or_gone(
            lambda: ec2.delete_volume(VolumeId=volume_id),
            ("InvalidVolume.NotFound",),
            ("VolumeInUse", "IncorrectState"),
        )


def _delete_or_gone(fn, gone, busy, timeout_s=60.0):
    """Teardown delete: done on a not-found code in gone; a code in busy (still releasing) is
    retried every 2 s up to timeout_s; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
