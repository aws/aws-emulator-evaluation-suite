"""op-contract-restore-image-from-recycle-bin."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-restore-image-from-recycle-bin"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A deregistered AMI retained by a matching Recycle Bin rule is restored by
    RestoreImageFromRecycleBin into a describable, available AMI again, while a
    syntactically malformed id is rejected with InvalidAMIID.Malformed."""
    ec2 = ctx.client("ec2")
    rbin = ctx.client("rbin")

    # The "...1234567890abcdef0" long-format id is the placeholder AWS's own docs/SDK
    # examples use for a syntactically valid resource id, but on real AWS it does not clear
    # RestoreImageFromRecycleBin's own id-format validator (distinct from, and stricter
    # than, the existence check): the service rejects it with InvalidAMIID.Malformed before
    # ever reaching the NotFound existence boundary.
    err = _error(
        lambda: ec2.restore_image_from_recycle_bin(ImageId="ami-1234567890abcdef0")
    )
    assert err["Code"] == "InvalidAMIID.Malformed", f"unexpected error code for unknown id: {err!r}"
    assert err.get("Message") == "The image ID 'ami-1234567890abcdef0' is malformed", (
        f"unexpected message: {err.get('Message')!r}"
    )

    tag_key = "sim2real-rbin"
    tag_value = ctx.unique_name("ami-")

    rule_id = rbin.create_rule(
        ResourceType="EC2_IMAGE",
        RetentionPeriod={"RetentionPeriodValue": 1, "RetentionPeriodUnit": "DAYS"},
        ResourceTags=[{"ResourceTagKey": tag_key, "ResourceTagValue": tag_value}],
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))

    if not _poll_until(
        lambda: rbin.get_rule(Identifier=rule_id)["Status"],
        lambda status: status == "available",
        timeout_s=120,
        interval_s=5,
    ):
        raise AssertionError(
            "unreachable: Recycle Bin retention rule never became available",
        )

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    volume_id = ec2.create_volume(Size=1, AvailabilityZone=az, VolumeType="gp3")["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    ec2.get_waiter("volume_available").wait(
        VolumeIds=[volume_id], WaiterConfig={"Delay": 1, "MaxAttempts": 120}
    )
    # A rule that reads "available" can still lag before it retains deregistrations, and an
    # AMI deregistered inside that lag is gone for good rather than binned. So the
    # register/deregister pair is retried with a fresh AMI (bounded) until one lands in the
    # bin; every attempt's AMI and snapshot stay registered for cleanup.
    def _make_image() -> str:
        snap_id = ec2.create_snapshot(VolumeId=volume_id)["SnapshotId"]
        ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
        ec2.get_waiter("snapshot_completed").wait(
            SnapshotIds=[snap_id], WaiterConfig={"Delay": 1, "MaxAttempts": 300}
        )
        ami = ec2.register_image(
            Name=ctx.unique_name("sim2real-ami-"),
            Architecture="x86_64",
            RootDeviceName="/dev/xvda",
            VirtualizationType="hvm",
            EnaSupport=True,
            BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
            TagSpecifications=[
                {"ResourceType": "image", "Tags": [{"Key": tag_key, "Value": tag_value}]}
            ],
        )["ImageId"]
        ctx.on_cleanup(lambda: _deregister_quiet(ec2, ami))
        ec2.get_waiter("image_available").wait(
            ImageIds=[ami], WaiterConfig={"Delay": 1, "MaxAttempts": 120}
        )
        return ami

    attempts: list[str] = []
    image_id = None
    deadline = time.monotonic() + 480
    while image_id is None and time.monotonic() < deadline:
        attempts.append(_make_image())
        ec2.deregister_image(ImageId=attempts[-1])
        image_id = _poll_until(
            lambda: _first_binned(ec2.list_images_in_recycle_bin, "Images", "ImageId", attempts),
            lambda found: bool(found),
            timeout_s=120,
            interval_s=5,
        ) or None
    if image_id is None:
        raise AssertionError(
            f"unreachable: none of the deregistered AMIs {attempts} appeared in Recycle Bin "
            "within the test window",
        )

    ec2.restore_image_from_recycle_bin(ImageId=image_id)

    def _restored() -> bool:
        try:
            resp = ec2.describe_images(ImageIds=[image_id])
        except Exception:
            return False
        images = resp.get("Images", [])
        return bool(images) and images[0]["State"] == "available"

    assert _poll_until(_restored, lambda ok: ok, timeout_s=90, interval_s=5), (
        "AMI was not visible/available again after RestoreImageFromRecycleBin"
    )


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = probe()
        except Exception:
            result = None
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result if predicate(result) else False


def _first_binned(list_fn, items_key, id_key, wanted):
    """Return the first id from ``wanted`` that the recycle bin lists, or None. The bin is
    listed unfiltered, so an id that was never binned cannot fail the whole read."""
    kwargs: dict = {}
    while True:
        page = list_fn(**kwargs)
        for entry in page.get(items_key, []):
            if entry[id_key] in wanted:
                return entry[id_key]
        if not page.get("NextToken"):
            return None
        kwargs["NextToken"] = page["NextToken"]


def _deregister_quiet(ec2, image_id):
    """Cleanup: deregister the AMI, tolerating one the check already deregistered."""
    from botocore.exceptions import ClientError

    try:
        ec2.deregister_image(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidAMIID.Unavailable", "InvalidAMIID.NotFound"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
