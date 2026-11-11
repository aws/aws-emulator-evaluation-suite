"""op-contract-enableImageDeprecation."""
from __future__ import annotations

import datetime as dt
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-enableImageDeprecation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableImageDeprecation: sets a future deprecation time on an owned AMI + rejects a
    deprecation time in the past."""
    ec2 = ctx.client("ec2")
    image_id, _snap_id, _vol_id = _create_minimal_ami(ctx)
    ctx.on_cleanup(lambda: _disable_deprecation_ignore(ctx, image_id))

    deprecate_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=6)
    resp = ec2.enable_image_deprecation(ImageId=image_id, DeprecateAt=deprecate_at)
    assert resp["Return"] is True, f"expected Return=True, got {resp.get('Return')!r}"

    def _probe():
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
        return images[0].get("DeprecationTime") if images else None

    deprecation_time = _poll_until(
        _probe, lambda v: v is not None, timeout_s=30, interval_s=3,
        reason="describe_images never reported a DeprecationTime after enable_image_deprecation",
    )
    assert deprecation_time is not None, "DescribeImages never reported a DeprecationTime"

    # Error boundary: a DeprecateAt timestamp in the past is rejected, and the schedule set by the
    # positive control above is left untouched by the rejected call.
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    code, message = _client_error(lambda: ec2.enable_image_deprecation(ImageId=image_id, DeprecateAt=past))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected_message = "EnableImageDeprecation failed. Caused by specified deprecation time in the past"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = ec2.describe_images(ImageIds=[image_id])["Images"][0].get("DeprecationTime")
    assert unchanged == deprecation_time, (
        f"rejected past-DeprecateAt call altered the schedule: was {deprecation_time!r}, now {unchanged!r}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
    reason: str = "condition not met",
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise TimeoutError(f"timed out after {timeout_s}s waiting for: {reason} (last value: {value!r})")


def _disable_deprecation_ignore(ctx, image_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.disable_image_deprecation(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAMIID.NotFound":
            raise


def _deregister_image_ignore(ctx, image_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.deregister_image(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
        ):
            raise


def _create_minimal_ami(ctx) -> tuple[str, str, str]:
    """Register a minimal, owned EBS-backed AMI without launching an instance."""
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]

    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}]}
        ],
    )
    volume_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
        reason=f"volume {volume_id} never reached available",
    )

    snap = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}]}
        ],
    )
    snapshot_id = snap["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180,
        interval_s=5,
        reason=f"snapshot {snapshot_id} never completed",
    )

    ami_name = ctx.unique_name("sim2real-behav-ami-")
    image = ec2.register_image(
        Name=ami_name,
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        EnaSupport=True,
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id, "VolumeType": "gp3"}}],
        TagSpecifications=[{"ResourceType": "image", "Tags": [{"Key": "Name", "Value": ami_name}]}],
    )
    image_id = image["ImageId"]
    ctx.on_cleanup(lambda: _deregister_image_ignore(ctx, image_id))
    _poll_until(
        lambda: (ec2.describe_images(ImageIds=[image_id])["Images"] or [{}])[0].get("State"),
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
        reason=f"image {image_id} never reached available",
    )
    return image_id, snapshot_id, volume_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
