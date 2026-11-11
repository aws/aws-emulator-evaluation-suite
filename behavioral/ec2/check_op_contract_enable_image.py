"""op-contract-enableImage."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-enableImage"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableImage: disable/enable round-trip on an owned AMI + NotFound error boundary."""
    ec2 = ctx.client("ec2")
    image_id, _snap_id, _vol_id = _create_minimal_ami(ctx)

    disable_resp = ec2.disable_image(ImageId=image_id)
    assert disable_resp["Return"] is True, f"expected DisableImage Return=True, got {disable_resp.get('Return')!r}"
    _wait_image_state(ctx, image_id, "disabled")

    enable_resp = ec2.enable_image(ImageId=image_id)
    assert enable_resp["Return"] is True, f"expected EnableImage Return=True, got {enable_resp.get('Return')!r}"
    _wait_image_state(ctx, image_id, "available")

    # Error boundary: enabling the all-zero placeholder AMI id. Real AWS rejects it at id
    # validation as InvalidAMIID.Malformed, before any image lookup.
    missing_image_id = "ami-00000000000000000"
    code, message = _client_error(lambda: ec2.enable_image(ImageId=missing_image_id))
    assert code == "InvalidAMIID.Malformed", f"expected InvalidAMIID.Malformed, got {code}"
    expected_message = f"The image ID '{missing_image_id}' is malformed"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _wait_image_state(ctx, image_id: str, expected: str) -> None:
    ec2 = ctx.client("ec2")

    def _probe():
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
        return images[0]["State"] if images else None

    state = _poll_until(_probe, lambda s: s == expected, timeout_s=60, interval_s=3)
    assert state == expected, f"expected image state {expected!r}, got {state!r}"


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
    )

    image = ec2.register_image(
        Name=ctx.unique_name("sim2real-behav-ami-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        EnaSupport=True,
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot_id, "VolumeType": "gp3"}}],
    )
    image_id = image["ImageId"]
    ctx.on_cleanup(lambda: _deregister_image_ignore(ctx, image_id))
    _wait_image_state(ctx, image_id, "available")
    return image_id, snapshot_id, volume_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
