"""op-contract-enableFastLaunch."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-enableFastLaunch"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableFastLaunch with DryRun on an owned Linux AMI answers DryRunOperation; the real call fails
    with InvalidRequest and leaves no fast-launch record, and a nonexistent AMI also fails with
    InvalidRequest (exact messages)."""
    ec2 = ctx.client("ec2")
    image_id, _snap_id, _vol_id, _az = _create_minimal_ami(ctx)

    # Positive control: DryRun exercises the IAM-permission path without depending on the
    # Windows-only validation this check exists to probe.
    dry_code, dry_message = _client_error(lambda: ec2.enable_fast_launch(ImageId=image_id, DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    expected_dry = "Request would have succeeded, but DryRun flag is set."
    assert dry_message == expected_dry, f"expected message {expected_dry!r}, got {dry_message!r}"

    # Rejection boundary: EnableFastLaunch only supports Windows AMIs; our minimal AMI has
    # no Platform set (i.e. it's treated as Linux/UNIX), so this must be rejected.
    code, message = _client_error(lambda: ec2.enable_fast_launch(ImageId=image_id))
    assert code == "InvalidRequest", f"expected InvalidRequest for a non-Windows AMI, got {code}"
    expected_linux = (
        "Can't enable EC2 Fast Launch. EC2 Fast Launch is only available for the Windows "
        "operating system platform."
    )
    assert message == expected_linux, f"expected message {expected_linux!r}, got {message!r}"

    # Effect-absent: the rejected call must not have enabled fast launch on our AMI --
    # confirmed via an independent read (DescribeFastLaunchImages), not the mutating call's
    # own response.
    fli = ec2.describe_fast_launch_images(ImageIds=[image_id])["FastLaunchImages"]
    assert fli == [], f"EnableFastLaunch was rejected but fast launch appears enabled: {fli}"

    # Rejection boundary: enabling fast launch on the all-zero placeholder AMI id must also
    # fail -- real AWS rejects it as InvalidRequest, naming the image id as not valid.
    missing_image_id = "ami-00000000000000000"
    nf_code, nf_message = _client_error(lambda: ec2.enable_fast_launch(ImageId=missing_image_id))
    assert nf_code == "InvalidRequest", f"expected InvalidRequest, got {nf_code}"
    expected_nf = f"Can't enable EC2 Fast Launch. Image ID: {missing_image_id} is not valid."
    assert nf_message == expected_nf, f"expected message {expected_nf!r}, got {nf_message!r}"


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


def _wait_volume_available(ctx, volume_id: str) -> None:
    ec2 = ctx.client("ec2")

    def _probe():
        return ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]

    state = _poll_until(_probe, lambda s: s == "available", timeout_s=60, interval_s=3)
    assert state == "available", f"volume never became available: {state}"


def _wait_snapshot_completed(ctx, snapshot_id: str) -> None:
    ec2 = ctx.client("ec2")

    def _probe():
        return ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]

    state = _poll_until(_probe, lambda s: s == "completed", timeout_s=120, interval_s=4)
    assert state == "completed", f"snapshot never completed: {state}"


def _wait_image_available(ctx, image_id: str) -> None:
    ec2 = ctx.client("ec2")

    def _probe():
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
        return images[0]["State"] if images else "pending"

    state = _poll_until(_probe, lambda s: s in ("available", "invalid", "failed"), timeout_s=60, interval_s=3)
    assert state == "available", f"image never became available: {state}"


def _create_minimal_ami(ctx) -> tuple[str, str, str, str]:
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
    _wait_volume_available(ctx, volume_id)

    snap = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}]}
        ],
    )
    snapshot_id = snap["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _wait_snapshot_completed(ctx, snapshot_id)

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
    _wait_image_available(ctx, image_id)
    return image_id, snapshot_id, volume_id, az


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
