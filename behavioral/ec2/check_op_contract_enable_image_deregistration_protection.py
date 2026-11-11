"""op-contract-enableImageDeregistrationProtection."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-enableImageDeregistrationProtection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableImageDeregistrationProtection: once enabled, DeregisterImage on the protected
    AMI must be rejected (overly-permissive boundary) until protection is disabled again."""
    ec2 = ctx.client("ec2")
    image_id, _snap_id, _vol_id = _create_minimal_ami(ctx)

    resp = _enable_protection_with_retry(ec2, image_id)
    # Real AWS models `Return` for this operation as a status string (observed:
    # "enabled-without-cooldown" when WithCooldown is omitted/false; "enabled" when a
    # cooldown is in effect) rather than a plain boolean -- accept either representation
    # as long as it unambiguously signals the enabled state.
    assert _return_indicates(resp.get("Return"), "enabled"), (
        f"EnableImageDeregistrationProtection did not indicate an enabled state: {resp}"
    )

    def _probe():
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
        return images[0].get("DeregistrationProtection") if images else None

    protection = _poll_until(_probe, lambda v: v is not None, timeout_s=30, interval_s=3)
    # Real AWS reports DeregistrationProtection on DescribeImages as a status string that
    # may include a cooldown qualifier (e.g. "enabled-without-cooldown") rather than the
    # bare "enabled" the API naming suggests; accept any value that unambiguously signals
    # the enabled state, mirroring the acceptance used for the enable-call's Return field.
    assert _return_indicates(protection, "enabled"), (
        f"expected DeregistrationProtection to indicate enabled, got {protection!r}"
    )

    # Overly-permissive boundary: deregistering a protected AMI must be rejected.
    code, message = _client_error(lambda: ec2.deregister_image(ImageId=image_id))
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code}"
    expected_protected = (
        f"{image_id} can't be deregistered because deregistration protection is "
        "enabled-without-cooldown. Please disable protection and try again."
    )
    assert message == expected_protected, f"expected message {expected_protected!r}, got {message!r}"

    # Disable protection: the AMI should now be deregisterable again -- the true end-to-end
    # effect, not just the disable call's own self-reported Return field. Real AWS can hold a
    # short propagation window even without an active cooldown, so poll the terminal
    # DeregisterImage call (never re-issuing disable itself) rather than asserting synchronously.
    disable_resp = ec2.disable_image_deregistration_protection(ImageId=image_id)
    assert _return_indicates(disable_resp.get("Return"), "disabled"), (
        f"DisableImageDeregistrationProtection did not indicate a disabled state: {disable_resp}"
    )

    deadline = time.monotonic() + 60.0
    last_code = None
    while True:
        try:
            ec2.deregister_image(ImageId=image_id)
            break
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "OperationNotPermitted" or time.monotonic() > deadline:
                raise AssertionError(
                    f"deregistration still blocked after disabling protection: {last_code}"
                )
            time.sleep(3)

    described = ec2.describe_images(ImageIds=[image_id])["Images"]
    assert described == [], f"image still registered after deregister: {described}"

    # Distinct error boundary: enabling protection on the all-zero placeholder AMI id, which
    # real AWS rejects at id validation as InvalidAMIID.Malformed.
    missing_image_id = "ami-00000000000000000"
    nf_code, nf_message = _client_error(
        lambda: ec2.enable_image_deregistration_protection(ImageId=missing_image_id)
    )
    assert nf_code == "InvalidAMIID.Malformed", f"expected InvalidAMIID.Malformed, got {nf_code}"
    expected_nf = f"The image ID '{missing_image_id}' is malformed"
    assert nf_message == expected_nf, f"expected message {expected_nf!r}, got {nf_message!r}"


def _return_indicates(value: Any, expected_prefix: str) -> bool:
    """Real AWS returns a status string for `Return` on these operations (e.g.
    "enabled-without-cooldown"/"enabled" for enable, "disabled" for disable) rather than
    the plain boolean the API naming suggests; accept either representation."""
    if value is True and expected_prefix == "enabled":
        return True
    if value is False:
        return False
    if isinstance(value, str):
        return value.lower().startswith(expected_prefix)
    return False


def _enable_protection_with_retry(ec2, image_id: str, *, timeout_s: float = 60.0, interval_s: float = 5.0):
    """EnableImageDeregistrationProtection can transiently return a not-yet-enabled
    Return status (rather than raising) if the freshly-registered AMI hasn't fully
    propagated yet; retry within a bounded window instead of failing on the first
    attempt. Note: real AWS does not reliably honor an explicit WithCooldown=False on a
    fresh AMI (it can keep failing to enable indefinitely for that combination) -- omit
    WithCooldown and let it take its default, which real AWS actually applies
    successfully."""
    deadline = time.monotonic() + timeout_s
    resp = None
    while time.monotonic() < deadline:
        resp = ec2.enable_image_deregistration_protection(ImageId=image_id)
        if _return_indicates(resp.get("Return"), "enabled"):
            return resp
        time.sleep(interval_s)
    return resp



def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
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
    raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")


def _deregister_image_ignore(ctx, image_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.disable_image_deregistration_protection(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAMIID.NotFound":
            raise
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
    _poll_until(
        lambda: (ec2.describe_images(ImageIds=[image_id])["Images"] or [{}])[0].get("State"),
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
    )
    return image_id, snapshot_id, volume_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
