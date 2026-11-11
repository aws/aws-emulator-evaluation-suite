"""op-contract-disable-image-deregistration-protection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-image-deregistration-protection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableImageDeregistrationProtection lifts protection: while it is enabled DeregisterImage fails
    with OperationNotPermitted, after the disable returns disabled the deregister succeeds, and an
    unknown AMI fails with InvalidAMIID.NotFound (exact messages)."""
    ec2 = ctx.client("ec2")
    image_id = _create_test_ami(ctx, register_cleanup=False)

    enable_resp = ec2.enable_image_deregistration_protection(ImageId=image_id, WithCooldown=False)
    assert _indicates_state(enable_resp.get("Return"), "enabled"), (
        f"EnableImageDeregistrationProtection did not indicate an enabled state: {enable_resp}"
    )

    # Independent read at the destination, not the enable call's own response: confirm the
    # protection state has actually propagated before relying on it to block deregistration.
    protection = _poll_until(
        lambda: (ec2.describe_images(ImageIds=[image_id])["Images"] or [{}])[0].get(
            "DeregistrationProtection"
        ),
        lambda v: _indicates_state(v, "enabled"),
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert _indicates_state(protection, "enabled"), (
        f"expected DescribeImages to report protection enabled, got {protection!r}"
    )

    code, message = _client_error(lambda: ec2.deregister_image(ImageId=image_id))
    assert code == "OperationNotPermitted", (
        f"expected deregistration to be blocked while protected, got {code}"
    )
    expected_message = f"{image_id} can't be deregistered because deregistration protection is enabled-without-cooldown. Please disable protection and try again."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent via an independent read: the blocked attempt must not have deregistered
    # the image - it is still present, distinct from just trusting the error code above.
    still_registered = ec2.describe_images(ImageIds=[image_id])["Images"]
    assert still_registered and still_registered[0]["ImageId"] == image_id, (
        f"image should still be registered after a blocked deregister attempt, got {still_registered}"
    )

    # Disable once, not in a retry loop: a repeat call reports nothing left to change. Its Return value
    # is the resulting state as a string ("disabled"), and deregistration unblocks shortly after, so
    # the DeregisterImage effect is polled below.
    resp = ec2.disable_image_deregistration_protection(ImageId=image_id)
    assert resp.get("Return") == "disabled", f"unexpected disable response shape: {resp}"

    # The true behavioral effect: deregistration now succeeds, once the disable has
    # propagated. Poll (bounded) rather than sleep, retrying only the read-only/terminal
    # DeregisterImage call - never re-issuing DisableImageDeregistrationProtection itself.
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

    code, message = _client_error(
        lambda: ec2.disable_image_deregistration_protection(ImageId="ami-00000000deadbeef0")
    )
    assert code == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {code}"
    expected_message = "Invalid ImageId: ami-00000000deadbeef0"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _indicates_state(value, expected_prefix):
    """Real AWS models both the *DeregistrationProtection call's `Return` and the
    DescribeImages `DeregistrationProtection` field as a status string that may carry a
    cooldown qualifier (e.g. "enabled-without-cooldown") rather than a bare boolean or the
    exact word; accept any representation that unambiguously signals the expected state."""
    if isinstance(value, bool):
        return value if expected_prefix == "enabled" else not value
    if isinstance(value, str):
        return value.lower().startswith(expected_prefix)
    return False


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


def _create_test_ami(ctx, register_cleanup: bool = True) -> str:
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]

    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{
            "ResourceType": "volume",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}],
        }],
    )
    vol_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[vol_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snap = ec2.create_snapshot(
        VolumeId=vol_id,
        TagSpecifications=[{
            "ResourceType": "snapshot",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}],
        }],
    )
    snap_id = snap["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    image = ec2.register_image(
        Name=ctx.unique_name("sim2real-behav-ami-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        VirtualizationType="hvm",
        EnaSupport=True,
    )
    image_id = image["ImageId"]

    if register_cleanup:
        def _deregister():
            try:
                ec2.deregister_image(ImageId=image_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "InvalidAMIID.NotFound",
                    "InvalidAMIID.Unavailable",
                ):
                    raise

        ctx.on_cleanup(_deregister)
    else:
        # The test itself deregisters the image as part of the success path; if that
        # fails partway through, still make sure protection is lifted and the image is
        # cleaned up so it doesn't leak.
        def _force_cleanup():
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

        ctx.on_cleanup(_force_cleanup)

    ec2.get_waiter("image_available").wait(ImageIds=[image_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return image_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
