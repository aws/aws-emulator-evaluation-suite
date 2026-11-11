"""op-contract-attachImageWatermark."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-attachImageWatermark"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachImageWatermark stamps an owned, non-public AMI; a nonexistent AMI is rejected."""
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")

    # error boundary: image does not exist. Note: AttachImageWatermark validates AMI-ID format
    # more strictly than the "NotFound" family of EC2 APIs -- even a length-correct, mixed-hex
    # 17-char ID like "ami-0123456789abcdef0" comes back as "...Malformed" rather than
    # "...NotFound" here (confirmed against real AWS), so that is the code this rejection path
    # actually surfaces.
    code, code_message = _error_code(
        lambda: ec2.attach_image_watermark(ImageId="ami-0123456789abcdef0", WatermarkName="sim2real-wm")
    )
    assert code == "InvalidAMIID.Malformed", f"expected InvalidAMIID.Malformed, got {code}"
    expected_code_message = "The image ID 'ami-0123456789abcdef0' is malformed"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # success path: register a minimal owned AMI (via a blank volume snapshot) and watermark it
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    volume = ec2.create_volume(
        Size=1,
        AvailabilityZone=az,
        VolumeType="gp3",
        TagSpecifications=_tag_spec(ctx, "volume", ctx.unique_name("sim2real-wmvol-")),
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
    )

    snapshot = ec2.create_snapshot(
        VolumeId=volume,
        Description=ctx.unique_name("sim2real-snap-"),
        TagSpecifications=_tag_spec(ctx, "snapshot", ctx.unique_name("sim2real-wmsnap-")),
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180,
        interval_s=5,
    )

    image = ec2.register_image(
        Name=ctx.unique_name("sim2real-ami-"),
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot}}],
        VirtualizationType="hvm",
        EnaSupport=True,
        TagSpecifications=_tag_spec(ctx, "image", ctx.unique_name("sim2real-ami-")),
    )["ImageId"]
    ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=image))
    _poll_until(
        lambda: ec2.describe_images(ImageIds=[image])["Images"][0]["State"],
        lambda s: s == "available",
        timeout_s=120,
        interval_s=3,
    )

    account_id = sts.get_caller_identity()["Account"]
    expected_key = f"{account_id}:sim2real-wm"
    resp = ec2.attach_image_watermark(ImageId=image, WatermarkName="sim2real-wm")
    assert resp["WatermarkKey"] == expected_key, f"expected {expected_key!r}, got {resp['WatermarkKey']!r}"

    # terminal read: an independent DescribeImages call (not the mutating call's own
    # response) must show the watermark as durable image state.
    watermarks = _describe_watermarks(ec2, image)
    assert watermarks == [expected_key], f"expected [{expected_key!r}], got {watermarks!r}"

    detach_resp = ec2.detach_image_watermark(ImageId=image, WatermarkKey=expected_key)
    assert detach_resp["Return"] is True, f"expected Return=True removing an attached watermark, got {detach_resp}"

    watermarks_after = _describe_watermarks(ec2, image)
    assert watermarks_after == [], f"expected no watermarks after detach, got {watermarks_after!r}"


def _tag_spec(ctx, resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _describe_watermarks(ec2, image_id: str) -> list[str]:
    image = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    return [w["WatermarkKey"] for w in image.get("ImageWatermarks", [])]


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
