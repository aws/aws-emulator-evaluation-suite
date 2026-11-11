"""create-image-contract."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateImage(NoReboot=True) against a running instance produces an AMI
    that eventually reaches 'available' with the instance's block device
    mappings snapshotted, and rejects a non-existent instance id.
    """
    ec2 = ctx.client("ec2")
    instance_id = _run_tagged_instance(ctx)

    resp = ec2.create_image(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-behav-ami-"),
        NoReboot=True,
        TagSpecifications=[_tag_spec(ctx, "image")],
    )
    image_id = resp["ImageId"]

    def _snapshot_ids_from(described):
        return [
            m["Ebs"]["SnapshotId"]
            for m in described.get("BlockDeviceMappings", [])
            if "Ebs" in m and "SnapshotId" in m["Ebs"]
        ]

    # Immediately after CreateImage returns, the block device mappings (and
    # their snapshot IDs) may not yet be populated on DescribeImages; poll
    # for them to show up instead of asserting on the very first read.
    described = _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0],
        lambda d: _snapshot_ids_from(d) or d["State"] in ("available", "failed", "error"),
        timeout_s=60.0,
        interval_s=5.0,
    )
    snapshot_ids = _snapshot_ids_from(described)
    assert snapshot_ids, "expected CreateImage to snapshot at least the root EBS volume"

    def _cleanup_image():
        try:
            ec2.deregister_image(ImageId=image_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "InvalidAMIID.NotFound",
                "InvalidAMIID.Unavailable",
            ):
                raise
        for snapshot_id in snapshot_ids:
            try:
                ec2.delete_snapshot(SnapshotId=snapshot_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                    raise

    ctx.on_cleanup(_cleanup_image)

    assert described["State"] in ("pending", "available"), (
        f"expected the AMI to still be pending or available once snapshotted, got {described['State']!r}"
    )

    state = _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"],
        lambda s: s in ("available", "failed", "error"),
        timeout_s=240.0,
        interval_s=15.0,
    )
    if state not in ("available", "failed", "error"):
        raise AssertionError(
            f"AMI {image_id} did not reach a terminal state within the bound (last: {state!r})",
        )
    assert state == "available", f"AMI reached unexpected terminal state {state!r}"

    # Error boundary: a non-existent instance id must be rejected up front.
    missing_instance = "i-0123456789abcdef0"
    code, message = _client_error(
        lambda: ec2.create_image(InstanceId=missing_instance, Name=ctx.unique_name("sim2real-behav-ami-"))
    )
    assert code == "InvalidInstanceID.NotFound", f"expected InvalidInstanceID.NotFound, got {code!r}"
    expected_message = f"The instance ID '{missing_instance}' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call *fn*; return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI visible in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _run_tagged_instance(ctx):
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[_tag_spec(ctx, "instance")],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
