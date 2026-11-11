"""op-contract-describe-image-attribute."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-image-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeImageAttribute returns description and bootMode for a caller-owned AMI and rejects
    the deprecated blockDeviceMapping attribute with AuthFailure, as documented."""
    ec2 = ctx.client("ec2")
    # These attributes are only describable on an image the caller owns; an Amazon public AMI
    # is rejected with AuthFailure, so the check creates its own.
    ami_id = _create_owned_ami(ctx)

    desc = ec2.describe_image_attribute(ImageId=ami_id, Attribute="description")
    assert desc["ImageId"] == ami_id, f"expected ImageId {ami_id}, got {desc.get('ImageId')}"
    assert "Description" in desc, f"expected a Description container in the response, got keys {list(desc)}"  # {'Value': ...} - may legitimately be absent/None

    boot_mode = ec2.describe_image_attribute(ImageId=ami_id, Attribute="bootMode")
    assert boot_mode["ImageId"] == ami_id, f"expected ImageId {ami_id}, got {boot_mode.get('ImageId')}"
    assert "BootMode" in boot_mode, f"expected a BootMode container in the response, got keys {list(boot_mode)}"

    # blockDeviceMapping is documented to always fail with AuthFailure, even for an owned image.
    code, message = _error(lambda: ec2.describe_image_attribute(ImageId=ami_id, Attribute="blockDeviceMapping"))
    assert code == "AuthFailure", f"expected AuthFailure for the deprecated attribute, got {code}"
    expected = "Unauthorized attempt to access restricted resource"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _find_al2023_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise AssertionError("no amazon-owned al2023 AMI visible in this account/region")
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    return images[0]["ImageId"]


def _default_subnet_id(ec2, *, ctx) -> str:
    # Without a SubnetId, a missing default VPC surfaces as an opaque VPCIdNotSpecified, so the
    # subnet is resolved explicitly to fail with a named precondition.
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("account has no shared network VPC/subnet to launch the instance in")
    return subnets[0]["SubnetId"]


def _launch_instance(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    kwargs: dict[str, Any] = dict(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=_default_subnet_id(ec2, ctx=ctx),
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ec2-")}],
            }
        ],
    )
    try:
        resp = ec2.run_instances(**kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("VPCIdNotSpecified", "MissingInput"):
            raise AssertionError(f"cannot launch instance: {code}")
        raise

    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


def _create_owned_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    base_ami_id = _find_al2023_ami(ctx)
    instance_id = _launch_instance(ctx, base_ami_id)

    image_name = ctx.unique_name("sim2real-image-")
    created = ec2.create_image(InstanceId=instance_id, Name=image_name, NoReboot=True)
    image_id = created["ImageId"]

    def _cleanup_image():
        snapshot_ids = [
            bdm["Ebs"]["SnapshotId"]
            for bdm in ec2.describe_images(ImageIds=[image_id])["Images"][0].get("BlockDeviceMappings", [])
            if bdm.get("Ebs", {}).get("SnapshotId")
        ]
        ec2.deregister_image(ImageId=image_id)
        for snapshot_id in snapshot_ids:
            try:
                ec2.delete_snapshot(SnapshotId=snapshot_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                    raise

    ctx.on_cleanup(_cleanup_image)

    _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"],
        lambda state: state == "available",
        timeout_s=300.0,
        interval_s=10.0,
    )
    return image_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
