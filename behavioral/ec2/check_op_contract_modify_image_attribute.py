"""op-contract-modify-image-attribute."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-image-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyImageAttribute grants/revokes launch permission on an owned AMI and rejects modifying one you don't own."""
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ec2)
    instance_id = _run_instance(ctx, ec2, "t3.micro")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    image_name = ctx.unique_name("sim2real-behav-ami-")
    image_id = ec2.create_image(
        InstanceId=instance_id,
        Name=image_name,
        NoReboot=True,
        TagSpecifications=[
            {"ResourceType": "image", "Tags": [{"Key": "Name", "Value": image_name}]},
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": image_name}]},
        ],
    )["ImageId"]
    ctx.on_cleanup(lambda: _cleanup_image(ec2, image_id))

    # A freshly-created image is still "pending" for a while; ModifyImageAttribute
    # rejects it until the image reaches "available".
    ec2.get_waiter("image_available").wait(ImageIds=[image_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # Group="all" can be refused by the account's Block Public Access for AMIs setting
    # (OperationNotPermitted), so grant to a dummy non-owner account id instead.
    grantee_account_id = "111122223333"

    ec2.modify_image_attribute(
        ImageId=image_id, LaunchPermission={"Add": [{"UserId": grantee_account_id}]}
    )
    attrs = ec2.describe_image_attribute(ImageId=image_id, Attribute="launchPermission")
    assert {"UserId": grantee_account_id} in attrs["LaunchPermissions"], attrs

    ec2.modify_image_attribute(
        ImageId=image_id, LaunchPermission={"Remove": [{"UserId": grantee_account_id}]}
    )
    attrs = ec2.describe_image_attribute(ImageId=image_id, Attribute="launchPermission")
    assert {"UserId": grantee_account_id} not in attrs["LaunchPermissions"], attrs

    # We do not own the amazon-published AMI we launched from; modifying its attributes
    # must be rejected as a permissions boundary, not a not-found.
    code, msg = _error(
        lambda: ec2.modify_image_attribute(
            ImageId=ami_id, LaunchPermission={"Add": [{"UserId": grantee_account_id}]}
        )
    )
    assert code == "AuthFailure", f"expected AuthFailure, got {code}"
    expected = f"Not authorized for image:{ami_id}"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no amazon-owned al2023 AMIs found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _run_instance(ctx, ec2, instance_type: str) -> str:
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-i-")}],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    return resp["Instances"][0]["InstanceId"]


def _terminate(ec2, instance_id: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _cleanup_image(ec2, image_id: str) -> None:
    try:
        deadline = time.monotonic() + 300
        state = None
        snapshot_ids: list[str] = []
        while time.monotonic() < deadline:
            described = ec2.describe_images(ImageIds=[image_id])["Images"]
            if not described:
                return
            state = described[0]["State"]
            snapshot_ids = [
                bdm["Ebs"]["SnapshotId"]
                for bdm in described[0].get("BlockDeviceMappings", [])
                if "Ebs" in bdm and "SnapshotId" in bdm["Ebs"]
            ]
            if state in ("available", "failed"):
                break
            time.sleep(10)
        ec2.deregister_image(ImageId=image_id)
        for snap_id in snapshot_ids:
            try:
                ec2.delete_snapshot(SnapshotId=snap_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
            "InvalidSnapshot.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
