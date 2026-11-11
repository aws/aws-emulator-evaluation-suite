"""modify-instance-attribute-immutable-field-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-instance-attribute-immutable-field-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceAttribute rejects an instanceType change on a running instance with
    IncorrectInstanceState and no effect, but accepts the identical call once it is stopped.
    """
    ec2 = ctx.client("ec2")
    instance_id = _run_instance(ctx, ec2, "t3.micro")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # instanceType is only mutable while the instance is stopped
    ec2.stop_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_instance_attribute(InstanceId=instance_id, InstanceType={"Value": "t3.small"})
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="instanceType")
    assert attr["InstanceType"]["Value"] == "t3.small", (
        f"positive control: expected instanceType t3.small after a stopped-state modify, got {attr}"
    )

    ec2.start_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    code, msg = _error(
        lambda: ec2.modify_instance_attribute(
            InstanceId=instance_id, InstanceType={"Value": "t3.micro"}
        )
    )
    assert code == "IncorrectInstanceState", f"expected IncorrectInstanceState, got {code}"
    expected = f"The instance '{instance_id}' is not in the 'stopped' state."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="instanceType")
    assert attr["InstanceType"]["Value"] == "t3.small", (
        f"expected instanceType to remain t3.small after the rejected modify, got {attr}"
    )

    ec2.stop_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_instance_attribute(InstanceId=instance_id, InstanceType={"Value": "t3.micro"})
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="instanceType")
    assert attr["InstanceType"]["Value"] == "t3.micro", (
        f"restore: expected instanceType t3.micro after a stopped-state modify, got {attr}"
    )


def _error(fn):
    """Return the (code, message) of fn()'s ClientError; an unexpected success raises."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
