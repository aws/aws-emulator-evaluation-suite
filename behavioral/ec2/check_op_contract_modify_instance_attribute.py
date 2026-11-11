"""op-contract-modify-instance-attribute."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-instance-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceAttribute sets disableApiTermination, and the API itself then enforces it."""
    ec2 = ctx.client("ec2")
    instance_id = _run_instance(ctx, ec2, "t3.micro")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiTermination")
    assert attr["DisableApiTermination"]["Value"] is True, attr

    # Observable side effect: TerminateInstances must now be rejected while the flag is set.
    code, msg = _error(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code}"
    expected = f"The instance '{instance_id}' may not be terminated. Modify its 'disableApiTermination' instance attribute and try again."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Independent read: the rejected terminate must not have advanced instance state.
    state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state == "running", f"expected instance to remain running after rejected terminate, got {state}"

    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": False})
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiTermination")
    assert attr["DisableApiTermination"]["Value"] is False, attr

    # Restore leg: the identical call must now succeed once protection is cleared.
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200}
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
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
