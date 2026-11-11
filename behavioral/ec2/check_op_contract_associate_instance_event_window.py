"""op-contract-associate-instance-event-window."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-associate-instance-event-window"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateInstanceEventWindow attaches instances/tags to a maintenance event window;
    specifying both InstanceIds and tags in the same association target is rejected."""
    ec2 = ctx.client("ec2")
    instance_id, _subnet_id = _launch_instance(ctx)

    window_id = ec2.create_instance_event_window(
        Name=ctx.unique_name("sim2real-eventwin-"),
        TimeRanges=[{"StartWeekDay": "sunday", "StartHour": 2, "EndWeekDay": "sunday", "EndHour": 6}],
    )["InstanceEventWindow"]["InstanceEventWindowId"]
    ctx.on_cleanup(lambda: ec2.delete_instance_event_window(InstanceEventWindowId=window_id, ForceDelete=True))

    resp = ec2.associate_instance_event_window(
        InstanceEventWindowId=window_id, AssociationTarget={"InstanceIds": [instance_id]}
    )
    targets = resp["InstanceEventWindow"]["AssociationTarget"]
    assert instance_id in targets.get("InstanceIds", []), f"association not reflected: {targets}"

    described = ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])["InstanceEventWindows"][0]
    described_targets = described["AssociationTarget"]
    assert instance_id in described_targets.get("InstanceIds", []), (
        f"expected {instance_id} in the described association target, got {described_targets}"
    )

    code, message = _client_error(
        lambda: ec2.associate_instance_event_window(
            InstanceEventWindowId=window_id,
            AssociationTarget={
                "InstanceIds": [instance_id],
                "InstanceTags": [{"Key": "sim2real", "Value": "x"}],
            },
        )
    )
    # AWS validates the association target's fields as mutually exclusive *values* rather
    # than an invalid *combination* of otherwise-independent parameters -- real AWS rejects
    # this with InvalidParameterValue, not InvalidParameterCombination.
    assert code == "InvalidParameterValue", f"unexpected error code: {code}"
    expected = (
        "Target Associations must be composed entirely of Instance IDs, Instance Tags, "
        "or Dedicated Host IDs."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _own_vpc_subnet(ctx):
    """A VPC and subnet the check creates itself, so it does not depend on a default VPC that a
    freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "Name", "Value": ctx.unique_name("sim2real-eventwin-vpc-")}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags_kv}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.91.1.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": tags_kv}]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id, subnet_id


def _latest_al2023_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_instance(ctx):
    ec2 = ctx.client("ec2")
    _vpc_id, subnet_id = _own_vpc_subnet(ctx)
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-instance-")}]}
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id, subnet_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
