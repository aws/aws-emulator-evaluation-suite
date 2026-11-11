"""target-group-register-fails-instance-wrong-vpc."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "target-group-register-fails-instance-wrong-vpc"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """RegisterTargets rejects an EC2 instance whose VPC does not match the target group's
    VPC with InvalidTarget, writes no target state, while the identical call for an
    instance in the matching VPC succeeds (positive control).
    """
    home_vpc_id, home_subnet_id, home_sg_id = _create_isolated_vpc_with_subnet(
        ctx, ctx.unique_name("sim2real-wrongvpc-home-")
    )
    tg_arn = _create_target_group(ctx, home_vpc_id, ctx.unique_name("sim2real-wvpc-tg-"))

    other_vpc_id, other_subnet_id, other_sg_id = _create_isolated_vpc_with_subnet(
        ctx, ctx.unique_name("sim2real-wrongvpc-other-")
    )
    other_instance_id = _launch_instance(ctx, other_subnet_id, other_sg_id, ctx.unique_name("sim2real-wrongvpc-inst-"))

    elbv2 = ctx.client("elbv2")

    code, message = _error(
        lambda: elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": other_instance_id, "Port": 80}])
    )
    assert code == "InvalidTarget", f"expected InvalidTarget for cross-VPC registration, got {code}"
    expected_message = (
        f"The following targets are not in the target group VPC '{home_vpc_id}': '{other_instance_id}'"
    )
    assert message == expected_message, f"InvalidTarget message {message!r}, expected {expected_message!r}"

    registered = elbv2.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
    assert registered == [], f"target group should have no registered targets, found {registered}"

    # Positive control: an instance that actually lives in the target group's own VPC
    # registers successfully with the identical call shape.
    good_instance_id = _launch_instance(ctx, home_subnet_id, home_sg_id, ctx.unique_name("sim2real-wrongvpc-good-"))
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": good_instance_id, "Port": 80}])
    registered = elbv2.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
    registered_ids = {d["Target"]["Id"] for d in registered}
    assert good_instance_id in registered_ids, "same-VPC instance was not registered by the control call"


def _tag_spec(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _latest_al2023_ami(ctx: Any) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _terminate_and_wait(ctx: Any, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _launch_instance(ctx: Any, subnet_id: str, sg_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    instance_id = ec2.run_instances(
        ImageId=ami_id, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id]}],
        TagSpecifications=_tag_spec("instance", name),
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


def _create_isolated_vpc_with_subnet(ctx: Any, name_prefix: str) -> tuple[str, str, str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16", TagSpecifications=_tag_spec("vpc", name_prefix + "vpc")
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.77.1.0/24", TagSpecifications=_tag_spec("subnet", name_prefix + "subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=name_prefix + "sg", Description="sim2real isolated vpc sg", VpcId=vpc_id,
        TagSpecifications=_tag_spec("security-group", name_prefix + "sg"),
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return vpc_id, subnet_id, sg_id


def _create_target_group(
    ctx: Any, vpc_id: str, name: str, protocol: str = "HTTP", port: int = 80, health_path: str = "/",
) -> str:
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=name, Protocol=protocol, Port=port, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol=protocol, HealthCheckPath=health_path,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because a
    target that accepts a request real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
