"""asg-registers-new-ec2-instance-with-target-group."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "asg-registers-new-ec2-instance-with-target-group"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A new EC2 instance launched by an ASG is automatically registered as a
    target in the target group attached at group-creation time."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    sg_id = _default_security_group(ctx, vpc_id)
    ami_id = _latest_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id, sg_id)
    tg_arn = _create_target_group(ctx, vpc_id, "reg")

    asg_name = _create_asg(
        ctx, lt_name, subnet_ids, min_size=1, max_size=1, desired=1,
        target_group_arns=[tg_arn], health_check_type="EC2",
    )

    instance_ids = _wait_for_inservice_instances(ctx, asg_name, count=1)
    instance_id = instance_ids[0]

    ec2 = ctx.client("ec2")
    state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state == "running", f"expected launched instance running, got {state}"

    registered_ids = _poll_until(
        lambda: [t["Target"]["Id"] for t in ctx.client("elbv2").describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]],
        lambda ids: instance_id in ids,
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert instance_id in registered_ids, (
        f"expected launched instance {instance_id} registered in target group {tg_arn}, "
        f"got {registered_ids}"
    )


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}]


def _default_vpc_and_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch ASG instances into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets]
    if not subnet_ids:
        raise AssertionError("shared network has no subnets to launch ASG instances into")
    return vpc_id, subnet_ids


def _default_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )
    return resp["SecurityGroups"][0]["GroupId"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, sg_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "SecurityGroupIds": [sg_id],
            "TagSpecifications": _tag_spec("instance", name),
        },
        TagSpecifications=_tag_spec("launch-template", name),
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _tg_name(ctx, suffix: str = "") -> str:
    name = ctx.unique_name(f"sim2real-tg{suffix}-")
    return name[:32].rstrip("-")


def _create_target_group(
    ctx, vpc_id: str, suffix: str = "", port: int = 22, protocol: str = "TCP",
    health_check_port: int | None = None, interval: int = 10, healthy: int = 2, unhealthy: int = 2,
) -> str:
    elbv2 = ctx.client("elbv2")
    tg_name = _tg_name(ctx, suffix)
    tg = elbv2.create_target_group(
        Name=tg_name,
        Protocol=protocol,
        Port=port,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol=protocol,
        HealthCheckPort=str(health_check_port or port),
        HealthCheckIntervalSeconds=interval,
        HealthyThresholdCount=healthy,
        UnhealthyThresholdCount=unhealthy,
        Tags=[{"Key": "Name", "Value": tg_name}, {"Key": "sim2real", "Value": "true"}],
    )["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_ignore_missing(ctx, arn))
    return arn


def _delete_target_group_ignore_missing(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError
    elbv2 = ctx.client("elbv2")
    try:
        _delete_target_group_when_free(elbv2, arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "TargetGroupNotFound":
            raise


def _create_asg(
    ctx, lt_name: str, subnet_ids: list[str], min_size: int, max_size: int, desired: int,
    target_group_arns: list[str] | None = None, health_check_type: str = "EC2", grace_period: int = 60,
) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-asg-")
    params: dict[str, Any] = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=",".join(subnet_ids[:2]),
        HealthCheckType=health_check_type,
        HealthCheckGracePeriod=grace_period,
        Tags=[
            {"Key": "Name", "Value": name, "PropagateAtLaunch": True},
            {"Key": "sim2real", "Value": "true", "PropagateAtLaunch": True},
        ],
    )
    if target_group_arns:
        params["TargetGroupARNs"] = target_group_arns
    asg.create_auto_scaling_group(**params)
    ctx.on_cleanup(lambda: _delete_asg(ctx, name))
    return name


def _delete_asg(ctx, name: str) -> None:
    """Force-delete the group and wait until it is gone: a refusal while a scaling activity runs
    is retried every 2 s, a group already gone is done, anything else raises."""
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + 400.0
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            busy = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")
            if err["Code"] not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"auto scaling group {name} still listed at the teardown deadline")
        time.sleep(2)


def _wait_for_inservice_instances(ctx, asg_name: str, count: int, timeout_s: float = 400.0, interval_s: float = 15.0) -> list[str]:
    asg = ctx.client("autoscaling")

    def probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]

    def pred(instances):
        return len([i for i in instances if i["LifecycleState"] == "InService"]) >= count

    instances = _poll_until(probe, pred, timeout_s, interval_s)
    return [i["InstanceId"] for i in instances if i["LifecycleState"] == "InService"]



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
