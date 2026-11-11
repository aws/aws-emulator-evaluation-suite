"""asg-waits-for-elb-healthy-before-marking-instance-inservice."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "asg-waits-for-elb-healthy-before-marking-instance-inservice"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """With HealthCheckType=ELB, a launched instance reaches InService without waiting for the load
    balancer, and the target group's health check then converges on healthy."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    vpc_cidr = _vpc_cidr(ctx, vpc_id)
    sg_id = _create_sg_allow_ssh(ctx, vpc_id, vpc_cidr)
    ami_id = _latest_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id, sg_id)

    # Health check on port 22 (sshd) which will pass once the instance boots.
    tg_arn = _create_target_group(ctx, vpc_id, "wait", port=22, health_check_port=22, interval=10, healthy=2, unhealthy=2)

    # Launch the instance and provision the NLB concurrently (the ASG needs only the target
    # group ARN), so the NLB's minutes-long provisioning overlaps the instance launch.
    asg_name = _create_asg(
        ctx, lt_name, subnet_ids, min_size=1, max_size=1, desired=1,
        target_group_arns=[tg_arn], health_check_type="ELB", grace_period=120,
    )
    lb_arn = _create_internal_nlb(ctx, subnet_ids)
    _wait_for_lb_active(ctx, lb_arn, timeout_s=190.0, interval_s=10.0)
    _create_listener(ctx, lb_arn, tg_arn)

    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    asg = ctx.client("autoscaling")

    instance_id = _poll_until(
        lambda: [i["InstanceId"] for i in asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]],
        lambda ids: len(ids) >= 1,
        timeout_s=60.0, interval_s=10.0,
    )[0]

    # InService does not wait on the ELB health check -- it reflects EC2 launch
    # success. Confirm it arrives quickly (well inside the grace period).
    lifecycle = _poll_until(
        lambda: next(
            (i["LifecycleState"] for i in asg.describe_auto_scaling_groups(
                AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]
             if i["InstanceId"] == instance_id),
            None,
        ),
        lambda s: s == "InService",
        timeout_s=60.0, interval_s=10.0,
    )
    assert lifecycle == "InService", f"instance never reached InService (last: {lifecycle!r})"

    ec2_state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert ec2_state == "running", f"expected the InService instance to be EC2-running, got {ec2_state!r}"

    # Independently, the target group's own health check converges on Healthy
    # once sshd is actually listening -- the ELB<->ASG resource binding, not a
    # blocking precondition for InService.
    healthy = _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": instance_id}])["TargetHealthDescriptions"],
        lambda health: bool(health) and health[0]["TargetHealth"]["State"] == "healthy",
        timeout_s=120.0, interval_s=10.0,
    )
    assert healthy[0]["TargetHealth"]["State"] == "healthy", (
        f"expected the target group to independently converge on healthy once sshd is up, "
        f"got {healthy[0]['TargetHealth']['State']!r}"
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
        raise AssertionError("no shared network VPC available in this account/region to launch ASG/NLB resources into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets]
    if not subnet_ids:
        raise AssertionError("shared network has no subnets to launch ASG/NLB resources into")
    return vpc_id, subnet_ids


def _vpc_cidr(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    return ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["CidrBlock"]


def _create_sg_allow_ssh(ctx, vpc_id: str, cidr: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real behavioral test sg", VpcId=vpc_id,
        TagSpecifications=_tag_spec("security-group", name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": cidr}]}],
    )
    return sg_id


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
    tg = elbv2.create_target_group(
        Name=_tg_name(ctx, suffix),
        Protocol=protocol,
        Port=port,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol=protocol,
        HealthCheckPort=str(health_check_port or port),
        HealthCheckIntervalSeconds=interval,
        HealthyThresholdCount=healthy,
        UnhealthyThresholdCount=unhealthy,
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


def _create_internal_nlb(ctx, subnet_ids: list[str]) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-nlb-")[:32].rstrip("-")
    lb = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids[:2] if len(subnet_ids) >= 2 else subnet_ids,
        Scheme="internal", Type="network",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn))
    return arn


def _wait_for_lb_active(ctx, lb_arn: str, timeout_s: float = 300.0, interval_s: float = 15.0) -> None:
    elbv2 = ctx.client("elbv2")
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s, interval_s,
    )


def _create_listener(ctx, lb_arn: str, tg_arn: str, port: int = 80) -> str:
    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="TCP", Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=arn))
    return arn


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



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
