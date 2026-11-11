"""asg-elb-health-check-triggers-instance-replacement."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "asg-elb-health-check-triggers-instance-replacement"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """With HealthCheckType=ELB, a target the load balancer reports unhealthy propagates into the
    ASG's own per-instance HealthStatus=Unhealthy, the trigger for instance replacement."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    sg_id = _default_security_group(ctx, vpc_id)
    ami_id = _latest_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id, sg_id)

    # Health check targets a port nothing listens on -> deterministically Unhealthy.
    tg_arn = _create_target_group(ctx, vpc_id, "rep", port=22, health_check_port=55555, interval=10, healthy=2, unhealthy=2)

    # Launch the instance and provision the NLB concurrently (the ASG needs only the target
    # group ARN), so the NLB's minutes-long provisioning overlaps the instance launch.
    asg_name = _create_asg(
        ctx, lt_name, subnet_ids, min_size=1, max_size=1, desired=1,
        target_group_arns=[tg_arn], health_check_type="ELB", grace_period=30,
    )
    lb_arn = _create_internal_nlb(ctx, subnet_ids)
    _wait_for_lb_active(ctx, lb_arn, timeout_s=190.0, interval_s=10.0)
    _create_listener(ctx, lb_arn, tg_arn)

    asg = ctx.client("autoscaling")
    original_id = _poll_until(
        lambda: [i["InstanceId"] for i in asg.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]],
        lambda ids: len(ids) >= 1,
        timeout_s=300.0,
        interval_s=10.0,
    )[0]

    elbv2 = ctx.client("elbv2")
    saw_unhealthy = False
    saw_asg_unhealthy = False
    # Auto Scaling's health-check housekeeping runs on a slower cadence than the ELB health
    # check, so the ASG-side propagation gets a longer window than the target group's.
    deadline = time.monotonic() + 420.0
    while time.monotonic() < deadline:
        try:
            health = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": original_id}])["TargetHealthDescriptions"]
            if health and health[0]["TargetHealth"]["State"] == "unhealthy":
                saw_unhealthy = True
        except Exception:
            pass
        instances = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]
        this_instance = next((i for i in instances if i["InstanceId"] == original_id), None)
        if this_instance is not None and this_instance.get("HealthStatus") == "Unhealthy":
            saw_asg_unhealthy = True
            break
        time.sleep(2.0)

    assert saw_unhealthy, "target health for the original instance never reported Unhealthy"
    assert saw_asg_unhealthy, (
        "ASG never marked the ELB-unhealthy instance's own HealthStatus as Unhealthy "
        "-- the ELB->ASG health-check wiring did not propagate"
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
    if len(subnet_ids) < 1:
        raise AssertionError("shared network has no subnets to launch ASG/NLB resources into")
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
