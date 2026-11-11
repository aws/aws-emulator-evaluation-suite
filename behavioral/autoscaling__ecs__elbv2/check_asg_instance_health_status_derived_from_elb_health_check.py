"""asg-instance-health-status-derived-from-elb-health-check."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "asg-instance-health-status-derived-from-elb-health-check"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """With HealthCheckType=ELB, an ASG instance that never passes the target
    group's health check is eventually reported as Unhealthy by describe_auto_scaling_instances,
    proving ASG derives instance health from the elbv2 target health, not just EC2 status."""
    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    ami_id = _latest_al2023_ami(ctx)
    sg_id = _create_web_sg(ctx, vpc_id)
    # Deliberately NO user data: nothing listens on port 80, so the target
    # group's HTTP health check on "/" can never succeed.
    lt_id = _create_launch_template(ctx, ami_id, sg_id, user_data_script=None)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, vpc_id, subnet_ids, sg_id)
    _wait_for_alb_active(ctx, lb_arn, timeout_s=180)
    _create_listener(ctx, lb_arn, tg_arn)
    asg_name = _create_asg(
        ctx,
        lt_id,
        subnet_ids,
        desired_capacity=1,
        min_size=1,
        max_size=1,
        target_group_arns=[tg_arn],
        health_check_type="ELB",
        health_check_grace_period=5,
    )

    instance_ids = _wait_for_asg_instance_ids(ctx, asg_name, count=1, timeout_s=300)
    instance_id = instance_ids[0]

    # First confirm the elbv2 side considers the target unhealthy.
    tg_health = _wait_for_target_state(
        ctx, tg_arn, instance_id, "unhealthy", timeout_s=300
    )
    assert tg_health["TargetHealth"]["State"] == "unhealthy", (
        f"expected target {instance_id} in {tg_arn} to be unhealthy, "
        f"got {tg_health['TargetHealth']['State']!r}"
    )

    # Then confirm the ASG's own instance health status is derived from it. AWS reports
    # this field as "UNHEALTHY" (all caps) for an ELB-derived status, unlike the mixed-case
    # "Healthy"/"Unhealthy" the API reference uses for the field in general, so the
    # comparison is case-insensitive.
    instance = _wait_for_instance_health(
        ctx, asg_name, instance_id, "unhealthy", timeout_s=420
    )
    assert instance["HealthStatus"].upper() == "UNHEALTHY", (
        f"expected ASG {asg_name} to report instance {instance_id} as unhealthy "
        f"(derived from the ELB health check), got {instance['HealthStatus']!r}"
    )
    assert instance["InstanceId"] == instance_id, (
        f"expected describe_auto_scaling_instances to return instance {instance_id}, "
        f"got {instance['InstanceId']!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _get_default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region for ASG test instances"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(
            "shared network VPC has no subnets available for ASG test instances"
        )
    return vpc_id, [s["SubnetId"] for s in subnets]


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_web_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral test sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["GroupId"]

    def _cleanup():
        last = None
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except Exception as exc:
                if getattr(exc, "response", {}).get("Error", {}).get("Code") == "InvalidGroup.NotFound":
                    return
                last = exc
                time.sleep(2)
        raise RuntimeError(f"security group {sg_id} was not deleted: {last!r}")

    ctx.on_cleanup(_cleanup)
    return sg_id


def _create_launch_template(ctx, ami_id, sg_id, user_data_script=None):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-lt-")
    lt_data = {
        "ImageId": ami_id,
        "InstanceType": "t3.micro",
        "SecurityGroupIds": [sg_id],
    }
    if user_data_script:
        import base64

        lt_data["UserData"] = base64.b64encode(user_data_script.encode()).decode()
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name, LaunchTemplateData=lt_data
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_target_group(ctx, vpc_id, port=80):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-asgtg-tg-")
    tg = elbv2.create_target_group(
        Name=name,
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol="HTTP",
        HealthCheckPort="traffic-port",
        HealthCheckPath="/",
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        HealthCheckIntervalSeconds=5,
        HealthCheckTimeoutSeconds=4,
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _create_alb(ctx, vpc_id, subnet_ids, sg_id):
    """An ALB whose listener forwards to a target group is what actually makes elbv2 run health
    checks against registered targets -- a bare target group never transitions a target out of
    "unused"/Target.NotInUse, which would make an ELB-health-check-typed ASG unable to observe
    unhealthy targets at all."""
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-asgtg-alb-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids[:4],
        SecurityGroups=[sg_id],
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]

    def _cleanup():
        # Fire the delete and return -- do not poll for disappearance here. All cleanups
        # share one bounded budget, and waiting here would starve the cleanups registered
        # before this one.
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)

    ctx.on_cleanup(_cleanup)
    return lb_arn


def _wait_for_alb_active(ctx, lb_arn, timeout_s=180.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        resp = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"]
        if resp:
            last = resp[0]["State"]["Code"]
            if last == "active":
                return
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"load balancer {lb_arn} active: the run budget ended first; not graded")
    raise AssertionError(f"load balancer {lb_arn} never became active; last={last}")


def _create_listener(ctx, lb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _create_asg(
    ctx,
    lt_id,
    subnet_ids,
    *,
    min_size=1,
    max_size=2,
    desired_capacity=1,
    target_group_arns=None,
    health_check_type="EC2",
    health_check_grace_period=60,
):
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-asgtg-asg-")
    params = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired_capacity,
        VPCZoneIdentifier=",".join(subnet_ids),
        HealthCheckType=health_check_type,
        HealthCheckGracePeriod=health_check_grace_period,
    )
    if target_group_arns:
        params["TargetGroupARNs"] = target_group_arns
    asg.create_auto_scaling_group(**params)

    def _cleanup():
        # Fire the delete and return -- do not poll for disappearance here. This callback
        # runs first in ctx.on_cleanup's LIFO order (registered last), and all cleanups share
        # one bounded budget: waiting here for full ASG teardown (which can take minutes)
        # would starve the cleanups registered before this one (listener, ALB, target group,
        # launch template, security group).
        from botocore.exceptions import ClientError

        try:
            asg.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, DesiredCapacity=0
            )
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ValidationError" or "not found" not in err.get("Message", ""):
                raise
            return

    ctx.on_cleanup(_cleanup)
    return name


def _wait_for_asg_instance_ids(ctx, asg_name, count, timeout_s=300.0):
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = []
    while time.monotonic() < deadline:
        resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ]
        if resp:
            last = resp[0]["Instances"]
            if len(last) >= count:
                return [i["InstanceId"] for i in last]
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"ASG {asg_name} reaching {count} instances: "
                           "the run budget ended first; not graded")
    raise AssertionError(
        f"ASG {asg_name} never reached {count} instances (last={last})"
    )


def _wait_for_target_state(ctx, tg_arn, instance_id, want_state, timeout_s=300.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]
        for d in descs:
            if d["Target"]["Id"] == instance_id:
                last = d["TargetHealth"]["State"]
                if last == want_state:
                    return d
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"target {instance_id} reaching state {want_state}: "
                           "the run budget ended first; not graded")
    raise AssertionError(
        f"target {instance_id} never reached state {want_state}; last={last}"
    )


def _wait_for_instance_health(ctx, asg_name, instance_id, want_status, timeout_s=420.0):
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        resp = asg.describe_auto_scaling_instances(InstanceIds=[instance_id])[
            "AutoScalingInstances"
        ]
        if resp:
            last = resp[0]["HealthStatus"]
            if last.upper() == want_status.upper():
                return resp[0]
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id} health {want_status}: "
                           "the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id} health never became {want_status}; last={last}"
    )



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
