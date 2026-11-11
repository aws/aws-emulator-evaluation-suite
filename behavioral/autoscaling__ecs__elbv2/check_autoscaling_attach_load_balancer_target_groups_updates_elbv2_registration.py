"""autoscaling-attach-load-balancer-target-groups-updates-elbv2-registration."""
from __future__ import annotations

import base64
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "autoscaling-attach-load-balancer-target-groups-updates-elbv2-registration"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancerTargetGroups on an already-running ASG causes its existing
    instance(s) to appear as registered (and eventually healthy) elbv2 targets."""
    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    ami_id = _latest_al2023_ami(ctx)
    sg_id = _create_web_sg(ctx, vpc_id)
    lt_id = _create_launch_template(ctx, ami_id, sg_id, user_data_script=_HTTPD_USER_DATA)

    # ASG created WITHOUT any target group.
    asg_name = _create_asg(
        ctx, lt_id, subnet_ids, desired_capacity=1, min_size=1, max_size=1,
        target_group_arns=None, health_check_type="EC2", health_check_grace_period=90,
    )
    instance_ids = _wait_for_asg_instance_ids(ctx, asg_name, count=1, timeout_s=300)
    assert len(instance_ids) == 1

    tg_arn = _create_target_group(ctx, vpc_id)

    # Before attaching, the target group must have no targets at all.
    elbv2 = ctx.client("elbv2")
    pre_attach = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert pre_attach == [], f"target group unexpectedly pre-populated: {pre_attach}"

    lb_arn = _create_alb(ctx, vpc_id, subnet_ids, sg_id)
    _wait_for_alb_active(ctx, lb_arn, timeout_s=180)
    _create_listener(ctx, lb_arn, tg_arn)

    asg = ctx.client("autoscaling")
    asg.attach_load_balancer_target_groups(AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_arn])

    descs = _wait_for_target_ids(ctx, tg_arn, instance_ids, timeout_s=300)
    seen_ids = {d["Target"]["Id"] for d in descs}
    assert seen_ids == set(instance_ids), f"expected only {instance_ids} registered, saw {seen_ids}"

    health = _wait_for_target_state(ctx, tg_arn, instance_ids[0], "healthy", timeout_s=300)
    assert health["TargetHealth"]["State"] == "healthy"


# yum-installed httpd serves its default (empty) docroot as 403, which the target group's
# HTTP/200 health check never passes -- serve real content instead.
_HTTPD_USER_DATA = (
    "#!/bin/bash\n"
    "mkdir -p /var/www/html\n"
    "echo sim2real-asgtg-ok > /var/www/html/index.html\n"
    "nohup python3 -m http.server 80 --directory /var/www/html "
    "> /var/log/sim2real-httpd.log 2>&1 &\n"
)


def _get_default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for ASG test instances")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for ASG test instances")
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
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": ctx.network().cidr}]}],
    )

    def _cleanup():
        deadline = time.monotonic() + 180
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return sg_id


def _create_launch_template(ctx, ami_id, sg_id, user_data_script=None):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-lt-")
    lt_data = {"ImageId": ami_id, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]}
    if user_data_script:
        lt_data["UserData"] = base64.b64encode(user_data_script.encode()).decode()
    lt_id = ec2.create_launch_template(LaunchTemplateName=name, LaunchTemplateData=lt_data)["LaunchTemplate"][
        "LaunchTemplateId"
    ]
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
        HealthCheckIntervalSeconds=10,
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _create_alb(ctx, vpc_id, subnet_ids, sg_id):
    """An ALB whose listener forwards to a target group is what actually makes elbv2 run health
    checks against registered targets -- a bare target group never transitions a target out of
    "unused"/Target.NotInUse."""
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
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                resp = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"]
                if not resp:
                    return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(5)

    ctx.on_cleanup(_cleanup)
    return lb_arn


def _wait_for_alb_active(ctx, lb_arn, timeout_s=180.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"]
        if resp:
            last = resp[0]["State"]["Code"]
            if last == "active":
                return
        time.sleep(2)
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
    ctx, lt_id, subnet_ids, *, min_size=1, max_size=2, desired_capacity=1,
    target_group_arns=None, health_check_type="EC2", health_check_grace_period=60,
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
        try:
            asg.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=0, DesiredCapacity=0)
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ValidationError" or "not found" not in err.get("Message", ""):
                raise
            return
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])
            if not resp["AutoScalingGroups"]:
                return
            time.sleep(2)
        raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")

    ctx.on_cleanup(_cleanup)
    return name


def _wait_for_asg_instance_ids(ctx, asg_name, count, timeout_s=300.0):
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if resp:
            last = resp[0]["Instances"]
            if len(last) >= count:
                return [i["InstanceId"] for i in last]
        time.sleep(2)
    raise AssertionError(f"ASG {asg_name} never reached {count} instances (last={last})")


def _wait_for_target_ids(ctx, tg_arn, expected_ids, timeout_s=300.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    seen: set[str] = set()
    descs = []
    while time.monotonic() < deadline:
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        seen = {d["Target"]["Id"] for d in descs}
        if set(expected_ids).issubset(seen):
            return descs
        time.sleep(2)
    raise AssertionError(f"target group {tg_arn} never registered {expected_ids}; saw {seen}")


def _wait_for_target_state(ctx, tg_arn, instance_id, want_state, timeout_s=300.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        for d in descs:
            if d["Target"]["Id"] == instance_id:
                last = d["TargetHealth"]["State"]
                if last == want_state:
                    return d
        time.sleep(2)
    raise AssertionError(f"target {instance_id} never reached state {want_state}; last={last}")



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
