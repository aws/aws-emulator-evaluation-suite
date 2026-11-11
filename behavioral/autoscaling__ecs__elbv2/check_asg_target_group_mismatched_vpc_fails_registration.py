"""asg-target-group-mismatched-vpc-fails-registration."""

from __future__ import annotations

import base64
import time

from behavioral_harness import tags

CHECK = "asg-target-group-mismatched-vpc-fails-registration"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """An ASG attached to a target group in another VPC never registers an instance: the launch is
    cancelled with "Failed to update target group <arn>" and the group stays empty, while a target
    group in the matching VPC attached instead gets the next instance registered."""
    vpc_a, subnet_ids_a = _shared_vpc_and_subnets(ctx)
    vpc_b = _create_other_vpc(ctx)

    ami_id = _latest_al2023_ami(ctx)
    sg_id = _create_web_sg(ctx, vpc_a)
    lt_id = _create_launch_template(
        ctx, ami_id, sg_id, user_data_script=_HTTPD_USER_DATA
    )

    tg_mismatched_arn = _create_target_group(ctx, vpc_b)  # wrong VPC on purpose
    tg_matching_arn = _create_target_group(ctx, vpc_a)  # correct VPC

    asg_name = _create_asg(
        ctx,
        lt_id,
        subnet_ids_a,
        desired_capacity=1,
        min_size=1,
        max_size=1,
        target_group_arns=[tg_mismatched_arn],
        health_check_type="EC2",
        health_check_grace_period=90,
    )
    asg = ctx.client("autoscaling")
    tg_name = tg_mismatched_arn.split(":targetgroup/", 1)[1].split("/", 1)[0]
    cancelled = _poll_until(
        lambda: [
            a for a in asg.describe_scaling_activities(AutoScalingGroupName=asg_name, MaxRecords=20)["Activities"]
            if a["StatusCode"] == "Cancelled" and "Failed to update target group" in a.get("StatusMessage", "")
        ],
        bool,
        timeout_s=600,
        interval_s=15,
        description="a launch cancelled by the mismatched-VPC target group registration",
    )
    assert tg_name in cancelled[0]["StatusMessage"], (
        f"expected the cancelled launch to name target group {tg_name}, got {cancelled[0]['StatusMessage']!r}"
    )
    mismatched_targets = ctx.client("elbv2").describe_target_health(
        TargetGroupArn=tg_mismatched_arn
    )["TargetHealthDescriptions"]
    assert mismatched_targets == [], (
        f"mismatched-VPC target group unexpectedly got targets: {mismatched_targets}"
    )

    # positive control: swap in the matching-VPC target group and the next instance registers.
    asg.detach_load_balancer_target_groups(
        AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_mismatched_arn]
    )
    asg.attach_load_balancer_target_groups(
        AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_matching_arn]
    )
    registered = _wait_for_registered_member(ctx, asg_name, tg_matching_arn, timeout_s=900)
    assert registered, f"expected an ASG instance registered in {tg_matching_arn}"

    still_mismatched = ctx.client("elbv2").describe_target_health(
        TargetGroupArn=tg_mismatched_arn
    )["TargetHealthDescriptions"]
    assert still_mismatched == [], (
        f"mismatched-VPC target group unexpectedly populated: {still_mismatched}"
    )


_HTTPD_USER_DATA = (
    "#!/bin/bash\nyum install -y httpd\nsystemctl enable httpd\nsystemctl start httpd\n"
)


def _shared_vpc_and_subnets(ctx):
    net = ctx.network()
    return net.vpc_id, list(net.subnet_ids)


def _create_other_vpc(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-othervpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    return vpc_id


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
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                # Only the target group's health checks, from inside the VPC, reach it.
                "IpRanges": [{"CidrIp": ctx.network().cidr}],
            }
        ],
    )

    def _cleanup():
        _delete_net(ec2, "delete_security_group", GroupId=sg_id)

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
        HealthCheckIntervalSeconds=10,
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


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
        asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if not asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]:
                return
            time.sleep(10)
        raise AssertionError(f"ASG {name} still present 600s after ForceDelete")

    ctx.on_cleanup(_cleanup)
    return name


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _wait_for_registered_member(ctx, asg_name, tg_arn, timeout_s=900.0):
    """The ASG's current InService instances that the target group lists as registered."""
    asg = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")

    def probe():
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        members = {i["InstanceId"] for i in groups[0]["Instances"] if i["LifecycleState"] == "InService"} if groups else set()
        targets = {d["Target"]["Id"] for d in elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]}
        return members & targets

    return _poll_until(
        probe, bool, timeout_s=timeout_s, interval_s=10,
        description=f"an InService instance of {asg_name} registered in {tg_arn}",
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that would leak the
# VPC while the check passes. So wait
# (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window, and raise
# a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
