"""e2e-scale-out-attach-lb-terminate-flow."""
from __future__ import annotations

import base64
import time

from behavioral_harness import tags

CHECK = "e2e-scale-out-attach-lb-terminate-flow"
GROUP = "e2e"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """Scale an ASG out, confirm the new instance registers healthy behind a real ALB
    target group, scale back in, and confirm the target deregisters and the instance
    terminates -- asserting only the end states, not each intermediate call."""
    autoscaling = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    if len(subnet_ids) < 2:
        raise AssertionError("need at least 2 shared-network subnets in different AZs for an ALB")
    ami = _al2_ami_id(ctx)

    lb_name = ctx.unique_name("sim2real-lb-")[:32].strip("-")
    lb = elbv2.create_load_balancer(
        Name=lb_name, Subnets=subnet_ids[:2], SecurityGroups=[sg_id],
        Scheme="internet-facing", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_load_balancer(elbv2, lb_arn))

    tg_name = ctx.unique_name("sim2real-tg-")[:32].strip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPath="/", HealthCheckIntervalSeconds=10,
        HealthCheckTimeoutSeconds=5, HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group(elbv2, lb_arn, tg_arn))
    # AWS drains a deregistering target for deregistration_delay.timeout_seconds (default 300s)
    # before dropping it from describe_target_health; shorten it so scale-in's removal is
    # observable well inside this check's own poll window rather than racing the AWS default.
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "10"}],
    )

    elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )

    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda state: state == "active",
        timeout_s=300.0, interval_s=10.0,
    )

    user_data = "#!/bin/bash\nyum install -y httpd\nsystemctl enable httpd\nsystemctl start httpd\necho ok > /var/www/html/index.html\n"
    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami, "InstanceType": "t3.micro",
            "NetworkInterfaces": [{
                "DeviceIndex": 0, "AssociatePublicIpAddress": True, "Groups": [sg_id],
            }],
            "UserData": base64.b64encode(user_data.encode()).decode("ascii"),
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0, MaxSize=1, DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids[:2]),
        HealthCheckType="ELB", HealthCheckGracePeriod=180,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_asg(autoscaling, asg_name))

    autoscaling.attach_load_balancer_target_groups(AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_arn])
    autoscaling.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False)

    healthy = _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"],
        lambda descs: any(d["TargetHealth"]["State"] == "healthy" for d in descs),
        timeout_s=600.0, interval_s=15.0,
    )
    healthy_instance_id = next(d["Target"]["Id"] for d in healthy if d["TargetHealth"]["State"] == "healthy")

    asg_state = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    assert any(i["InstanceId"] == healthy_instance_id and i["LifecycleState"] == "InService" for i in asg_state["Instances"]), (
        f"expected {healthy_instance_id} InService in {asg_name}; got {asg_state['Instances']!r}"
    )

    autoscaling.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=0, HonorCooldown=False)

    _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"],
        lambda descs: not any(d["Target"]["Id"] == healthy_instance_id for d in descs),
        timeout_s=300.0, interval_s=10.0,
    )
    _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"],
        lambda instances: len(instances) == 0,
        timeout_s=300.0, interval_s=10.0,
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _delete_asg(autoscaling, asg_name, timeout_s=600.0):
    """Force-delete the group and wait until it (and so its instances) are gone."""
    from botocore.exceptions import ClientError

    try:
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    except ClientError as e:
        if "not found" not in e.response["Error"].get("Message", "").lower():
            raise
    _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"],
        lambda groups: not groups,
        timeout_s=timeout_s, interval_s=15.0,
    )


def _delete_target_group(elbv2, lb_arn, tg_arn, timeout_s=300.0):
    """Delete the listeners that forward to the target group, then the target group itself."""
    from botocore.exceptions import ClientError

    try:
        for listener in elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]:
            elbv2.delete_listener(ListenerArn=listener["ListenerArn"])
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("LoadBalancerNotFound", "ListenerNotFound"):
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=tg_arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(10.0)


def _delete_load_balancer(elbv2, lb_arn):
    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    elbv2.get_waiter("load_balancers_deleted").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    seen_az = {}
    for s in subnets:
        seen_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, list(seen_az.values()), sg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
