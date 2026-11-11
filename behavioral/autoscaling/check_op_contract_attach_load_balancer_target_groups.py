"""op-contract-attachLoadBalancerTargetGroups."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-attachLoadBalancerTargetGroups"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancerTargetGroups registers a real target group with the group
    (state Adding->Added); attaching a nonexistent target group ARN is rejected and
    does not change the group's target group list."""
    asg = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")

    ami_id = _latest_al2023_ami(ctx)
    subnet_id, vpc_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[
            {"Key": "sim2real:managed", "ResourceId": group_name, "ResourceType": "auto-scaling-group", "Value": "true"},
            {"Key": "sim2real:prefix", "ResourceId": group_name, "ResourceType": "auto-scaling-group", "Value": "sim2real-behav"},
        ],
    )

    def _delete_group():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_delete_group)

    tg_name = ctx.unique_name("sim2real-behav-tg-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance"
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    elbv2.add_tags(
        ResourceArns=[tg_arn],
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )

    # --- success path ---
    asg.attach_load_balancer_target_groups(
        AutoScalingGroupName=group_name, TargetGroupARNs=[tg_arn]
    )

    def _probe():
        return asg.describe_load_balancer_target_groups(AutoScalingGroupName=group_name)[
            "LoadBalancerTargetGroups"
        ]

    tgs = _poll_until(
        _probe,
        lambda lst: len(lst) == 1 and lst[0]["State"] in ("Added", "InService"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert tgs[0]["LoadBalancerTargetGroupARN"] == tg_arn, (
        f"expected attached target group {tg_arn}, describe returned {tgs[0]!r}"
    )

    # --- error boundary: attach a well-formed but nonexistent target group ARN ---
    fake_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{tg_arn.split(':')[4]}:"
        f"targetgroup/sim2real-nonexistent-{uuid.uuid4().hex[:12]}/0123456789abcdef"
    )
    code, message = _error(
        lambda: asg.attach_load_balancer_target_groups(
            AutoScalingGroupName=group_name, TargetGroupARNs=[fake_arn]
        )
    )
    assert code == "ValidationError", f"expected ValidationError for bogus target group, got {code}"
    expected_message = "Provided Target Groups may not be valid. Please ensure they exist and try again."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tgs_after = asg.describe_load_balancer_target_groups(AutoScalingGroupName=group_name)[
        "LoadBalancerTargetGroups"
    ]
    assert [t["LoadBalancerTargetGroupARN"] for t in tgs_after] == [tg_arn], (
        f"expected attachment list unchanged at [{tg_arn}] after rejected attach, "
        f"got {tgs_after!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]

    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in shared network")
    return subnets[0]["SubnetId"], vpc_id


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [
                    {"Key": "sim2real:managed", "Value": "true"},
                    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
                ],
            }
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id



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
