"""autoscaling-instance-launch-event-triggers-target-group-check."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "autoscaling-instance-launch-event-triggers-target-group-check"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An ASG attached to an ALB target group emits an "EC2 Instance Launch
    Successful" event on scale-out, delivered via EventBridge to SQS, and the
    launched instance is registered as a target in the target group."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    ami_id = _latest_al2023_ami(ctx)
    vpc_id, subnet_ids = _default_vpc_two_subnets(ctx)
    default_sg_id = _default_sg(ctx, vpc_id)

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckEnabled=True,
        Tags=_managed_tags(),
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    alb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-alb-"),
        Subnets=subnet_ids,
        SecurityGroups=[default_sg_id],
        Type="application",
        Scheme="internet-facing",
        Tags=_managed_tags(),
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])[
            "LoadBalancers"
        ][0]["State"]["Code"],
        lambda c: c == "active",
        timeout_s=180,
        interval_s=5.0,
        description="ALB active",
    )

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_managed_tags(),
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    lt_name = ctx.unique_name("sim2real-lt2-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": "t3.micro",
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": lt_name}, *_managed_tags()],
                }
            ],
        },
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": _managed_tags()}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-asg2-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        TargetGroupARNs=[tg_arn],
        Tags=_managed_tags(),
    )
    ctx.on_cleanup(lambda: _delete_asg(ctx, asg_name))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-asgq2-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-asgrule2-")
    pattern = {
        "source": ["aws.autoscaling"],
        "detail-type": ["EC2 Instance Launch Successful"],
        "detail": {"AutoScalingGroupName": [asg_name]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=_managed_tags(),
    )["RuleArn"]

    def _cleanup_rule() -> None:
        try:
            events.remove_targets(Rule=rule_name, Ids=["1"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            events.delete_rule(Name=rule_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_rule)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])

    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False
    )

    envelope = _wait_for_launch_event(sqs, queue_url, asg_name, timeout_s=180.0)
    instance_id = envelope["detail"]["EC2InstanceId"]
    assert instance_id, f"launch event detail carried no EC2InstanceId: {envelope!r}"

    health = _poll_until(
        lambda: elbv2.describe_target_health(
            TargetGroupArn=tg_arn, Targets=[{"Id": instance_id}]
        )["TargetHealthDescriptions"],
        lambda descs: len(descs) == 1,
        timeout_s=90,
        interval_s=5.0,
        description=f"instance {instance_id} registered in target group",
    )
    assert health[0]["Target"]["Id"] == instance_id, (
        f"expected target {instance_id}, got {health[0]['Target']['Id']}"
    )
    # The listener already forwards to tg_arn and HealthCheckEnabled=True, so a target that
    # just appeared here is actively health-checked, not idle -- "unused" (no listener action
    # uses the group) and "draining" (mid-deregistration) cannot legitimately occur on this
    # wiring; a target reporting either would mean registration/health-check routing is broken.
    state = health[0]["TargetHealth"]["State"]
    assert state in {"initial", "healthy", "unhealthy"}, (
        f"instance {instance_id} reported target health state {state!r}, "
        "which is not reachable on a group with an active forwarding listener"
    )


_MANAGED_TAGS = {"sim2real": CHECK, "sim2real:managed": "true"}


def _managed_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_vpc_two_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "shared network VPC does not have subnets in >=2 AZs to attach an ALB to"
        )
    return vpc_id, list(by_az.values())[:2]


def _default_sg(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    return sgs[0]["GroupId"]


def _wait_for_launch_event(sqs, queue_url, asg_name, timeout_s=180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            try:
                envelope = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if (
                envelope
                and envelope.get("detail", {}).get("AutoScalingGroupName") == asg_name
            ):
                return envelope
    raise AssertionError(
        f"no instance-launch event delivered for ASG {asg_name} within {timeout_s}s"
    )


def _delete_asg(ctx, asg_name: str) -> None:
    # ForceDelete terminates the member instances with the group, within the cleanup budget.
    autoscaling = ctx.client("autoscaling")
    try:
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "ValidationError" or "not found" not in err.get("Message", ""):
            raise



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
