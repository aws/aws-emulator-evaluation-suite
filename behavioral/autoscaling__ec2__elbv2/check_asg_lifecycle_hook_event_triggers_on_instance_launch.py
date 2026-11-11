"""asg-lifecycle-hook-event-triggers-on-instance-launch."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "asg-lifecycle-hook-event-triggers-on-instance-launch"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A launch lifecycle hook makes Auto Scaling publish an 'EC2 Instance-launch Lifecycle Action'
    event to EventBridge naming the launching instance, the group and the hook."""
    asg_name = ctx.unique_name("sim2real-asg-")
    hook_name = ctx.unique_name("sim2real-hook-")

    _, subnet_id = _default_vpc_subnet(ctx)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    queue_url, queue_arn = _create_sqs_queue(ctx)
    pattern = {
        "source": ["aws.autoscaling"],
        "detail-type": ["EC2 Instance-launch Lifecycle Action"],
        "detail": {"AutoScalingGroupName": [asg_name]},
    }
    _create_rule_with_sqs_target(ctx, pattern, queue_url, queue_arn)

    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=1,
        MaxSize=1,
        DesiredCapacity=1,
        VPCZoneIdentifier=subnet_id,
        LifecycleHookSpecificationList=[
            {
                "LifecycleHookName": hook_name,
                "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
                "HeartbeatTimeout": 90,
                "DefaultResult": "CONTINUE",
            }
        ],
        Tags=[
            {
                "Key": "sim2real",
                "Value": "true",
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "PropagateAtLaunch": False,
            }
        ],
    )
    ctx.on_cleanup(
        lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    event = _poll_sqs_for_message(
        ctx,
        queue_url,
        lambda body: body.get("detail", {}).get("AutoScalingGroupName") == asg_name,
        timeout_s=240.0,
    )
    detail = event["detail"]
    assert event["detail-type"] == "EC2 Instance-launch Lifecycle Action", (
        f"expected detail-type 'EC2 Instance-launch Lifecycle Action', got {event['detail-type']!r}"
    )
    assert event["source"] == "aws.autoscaling", f"expected source 'aws.autoscaling', got {event['source']!r}"
    assert detail["LifecycleTransition"] == "autoscaling:EC2_INSTANCE_LAUNCHING", (
        f"expected transition 'autoscaling:EC2_INSTANCE_LAUNCHING', got {detail['LifecycleTransition']!r}"
    )
    assert detail["LifecycleHookName"] == hook_name, (
        f"expected hook name {hook_name!r}, got {detail['LifecycleHookName']!r}"
    )

    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    live_instance_ids = [i["InstanceId"] for i in groups[0]["Instances"]] if groups else []
    assert detail["EC2InstanceId"] in live_instance_ids, (
        f"event named instance {detail['EC2InstanceId']!r}, but the ASG's own "
        f"DescribeAutoScalingGroups reports {live_instance_ids!r}"
    )

    # Let the launch actually finish instead of leaving the instance stuck in
    # Pending:Wait for the whole heartbeat window (best-effort, not asserted).
    try:
        asg.complete_lifecycle_action(
            LifecycleHookName=hook_name,
            AutoScalingGroupName=asg_name,
            LifecycleActionToken=detail["LifecycleActionToken"],
            LifecycleActionResult="CONTINUE",
        )
    except Exception:
        pass


def _default_vpc_subnet(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to launch a test instance into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch a test instance into")
    return vpc_id, subnets[0]["SubnetId"]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_sqs_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags={"sim2real": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow_eventbridge_to_send(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
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
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _create_rule_with_sqs_target(ctx, pattern: dict, queue_url: str, queue_arn: str) -> str:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    _allow_eventbridge_to_send(ctx, queue_url, queue_arn, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target-1", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target-1"]))
    return rule_name


def _poll_sqs_for_message(ctx, queue_url: str, predicate, timeout_s: float = 180.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body, dict) and predicate(body):
                return body
    raise AssertionError(f"expected message not received on {queue_url} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
