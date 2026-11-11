"""autoscaling-lifecycle-hook-event-delivered-to-eventbridge."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "autoscaling-lifecycle-hook-event-delivered-to-eventbridge"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scaling an ASG with a launch lifecycle hook out emits an "EC2 Instance-launch
    Lifecycle Action" event, delivered to an EventBridge-targeted SQS queue with the
    hook's transition and action token."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    ami_id = _latest_al2023_ami(ctx)
    subnet_id = _default_vpc_subnet(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": "t3.micro",
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": lt_name}]}
            ],
        },
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "Name", "Value": lt_name}],
            }
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "Name", "Value": asg_name, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: _delete_asg(ctx, asg_name))

    hook_name = ctx.unique_name("sim2real-hook-")
    autoscaling.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=asg_name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout=300,
        DefaultResult="CONTINUE",
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_lifecycle_hook(
            LifecycleHookName=hook_name, AutoScalingGroupName=asg_name
        )
    )

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-asgq-"), tags={"sim2real": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-asgrule-")
    pattern = {
        "source": ["aws.autoscaling"],
        "detail-type": ["EC2 Instance-launch Lifecycle Action"],
        "detail": {"AutoScalingGroupName": [asg_name]},
    }
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
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
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])

    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False
    )

    envelope = _wait_for_lifecycle_event(sqs, queue_url, asg_name, timeout_s=300.0)
    detail = envelope["detail"]
    assert envelope["source"] == "aws.autoscaling", (
        f"expected event source aws.autoscaling, got {envelope.get('source')!r}"
    )
    assert envelope["detail-type"] == "EC2 Instance-launch Lifecycle Action", (
        f"expected detail-type 'EC2 Instance-launch Lifecycle Action', "
        f"got {envelope.get('detail-type')!r}"
    )
    assert detail["LifecycleTransition"] == "autoscaling:EC2_INSTANCE_LAUNCHING", (
        f"expected LifecycleTransition autoscaling:EC2_INSTANCE_LAUNCHING, "
        f"got {detail.get('LifecycleTransition')!r}"
    )
    assert detail["LifecycleHookName"] == hook_name, (
        f"expected LifecycleHookName {hook_name!r}, got {detail.get('LifecycleHookName')!r}"
    )
    assert detail["AutoScalingGroupName"] == asg_name, (
        f"expected AutoScalingGroupName {asg_name!r}, got {detail.get('AutoScalingGroupName')!r}"
    )
    assert detail["EC2InstanceId"].startswith("i-"), (
        f"expected a real EC2 instance id, got {detail.get('EC2InstanceId')!r}"
    )
    assert detail["LifecycleActionToken"], (
        f"expected a non-empty LifecycleActionToken, got {detail.get('LifecycleActionToken')!r}"
    )

    # let the held instance finish launching so ASG teardown is clean
    try:
        autoscaling.complete_lifecycle_action(
            LifecycleHookName=hook_name,
            AutoScalingGroupName=asg_name,
            LifecycleActionToken=detail["LifecycleActionToken"],
            LifecycleActionResult="CONTINUE",
            InstanceId=detail["EC2InstanceId"],
        )
    except Exception:
        pass


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_vpc_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return subnets[0]["SubnetId"]


def _wait_for_lifecycle_event(sqs, queue_url, asg_name, timeout_s=180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                envelope = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if envelope and envelope.get("detail", {}).get("AutoScalingGroupName") == asg_name:
                return envelope
    raise AssertionError(f"no lifecycle hook event delivered for ASG {asg_name} within {timeout_s}s")


def _delete_asg(ctx, asg_name: str) -> None:
    # ForceDelete terminates the member instances with the group, within the cleanup budget.
    autoscaling = ctx.client("autoscaling")
    try:
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "ValidationError" or "not found" not in err.get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
