"""autoscaling-event-rule-mismatched-pattern-no-delivery."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "autoscaling-event-rule-mismatched-pattern-no-delivery"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule matching only "EC2 Instance Terminate Successful" never receives the
    launch event an ASG scale-out emits; correcting the pattern on the same rule delivers the next launch."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    ami_id = _latest_al2023_ami(ctx)
    subnet_id = _default_vpc_subnet(ctx)

    lt_name = ctx.unique_name("sim2real-lt3-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": "t3.micro",
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": lt_name}]},
            ],
        },
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]},
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-asg3-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: _delete_asg(ctx, asg_name))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-mismatchq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-mismatchrule-")
    wrong_pattern = {
        "source": ["aws.autoscaling"],
        "detail-type": ["EC2 Instance Terminate Successful"],
        "detail": {"AutoScalingGroupName": [asg_name]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(wrong_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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

    # --- broken: pattern requires the wrong detail-type ---
    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False
    )
    _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]["Instances"],
        lambda instances: len(instances) >= 1,
        timeout_s=120,
        interval_s=5.0,
        description="ASG launched an instance",
    )
    mismatched = _poll_for_message(sqs, queue_url, asg_name, timeout_s=60.0)
    assert mismatched is None, (
        "an event was delivered even though the rule's event pattern's detail-type "
        "does not match the real event's detail-type"
    )

    # Switch the rule to the correct pattern BEFORE scaling back to 0 -- otherwise
    # the termination we're about to trigger emits an "EC2 Instance Terminate
    # Successful" event that the still-active wrong_pattern rule WOULD match,
    # leaving a stale message in the queue that the positive-control poll below
    # would pick up instead of the real launch event.
    correct_pattern = {
        "source": ["aws.autoscaling"],
        "detail-type": ["EC2 Instance Launch Successful"],
        "detail": {"AutoScalingGroupName": [asg_name]},
    }
    events.put_rule(Name=rule_name, EventPattern=json.dumps(correct_pattern), State="ENABLED")

    # scale back to 0 so the next scale-out is a fresh, observable launch event
    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=0, HonorCooldown=False
    )
    _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]["Instances"],
        lambda instances: len(instances) == 0,
        timeout_s=180,
        interval_s=5.0,
        description="ASG instance terminated before the positive-control relaunch",
    )
    # drain any stray messages (e.g. a delayed EventBridge retry) so the next
    # poll can only observe the fresh positive-control launch event
    while True:
        stray = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = stray.get("Messages", [])
        if not msgs:
            break
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    # --- positive control: pattern is now correct; relaunch and observe delivery ---
    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=1, HonorCooldown=False
    )
    delivered = _poll_for_message(sqs, queue_url, asg_name, timeout_s=120.0)
    assert delivered is not None, (
        "event still not delivered after correcting the rule's event pattern -- "
        "positive control failed"
    )
    assert delivered["detail-type"] == "EC2 Instance Launch Successful", (
        f"expected the delivered event's detail-type to be "
        f"'EC2 Instance Launch Successful', got {delivered['detail-type']!r}"
    )


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


def _poll_for_message(sqs, queue_url, asg_name, timeout_s: float) -> dict[str, Any] | None:
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
    return None


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
