"""elb-target-health-change-event-not-delivered-without-eventbridge-rule."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "elb-target-health-change-event-not-delivered-without-eventbridge-rule"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A forced state change of an alarm on a target group's UnHealthyHostCount is delivered nowhere
    without an EventBridge rule; after a matching rule and SQS target are added, the next change
    arrives."""
    vpc_id, subnet_ids, sg_id = _create_vpc_two_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    cw = ctx.client("cloudwatch")

    lb_name = _short_name(ctx, "sim2real-alb-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_delete_lb(elbv2, lb_arn))

    tg_name = _short_name(ctx, "sim2real-tg-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance"
    )["TargetGroups"][0]["TargetGroupArn"]
    elbv2.add_tags(ResourceArns=[tg_arn], Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    lb_suffix = lb_arn.split(":loadbalancer/")[1]
    tg_suffix = tg_arn.split(":")[-1]

    alarm_name = ctx.unique_name("sim2real-tg-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/ApplicationELB",
        MetricName="UnHealthyHostCount",
        Dimensions=[
            {"Name": "TargetGroup", "Value": tg_suffix},
            {"Name": "LoadBalancer", "Value": lb_suffix},
        ],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # Force the target-health alarm to transition deterministically instead of
    # waiting on a real health-check sweep. No EventBridge rule exists yet.
    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real forced ALARM"
    )
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0][
            "StateValue"
        ],
        lambda s: s == "ALARM",
        timeout_s=30.0,
        interval_s=2.0,
        description=f"alarm {alarm_name} reaches ALARM",
    )

    queue_url, queue_arn = _create_sqs_queue(ctx)
    _assert_no_matching_message(
        ctx,
        queue_url,
        lambda body: body.get("detail", {}).get("alarmName") == alarm_name,
        timeout_s=40.0,
    )

    # Positive control: wire a matching rule now and re-transition the SAME alarm.
    pattern = {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "detail": {"alarmName": [alarm_name]},
    }
    _create_rule_with_sqs_target(ctx, pattern, queue_url, queue_arn)

    # The rule's queue policy and target can take seconds to take effect, so each attempt
    # drives a new ALARM -> OK transition until the matching event arrives.
    event = None
    attempts_deadline = time.monotonic() + 120.0
    while event is None and time.monotonic() < attempts_deadline:
        cw.set_alarm_state(
            AlarmName=alarm_name, StateValue="OK", StateReason="sim2real forced OK"
        )
        event = _receive_matching_message(
            ctx,
            queue_url,
            lambda body: body.get("detail", {}).get("alarmName") == alarm_name,
            timeout_s=25.0,
        )
        if event is None:
            cw.set_alarm_state(
                AlarmName=alarm_name,
                StateValue="ALARM",
                StateReason="sim2real retry ALARM",
            )
            _poll_until(
                lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0][
                    "StateValue"
                ],
                lambda s: s == "ALARM",
                timeout_s=15.0,
                interval_s=2.0,
                description=f"alarm {alarm_name} reaches ALARM before retrying delivery",
            )
    if event is None:
        raise AssertionError(
            f"expected message for alarm {alarm_name} never received on {queue_url} "
            "despite retrying the OK transition for 120s"
        )
    assert event["detail-type"] == "CloudWatch Alarm State Change", (
        f"expected detail-type 'CloudWatch Alarm State Change', got {event['detail-type']!r}"
    )
    assert event["detail"]["state"]["value"] == "OK", (
        f"expected delivered state OK, got {event['detail']['state']['value']!r}"
    )
    assert event["detail"]["previousState"]["value"] == "ALARM", (
        f"expected delivered previousState ALARM, got {event['detail']['previousState']['value']!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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


def _retry_delete(fn, *, timeout_s: float = 300.0) -> None:
    """Retry a VPC-member delete while ENIs released by the ALB drain away."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _create_vpc_two_subnets(ctx) -> tuple[str, list[str], str]:
    """Create a VPC with subnets in two AZs and a security group; register their cleanup."""
    ec2 = ctx.client("ec2")

    def tag_spec(kind: str) -> list[dict]:
        return [{"ResourceType": kind, "Tags": [{"Key": "sim2real", "Value": "true"}]}]

    vpc_id = ec2.create_vpc(CidrBlock="10.41.0.0/16", TagSpecifications=tag_spec("vpc"))[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
        if z["State"] == "available"
    ]
    subnet_ids: list[str] = []
    for i, zone in enumerate(zones[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.41.{i + 1}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=tag_spec("subnet"),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid))
        )
        subnet_ids.append(subnet_id)
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-alb-sg-"),
        Description="sim2real alb sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec("security-group"),
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id))
    )
    return vpc_id, subnet_ids, sg_id


def _short_name(ctx, prefix: str, max_len: int = 32) -> str:
    raw = ctx.unique_name(prefix)
    name = raw[-max_len:] if len(raw) > max_len else raw
    return name.lstrip("-")


def _safe_delete_lb(elbv2, lb_arn: str) -> None:
    """Delete the load balancer, retrying ResourceInUse every 2 s for up to 60 s; anything else
    raises."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_sqs_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags={"sim2real": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _allow_eventbridge_to_send(
    ctx, queue_url: str, queue_arn: str, rule_arn: str
) -> None:
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
    sqs.set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _create_rule_with_sqs_target(
    ctx, pattern: dict, queue_url: str, queue_arn: str
) -> str:
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


def _receive_matching_message(
    ctx, queue_url: str, predicate, timeout_s: float = 180.0
) -> dict | None:
    """Return the first message matching `predicate` within `timeout_s`, or None."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body, dict) and predicate(body):
                return body
    return None


def _assert_no_matching_message(
    ctx, queue_url: str, predicate, timeout_s: float = 40.0
) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body, dict) and predicate(body):
                raise AssertionError(
                    f"unexpected event delivered with no matching rule wired: {body!r}"
                )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
