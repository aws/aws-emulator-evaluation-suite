"""server-side-schedule-invocation-uses-declared-role-arn."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "server-side-schedule-invocation-uses-declared-role-arn"
GROUP = "server-side"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 15 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Invocation permissions follow each schedule's RoleArn, not the creating caller: from the same
    caller, a schedule whose role lacks sqs:SendMessage dead-letters while a permitted sibling
    delivers."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    target_allow = _create_sqs_queue(ctx, "sim2real-behav-sched-role-allow-tgt-")
    target_deny = _create_sqs_queue(ctx, "sim2real-behav-sched-role-deny-tgt-")
    dlq = _create_sqs_queue(ctx, "sim2real-behav-sched-role-dlq-")

    role_allow = _create_scheduler_role(
        ctx,
        "sim2real-behav-sched-role-allow-",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target_allow["arn"]}],
    )
    role_deny = _create_scheduler_role(
        ctx,
        "sim2real-behav-sched-role-deny-",
        # This role can reach the DLQ but is deliberately NOT granted sqs:SendMessage
        # on target_deny -- the same caller creates both schedules below.
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq["arn"]}],
    )

    marker_allow = ctx.unique_name("sim2real-behav-role-allow-marker-")
    marker_deny = ctx.unique_name("sim2real-behav-role-deny-marker-")
    fire_in_s = 15

    name_allow = ctx.unique_name("sim2real-behav-sched-role-allow-")
    _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=name_allow,
        fire_in_s=fire_in_s,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": target_allow["arn"], "RoleArn": role_allow, "Input": marker_allow},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name_allow))

    name_deny = ctx.unique_name("sim2real-behav-sched-role-deny-")
    deny_resp = _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=name_deny,
        fire_in_s=fire_in_s,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target_deny["arn"],
            "RoleArn": role_deny,
            "Input": marker_deny,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name_deny))
    deny_schedule_arn = deny_resp["ScheduleArn"]

    deadline = time.monotonic() + _budget_s(ctx, fire_in_s + 150)
    allow_msg = None
    deny_msg = None
    while time.monotonic() < deadline and (allow_msg is None or deny_msg is None):
        if allow_msg is None:
            r = sqs.receive_message(QueueUrl=target_allow["url"], MaxNumberOfMessages=1, WaitTimeSeconds=1)
            msgs = r.get("Messages", [])
            if msgs:
                allow_msg = msgs[0]
        if deny_msg is None:
            r = sqs.receive_message(
                QueueUrl=dlq["url"], MaxNumberOfMessages=1, WaitTimeSeconds=1, MessageAttributeNames=["All"]
            )
            msgs = r.get("Messages", [])
            if msgs:
                deny_msg = msgs[0]

    if (allow_msg is None or deny_msg is None) and _budget_spent(ctx):
        raise TimeoutError("both schedules' deliveries: the run budget ended first; not graded")
    if allow_msg is None:
        raise AssertionError("schedule with a permitted role never invoked its target")
    if deny_msg is None:
        raise AssertionError("schedule with a denied role never routed to its DLQ")
    sqs.delete_message(QueueUrl=target_allow["url"], ReceiptHandle=allow_msg["ReceiptHandle"])
    sqs.delete_message(QueueUrl=dlq["url"], ReceiptHandle=deny_msg["ReceiptHandle"])

    assert allow_msg["Body"] == marker_allow, (
        f"expected the permitted role's target to receive {marker_allow!r}, got {allow_msg['Body']!r}"
    )
    dlq_schedule_arn = deny_msg["MessageAttributes"]["SCHEDULE_ARN"]["StringValue"]
    assert dlq_schedule_arn == deny_schedule_arn, (
        f"expected the DLQ message to attribute the failure to {deny_schedule_arn!r}, got {dlq_schedule_arn!r}"
    )

    leftover = sqs.receive_message(QueueUrl=target_deny["url"], MaxNumberOfMessages=5, WaitTimeSeconds=2)
    leftover_messages = leftover.get("Messages", [])
    assert not leftover_messages, (
        f"expected the denied role's own target to receive nothing, got {len(leftover_messages)} message(s)"
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


def _create_schedule_with_role_propagation_retry(scheduler, *, fire_in_s, deadline_s: float = 30.0, **kwargs):
    """IAM role/policy propagation to other AWS services can lag CreateRole/PutRolePolicy
    by several seconds, and Scheduler validates that it can assume the target role at
    CreateSchedule time. Retry on that specific, named failure until the deadline elapses;
    any other error is a real defect and must not be retried away. Each attempt anchors its
    at() fire_in_s seconds after the attempt, so a retry never schedules a past time."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return scheduler.create_schedule(ScheduleExpression=_at_expression(fire_in_s)[0], **kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code != "ValidationException" or "assume" not in message.lower():
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_sqs_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn, "name": name}


def _create_scheduler_role(ctx, prefix: str, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name(prefix)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _at_expression(seconds_from_now: int) -> tuple[str, datetime]:
    when = datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)
    return f"at({when.strftime('%Y-%m-%dT%H:%M:%S')})", when


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
