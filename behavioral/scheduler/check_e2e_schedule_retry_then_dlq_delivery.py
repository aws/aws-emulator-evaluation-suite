"""e2e-schedule-retry-then-dlq-delivery."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-schedule-retry-then-dlq-delivery"
GROUP = "e2e"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule whose target invocation is denied dead-letters the event (ERROR_CODE AccessDenied)
    and never reaches the target, while an identically-timed permitted schedule delivers."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")
    ctx.client("iam")

    main_url, main_arn = _create_queue(ctx)
    dlq_url, dlq_arn = _create_queue(ctx)
    control_url, control_arn = _create_queue(ctx)

    # The single broken thing: the role can deliver to the DLQ and to the control queue, but
    # has no permission on the main target queue, so every invocation of the main target fails
    # with an access-denied error while the control schedule below still delivers.
    role_arn = _create_scheduler_role(
        ctx,
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": [dlq_arn, control_arn]}],
    )

    schedule_name = ctx.unique_name("sim2real-sched-")
    control_name = ctx.unique_name("sim2real-sched-ctrl-")
    marker = f"e2e-dlq-{ctx.unique_name('marker-')}"
    control_marker = f"e2e-ctrl-{ctx.unique_name('marker-')}"
    fire_dt = datetime.now(timezone.utc) + timedelta(minutes=2)
    at_expr = f"at({fire_dt.strftime('%Y-%m-%dT%H:%M:%S')})"
    resp = _create_schedule_with_retry(
        scheduler,
        Name=schedule_name,
        ScheduleExpression=at_expr,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": main_arn,
            "RoleArn": role_arn,
            "Input": marker,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq_arn},
        },
        State="ENABLED",
    )
    schedule_arn = resp["ScheduleArn"]
    ctx.on_cleanup(lambda: _safe_delete_schedule(scheduler, schedule_name))
    _create_schedule_with_retry(
        scheduler,
        Name=control_name,
        ScheduleExpression=at_expr,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": control_arn,
            "RoleArn": role_arn,
            "Input": control_marker,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        },
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: _safe_delete_schedule(scheduler, control_name))

    poll_timeout_s = int((fire_dt - datetime.now(timezone.utc)).total_seconds()) + 150

    # Positive control: rules out a scheduler that dead-letters every invocation regardless
    # of permission.
    control_msg = _poll_for_message(sqs, control_url, timeout_s=poll_timeout_s)
    assert control_msg is not None, (
        "permitted control schedule never delivered -- can't attribute the denied leg's DLQ "
        "event to the missing permission rather than a scheduler that dead-letters everything"
    )
    assert control_msg["Body"] == control_marker, f"control delivery carried the wrong body: {control_msg['Body']!r}"

    dead_letter = _poll_for_message(sqs, dlq_url, timeout_s=poll_timeout_s)
    assert dead_letter is not None, "failed invocation never reached the configured DLQ"

    payload = json.loads(dead_letter["Body"])
    assert payload["MessageBody"] == marker
    assert payload["QueueUrl"] == main_url

    attrs = {k: v.get("StringValue") for k, v in dead_letter.get("MessageAttributes", {}).items()}
    assert attrs.get("ERROR_CODE") == "AccessDenied", (
        f"dead-letter ERROR_CODE was {attrs.get('ERROR_CODE')!r}, expected 'AccessDenied'; "
        f"all attributes were {attrs!r}"
    )
    assert attrs.get("SCHEDULE_ARN") == schedule_arn, (
        f"dead-letter SCHEDULE_ARN was {attrs.get('SCHEDULE_ARN')!r}, expected the failing "
        f"schedule's own ARN {schedule_arn!r}"
    )
    assert attrs.get("TARGET_ARN") == main_arn, (
        f"dead-letter TARGET_ARN was {attrs.get('TARGET_ARN')!r}, expected the denied target "
        f"queue's ARN {main_arn!r}"
    )

    # The main queue never actually received the invocation -- delivery genuinely failed,
    # it wasn't silently accepted and also mirrored to the DLQ.
    main_msg = sqs.receive_message(QueueUrl=main_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
    assert "Messages" not in main_msg, "target queue unexpectedly received the denied invocation"


_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_scheduler_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_with_retry(scheduler, retries=10, delay=3, **kwargs):
    last_exc = None
    for _ in range(retries):
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    raise last_exc


def _safe_delete_schedule(scheduler, name):
    try:
        scheduler.delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_for_message(sqs, queue_url, timeout_s):
    deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout_s)
    while datetime.now(timezone.utc) < deadline:
        remaining = max(1, int((deadline - datetime.now(timezone.utc)).total_seconds()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=min(10, remaining),
            MessageAttributeNames=["All"],
        )
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
