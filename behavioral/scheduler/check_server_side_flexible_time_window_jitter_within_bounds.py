"""server-side-flexible-time-window-jitter-within-bounds."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-flexible-time-window-jitter-within-bounds"
GROUP = "server-side"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-flexible-time-windows.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With FlexibleTimeWindow Mode=FLEXIBLE, the server-chosen invocation time
    for a one-time schedule falls within [nominal, nominal + MaximumWindowInMinutes],
    never before the nominal fire time and never past the declared window."""
    scheduler = ctx.client("scheduler")
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, [queue_arn])

    window_minutes = 2
    lead_minutes = 1
    nominal = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=lead_minutes)
    nominal_expr = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"

    name = ctx.unique_name("sim2real-sched-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=name,
        ScheduleExpression=nominal_expr,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": window_minutes},
        State="ENABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    nominal_epoch_ms = int(nominal.timestamp() * 1000)
    window_end_epoch_ms = nominal_epoch_ms + window_minutes * 60 * 1000

    timeout_s = lead_minutes * 60 + window_minutes * 60 + 60.0
    sent_ms = _wait_for_message_sent_timestamp(ctx, queue_url, timeout_s=timeout_s)

    # tolerate a few seconds of clock/propagation slack at each boundary
    slack_ms = 15_000
    assert sent_ms >= nominal_epoch_ms - slack_ms, (
        f"invocation fired before its nominal time: sent={sent_ms} nominal={nominal_epoch_ms}"
    )
    assert sent_ms <= window_end_epoch_ms + slack_ms, (
        f"invocation fired after its flexible window closed: "
        f"sent={sent_ms} window_end={window_end_epoch_ms}"
    )


_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _wait_for_message_sent_timestamp(ctx, queue_url, timeout_s):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=15,
            AttributeNames=["SentTimestamp"],
        )
        msgs = resp.get("Messages", [])
        if msgs:
            m = msgs[0]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            return int(m["Attributes"]["SentTimestamp"])
    raise AssertionError(f"no invocation observed within {timeout_s}s")


def _create_scheduler_role(ctx, allowed_queue_arns):
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
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": list(allowed_queue_arns)}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    """IAM role trust is eventually consistent; retry CreateSchedule briefly."""
    last_exc = None
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as e:
            last_exc = e
            if e.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
