"""schedule-flexible-time-window-invocation-within-bounds."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-flexible-time-window-invocation-within-bounds"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]

_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_ROLE_PROPAGATION_TIMEOUT_S = 60


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-flexible-time-windows.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Mode=FLEXIBLE schedule invokes its target within [nominal, nominal + MaximumWindow],
    measured by the delivered message's SQS SentTimestamp, with small skew/delivery tolerances."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    target = _create_sqs_queue(ctx, "sim2real-behav-sched-flex-tgt-")
    role_arn = _create_scheduler_role(
        ctx,
        "sim2real-behav-sched-flex-role-",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target["arn"]}],
    )

    marker = ctx.unique_name("sim2real-behav-flex-marker-")
    schedule_name = ctx.unique_name("sim2real-behav-flex-sched-")
    max_window_minutes = 1
    at_expr, nominal = _at_expression(90)

    _create_schedule_retrying(
        scheduler,
        Name=schedule_name,
        ScheduleExpression=at_expr,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": max_window_minutes},
        State="ENABLED",
        Target={"Arn": target["arn"], "RoleArn": role_arn, "Input": marker},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name))

    described = scheduler.get_schedule(Name=schedule_name)
    assert described["FlexibleTimeWindow"]["Mode"] == "FLEXIBLE", (
        f"expected FlexibleTimeWindow.Mode='FLEXIBLE', got {described['FlexibleTimeWindow']!r}"
    )
    assert described["FlexibleTimeWindow"]["MaximumWindowInMinutes"] == max_window_minutes, (
        f"expected MaximumWindowInMinutes={max_window_minutes}, "
        f"got {described['FlexibleTimeWindow']!r}"
    )

    window_close = nominal + timedelta(minutes=max_window_minutes)
    deadline = time.monotonic() + max(30, (window_close - datetime.now(timezone.utc)).total_seconds() + 150)
    message = None
    while time.monotonic() < deadline and message is None:
        r = sqs.receive_message(
            QueueUrl=target["url"],
            MaxNumberOfMessages=1,
            WaitTimeSeconds=20,
            AttributeNames=["SentTimestamp"],
        )
        msgs = r.get("Messages", [])
        if msgs:
            message = msgs[0]
    if message is None:
        raise AssertionError("target never received the flexible-window invocation")
    sqs.delete_message(QueueUrl=target["url"], ReceiptHandle=message["ReceiptHandle"])
    assert message["Body"] == marker, f"expected body {marker!r}, got {message['Body']!r}"

    sent_ms = int(message["Attributes"]["SentTimestamp"])
    invoked_at = datetime.fromtimestamp(sent_ms / 1000.0, tz=timezone.utc)

    # Small tolerances absorb clock skew (before the window opens) and end-to-end
    # delivery overhead (after the window closes).
    clock_skew_tolerance = timedelta(seconds=5)
    delivery_overhead_tolerance = timedelta(seconds=30)
    assert invoked_at >= nominal - clock_skew_tolerance, (
        f"invoked at {invoked_at.isoformat()} before nominal {nominal.isoformat()}"
    )
    assert invoked_at <= window_close + delivery_overhead_tolerance, (
        f"invoked at {invoked_at.isoformat()} after window close {window_close.isoformat()}"
    )


def _create_sqs_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    url = sqs.create_queue(QueueName=name, tags=_MANAGED_TAGS)["QueueUrl"]
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
        Tags=_MANAGED_TAGS_KV,
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


def _create_schedule_retrying(scheduler, **kwargs) -> None:
    """CreateSchedule assumes the target role and IAM propagation is eventually consistent, so
    early attempts can fail with ValidationException; retry for a bounded window."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            scheduler.create_schedule(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _at_expression(seconds_from_now: int) -> tuple[str, datetime]:
    when = datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)
    return f"at({when.strftime('%Y-%m-%dT%H:%M:%S')})", when


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
