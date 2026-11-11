"""schedule-disabled-state-suppresses-invocation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-disabled-state-suppresses-invocation"
GROUP = "server-side"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A DISABLED rate(2 minutes) schedule delivers nothing to its SQS target across a full
    cadence tick, and the same schedule delivers once re-enabled (positive control)."""
    scheduler = ctx.client("scheduler")
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, [queue_arn])

    name = ctx.unique_name("sim2real-sched-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=name,
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    # Poll well past one cadence tick (120s) while DISABLED; nothing must arrive.
    deadline = time.monotonic() + 150.0
    while time.monotonic() < deadline:
        leaked = _receive_all(ctx, queue_url)
        assert leaked == [], f"DISABLED schedule delivered a message: expected none, got {leaked!r}"
        time.sleep(2)

    # positive control: the SAME schedule, once ENABLED, does deliver.
    scheduler.update_schedule(
        Name=name,
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    messages = _poll_until(
        lambda: _receive_all(ctx, queue_url),
        lambda msgs: len(msgs) >= 1,
        timeout_s=_capped(ctx, 150.0),
        interval_s=2.0,
    )
    assert len(messages) >= 1, f"expected re-enabled schedule to deliver >=1 message, got {len(messages)}"


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_all(ctx, queue_url):
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    msgs = resp.get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return msgs


def _capped(ctx, timeout_s):
    """A poll's timeout, bounded by the runner's remaining time less 5 s so it fails with its own message."""
    left = ctx.time_left()
    return timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
