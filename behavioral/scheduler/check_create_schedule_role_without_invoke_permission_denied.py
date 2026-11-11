"""create-schedule-role-without-invoke-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-role-without-invoke-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["scheduler"]

_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


# timing:real-time — schedule: 60 s
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """CreateSchedule accepts a role lacking sqs:SendMessage on the target queue, but its invocations never reach that
    queue and land in the schedule's dead-letter queue, while a sibling schedule whose role has permission delivers.
    """
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    # --- denied path: role can be assumed by scheduler, but cannot SendMessage
    # to the target queue -- only to the DLQ.
    target_queue = _create_queue(ctx)
    dlq_queue = _create_queue(ctx)
    denied_role_arn = _create_scheduler_role(ctx, dlq_queue["arn"])

    # --- positive control: role has SendMessage on its own target queue.
    good_target = _create_queue(ctx)
    good_role_arn = _create_scheduler_role(ctx, good_target["arn"])

    denied_schedule = ctx.unique_name("sim2real-sched-noperm-")
    create_resp = _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=denied_schedule,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target_queue["arn"],
            "RoleArn": denied_role_arn,
            "DeadLetterConfig": {"Arn": dlq_queue["arn"]},
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        },
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=denied_schedule))
    # CreateSchedule accepted the request despite the role having no permission
    # to invoke the target -- that gap is only enforced at invocation time.
    assert create_resp["ScheduleArn"]

    good_schedule = ctx.unique_name("sim2real-sched-withperm-")
    _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=good_schedule,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": good_target["arn"], "RoleArn": good_role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_schedule))

    dlq_messages, good_messages = _poll_two_queues(
        sqs, dlq_queue["url"], good_target["url"], timeout_s=210.0
    )
    assert len(dlq_messages) >= 1, "dead-letter queue never received the failed-invocation event"
    assert len(good_messages) >= 1, "positive-control target never received the scheduled message"

    leftover = sqs.receive_message(QueueUrl=target_queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=1)
    assert not leftover.get("Messages"), "target lacking permission unexpectedly received a message"


def _create_queue(ctx: Any) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_scheduler_role(ctx: Any, resource_arn: str) -> str:
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
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": resource_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_with_role_propagation_retry(
    scheduler: Any, timeout_s: float = 60.0, interval_s: float = 3.0, **kwargs: Any
) -> dict[str, Any]:
    """CreateSchedule validates the target role by assuming it, and freshly-created IAM
    roles/policies are not instantly visible to every AWS service that references them by
    ARN (documented eventual consistency). Retry the create within a bound rather than
    guessing a fixed settle time."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if (
                error.get("Code") == "ValidationException"
                and "execution role" in error.get("Message", "")
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _poll_two_queues(sqs, url_a: str, url_b: str, timeout_s: float = 210.0, interval_s: float = 10.0):
    """Poll both queues concurrently (rather than sequentially) until each has at
    least one message or the deadline passes -- both schedules fire on independent
    AWS-side rate() timers, so there is no reason to wait for them serially."""
    deadline = time.monotonic() + timeout_s
    got_a: list[dict] = []
    got_b: list[dict] = []
    while time.monotonic() < deadline and (not got_a or not got_b):
        if not got_a:
            resp = sqs.receive_message(QueueUrl=url_a, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                got_a.append(msg)
                sqs.delete_message(QueueUrl=url_a, ReceiptHandle=msg["ReceiptHandle"])
        if not got_b:
            resp = sqs.receive_message(QueueUrl=url_b, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                got_b.append(msg)
                sqs.delete_message(QueueUrl=url_b, ReceiptHandle=msg["ReceiptHandle"])
        if not got_a or not got_b:
            time.sleep(interval_s)
    return got_a, got_b


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
