"""e2e-schedule-to-sqs-fire-and-receive."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-schedule-to-sqs-fire-and-receive"
GROUP = "e2e"
SERVICES = ["scheduler"]


_DRAIN_TIMEOUT_S = 20
# The minimum for proving a rate(1 minute) timer actually stopped: two full cadence periods plus
# Scheduler's own delivery slack. A shorter window reports a correct but slower target as blocked.
_QUIET_WINDOW_TIMEOUT_S = 150


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule targeting SQS delivers Input, then stops delivering once deleted."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(
        ctx,
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    )

    schedule_name = ctx.unique_name("sim2real-sched-")
    marker = f"e2e-fire-{ctx.unique_name('marker-')}"
    _create_schedule_with_retry(
        scheduler,
        Name=schedule_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": marker},
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: _safe_delete_schedule(scheduler, schedule_name))

    first = _poll_for_message(sqs, queue_url, timeout_s=90)
    assert first is not None, "schedule never delivered its first invocation to SQS"
    assert first["Body"] == marker, (
        f"delivered body {first['Body']!r} did not match the configured Input {marker!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=first["ReceiptHandle"])

    scheduler.delete_schedule(Name=schedule_name)
    code, message = _error(lambda: scheduler.get_schedule(Name=schedule_name))
    assert code == "ResourceNotFoundException", (
        f"schedule {schedule_name} still exists after delete_schedule (got {code!r})"
    )
    assert message == f"Schedule {schedule_name} does not exist.", (
        f"unexpected not-found message: {message!r}"
    )

    # Retire anything Scheduler had already dispatched before the delete landed, so an
    # in-flight message racing the delete is never mistaken for a post-delete stray.
    _drain_to_empty(sqs, queue_url, timeout_s=_DRAIN_TIMEOUT_S)

    stray = _poll_for_message(sqs, queue_url, timeout_s=_QUIET_WINDOW_TIMEOUT_S)
    assert stray is None, f"queue received a message after the schedule was deleted: {stray!r}"

    depth = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", (
        f"queue depth is {depth!r} after the {_QUIET_WINDOW_TIMEOUT_S}s quiet window, not 0 -- "
        f"the timer did not fully stop"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}


def _error(fn):
    """The AWS error (code, message) a call raised. Raises if the call unexpectedly SUCCEEDS, so a
    success can never be confused with a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail but succeeded")


def _drain_to_empty(sqs, queue_url, *, timeout_s, consecutive_empty=2):
    """Drain until `consecutive_empty` receives come back empty."""
    empties = 0
    deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout_s)
    while datetime.now(timezone.utc) < deadline and empties < consecutive_empty:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        if not messages:
            empties += 1
            continue
        empties = 0
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
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


def _create_schedule_with_retry(scheduler, retries=8, delay=3, **kwargs):
    """IAM role trust is eventually consistent; CreateSchedule validates it synchronously."""
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
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=min(10, remaining)
        )
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
