"""e2e-schedule-group-cascade-cleanup-stops-invocations."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-schedule-group-cascade-cleanup-stops-invocations"
GROUP = "e2e"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Deleting a schedule group cascades to its schedules and stops future invocations."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    group_name = ctx.unique_name("sim2real-sched-grp-")
    scheduler.create_schedule_group(
        Name=group_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
    ctx.on_cleanup(lambda: _safe_delete_group(scheduler, group_name))

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(
        ctx, [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]
    )

    schedule_name = ctx.unique_name("sim2real-sched-")
    marker = f"e2e-cascade-{ctx.unique_name('marker-')}"
    _create_schedule_with_retry(
        scheduler,
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": marker},
        State="ENABLED",
    )

    first = _poll_for_message(sqs, queue_url, timeout_s=100)
    assert first is not None, "schedule in group never delivered its first invocation"
    assert first["Body"] == marker
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=first["ReceiptHandle"])

    scheduler.delete_schedule_group(Name=group_name)

    # The group transitions ACTIVE -> DELETING while EventBridge Scheduler asynchronously
    # removes the schedules it contains, then disappears entirely.
    removed = _poll_until_removed(scheduler, group_name, timeout_s=90)
    assert removed, "schedule group was never fully removed after DeleteScheduleGroup"

    try:
        scheduler.get_schedule(Name=schedule_name, GroupName=group_name)
        raise AssertionError("member schedule still exists after its group was cascade-deleted")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for the deleted member schedule, "
            f"got {exc.response['Error']['Code']}"
        )
        expected_message = f"Schedule group {group_name} does not exist."
        assert exc.response["Error"]["Message"] == expected_message, (
            f"expected message {expected_message!r}, got {exc.response['Error']['Message']!r}"
        )

    # Dispatches committed before the cascade converged can still land after the group reads
    # as gone; retire them by draining until a quiet span longer than one rate(1 minute)
    # period (7 consecutive empty 10s receives) before the strict window.
    _drain_to_quiet(sqs, queue_url, timeout_s=240, consecutive_empty=7)

    stray = _poll_for_message(sqs, queue_url, timeout_s=80)
    assert stray is None, "queue received an invocation after its schedule group was deleted"


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"), tags={"sim2real:managed": "true"}
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _safe_delete_group(scheduler, name):
    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_removed(scheduler, group_name, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            scheduler.get_schedule_group(Name=group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        time.sleep(5)
    return False


def _drain_to_quiet(sqs, queue_url, timeout_s, consecutive_empty=2):
    deadline = time.monotonic() + timeout_s
    empties = 0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        messages = resp.get("Messages", [])
        if not messages:
            empties += 1
            if empties >= consecutive_empty:
                return
            continue
        empties = 0
        for m in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    raise AssertionError(f"queue never went quiet within {timeout_s}s after the group was deleted")


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
