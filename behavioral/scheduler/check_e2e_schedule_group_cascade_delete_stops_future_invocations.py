"""e2e-schedule-group-cascade-delete-stops-future-invocations."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-schedule-group-cascade-delete-stops-future-invocations"
GROUP = "e2e"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A recurring schedule inside a schedule group is observed firing, then cascading
    DeleteScheduleGroup removes the group and its schedule and no further messages
    arrive within the next scheduled window."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_arn = _create_scheduler_role(ctx, [queue_arn])

    group_name = ctx.unique_name("sim2real-schedgrp-")
    scheduler.create_schedule_group(Name=group_name)
    ctx.on_cleanup(
        lambda: _safe_ignore_not_found(lambda: scheduler.delete_schedule_group(Name=group_name))
    )

    sched_name = ctx.unique_name("sim2real-sched-")
    _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=sched_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": json.dumps({"group": group_name})},
    )

    body = _wait_for_message_body(sqs, queue_url, timeout_s=150.0)
    assert body == {"group": group_name}, f"unexpected payload delivered: {body}"

    scheduler.delete_schedule_group(Name=group_name)

    # DeleteScheduleGroup cascades asynchronously: poll until the contained schedule
    # itself has actually been removed before checking for further deliveries.
    _poll_schedule_gone(scheduler, sched_name, group_name, timeout_s=90.0)
    assert _error(lambda: scheduler.get_schedule_group(Name=group_name)) == (
        "ResourceNotFoundException",
        f"Schedule group {group_name} does not exist.",
    ), "schedule group still exists after cascade delete completed"

    # A dispatch already committed before the cascade converged can still land after both
    # GetSchedule and GetScheduleGroup already read as gone. Drain to two consecutive empty receives first,
    # so a pre-committed straggler is retired rather than mistaken for a still-firing
    # schedule, then start the strict window from a queue that is actually quiet.
    _drain_to_quiet(sqs, queue_url, timeout_s=90.0)

    # rate(1 minute) means the next scheduled fire (if any) would land within ~60s;
    # observe a window comfortably longer than one full period, starting only once the
    # queue is quiet, to confirm the cascade delete actually stopped future invocations.
    extra = _drain_messages(sqs, queue_url, timeout_s=90.0)
    assert extra == [], f"message delivered after schedule-group cascade delete: {extra}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a
    target that still serves the deleted resource never reads as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_schedule_with_role_propagation_retry(
    scheduler, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs
) -> None:
    """Freshly-created IAM roles/policies are eventually consistent: CreateSchedule can
    reject a just-minted execution role with a ValidationException until the role has
    propagated. Retry the create for a bounded window rather than treating this as a
    hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            scheduler.create_schedule(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "execution role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_scheduler_role(ctx, queue_arns: list[str]) -> str:
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-sched-sqs-send"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arns}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _poll_schedule_gone(
    scheduler, name: str, group_name: str, timeout_s: float = 90.0, interval_s: float = 5.0
) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            scheduler.get_schedule(Name=name, GroupName=group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("schedule still exists after schedule-group cascade delete completed")


def _wait_for_message_body(
    sqs, queue_url: str, timeout_s: float = 150.0, interval_s: float = 5.0
) -> Any:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        if messages:
            msg = messages[0]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                return json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                return msg["Body"]
        time.sleep(max(0.0, interval_s - 5.0))
    raise AssertionError(f"no message delivered to {queue_url} within {timeout_s}s")


def _drain_to_quiet(sqs, queue_url: str, timeout_s: float, consecutive_empty: int = 2) -> None:
    """Drain until `consecutive_empty` receives in a row come back empty, retiring anything
    dispatched before the cascade delete fully converged. Never raises -- absence of quiet
    within the budget is caught by the strict window that follows, not here."""
    deadline = time.monotonic() + timeout_s
    empties = 0
    while time.monotonic() < deadline and empties < consecutive_empty:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        if not messages:
            empties += 1
            continue
        empties = 0
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _drain_messages(sqs, queue_url: str, timeout_s: float, interval_s: float = 5.0) -> list[Any]:
    deadline = time.monotonic() + timeout_s
    out: list[Any] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        time.sleep(max(0.0, interval_s - 5.0))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
