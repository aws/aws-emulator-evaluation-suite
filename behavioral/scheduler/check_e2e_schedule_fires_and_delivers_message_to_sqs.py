"""e2e-schedule-fires-and-delivers-message-to-sqs."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-schedule-fires-and-delivers-message-to-sqs"
GROUP = "e2e"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A recurring EventBridge Scheduler schedule delivers its configured Input payload
    verbatim to an SQS target via ReceiveMessage, and DeleteSchedule stops further
    deliveries within the next scheduled window."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_arn = _create_scheduler_role(ctx, [queue_arn])

    name = ctx.unique_name("sim2real-sched-")
    marker = ctx.unique_name("marker-")
    payload = json.dumps({"marker": marker})
    _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": payload},
    )
    ctx.on_cleanup(lambda: _safe_ignore_not_found(lambda: scheduler.delete_schedule(Name=name)))

    body = _wait_for_message_body(sqs, queue_url, timeout_s=150.0)
    assert body == {"marker": marker}, f"unexpected payload delivered: {body}"

    scheduler.delete_schedule(Name=name)
    _assert_schedule_gone(scheduler, name)

    # Grace window: an invocation the scheduler had already committed at the instant
    # DeleteSchedule was called can still land a moment later. Drain it silently here
    # so it is never mistaken for a delivery that happened after deletion.
    _drain_messages(sqs, queue_url, timeout_s=15.0)

    # rate(1 minute) means the next scheduled fire (if any) would land within ~60s;
    # observe a window comfortably longer than one full period to confirm no further
    # delivery occurs once the schedule has been deleted.
    extra = _drain_messages(sqs, queue_url, timeout_s=90.0)
    assert extra == [], f"message delivered after DeleteSchedule: {extra}"


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
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


def _assert_schedule_gone(scheduler, name: str) -> None:
    try:
        scheduler.get_schedule(Name=name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from GetSchedule after DeleteSchedule, got {code}"
        )
        message = exc.response["Error"]["Message"]
        assert message == f"Schedule {name} does not exist.", (
            f"unexpected GetSchedule message after DeleteSchedule: {message!r}"
        )
    else:
        raise AssertionError(f"schedule {name} still visible via GetSchedule after DeleteSchedule")


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
