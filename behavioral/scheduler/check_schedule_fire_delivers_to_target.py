"""schedule-fire-delivers-to-target."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-fire-delivers-to-target"
GROUP = "deploy"
SERVICES = ["scheduler"]

# Provisions the schedule directly through the Scheduler API and verifies it actually fires
# and delivers, not merely reaches ACTIVE.


# timing:real-time — schedule: 50 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Schedule with a rate() expression and an SQS target actually fires and
    delivers a message to the queue, not merely reaches ENABLED/ACTIVE state."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    queue_name = ctx.unique_name("sim2real-behav-schedq-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_if_present(sqs, queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-schedrole-")
    assume_policy = json.dumps(
        {
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
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=assume_policy,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_if_present(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="AllowSendToQueue",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_if_present(iam, role_name, "AllowSendToQueue"))
    _wait_role_visible(iam, role_name)

    schedule_name = ctx.unique_name("sim2real-behav-sched-")
    # A freshly-created role's trust policy can take a few seconds to propagate to the
    # scheduler service; retry the actual create call on that specific rejection rather
    # than waiting out a fixed, unverified grace period.
    _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=schedule_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": "hello-from-scheduler"}),
        },
    )
    schedule_deleted = False

    def _cleanup_schedule() -> None:
        if not schedule_deleted:
            _delete_schedule_if_present(scheduler, schedule_name)

    ctx.on_cleanup(_cleanup_schedule)

    # Confirm the schedule is really ENABLED with the expected target, not just that
    # CreateSchedule returned 200.
    schedule = scheduler.get_schedule(Name=schedule_name)
    assert schedule["State"] == "ENABLED"
    assert schedule["Target"]["Arn"] == queue_arn

    # Poll for the schedule to actually fire (rate(1 minute)) and deliver to the queue.
    deadline = time.monotonic() + 240
    delivered: dict[str, Any] | None = None
    while time.monotonic() < deadline and delivered is None:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=15
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            if body.get("marker") == "hello-from-scheduler":
                delivered = body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    assert delivered is not None, "schedule never delivered a message to the target queue"

    # Explicitly delete the schedule and confirm the deletion actually took effect.
    scheduler.delete_schedule(Name=schedule_name)
    schedule_deleted = True
    try:
        scheduler.get_schedule(Name=schedule_name)
        raise AssertionError("schedule still exists after DeleteSchedule")
    except scheduler.exceptions.ResourceNotFoundException as exc:
        got_message = exc.response["Error"].get("Message")
        expected = f"Schedule {schedule_name} does not exist."
        assert got_message == expected, f"expected {expected!r}, got {got_message!r}"

    sqs.delete_queue(QueueUrl=queue_url)


def _wait_role_visible(iam, role_name: str, timeout_s: int = 30) -> None:
    """IAM is eventually consistent; poll get_role until it is visible."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except iam.exceptions.NoSuchEntityException:
            time.sleep(2)
    raise AssertionError(f"role {role_name} never became visible within {timeout_s}s")


def _create_schedule_with_role_propagation_retry(
    scheduler, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs
) -> None:
    """CreateSchedule can reject a just-minted execution role with a ValidationException
    until its trust policy has propagated to the scheduler service. Retry the create for
    a bounded window on that specific rejection rather than guessing a fixed delay."""
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


def _delete_queue_if_present(sqs, queue_url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=queue_url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _delete_role_policy_if_present(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_if_present(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_schedule_if_present(scheduler, schedule_name: str) -> None:
    try:
        scheduler.delete_schedule(Name=schedule_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

