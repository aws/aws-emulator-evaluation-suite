"""schedule-group-lifecycle-cascade-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-group-lifecycle-cascade-delete"
GROUP = "deploy"
SERVICES = ["scheduler"]

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A group with two schedules reads back ACTIVE/ENABLED; DeleteSchedule removes one, and
    DeleteScheduleGroup cascades to the group and its remaining schedule (Get -> NotFound)."""
    scheduler = ctx.client("scheduler")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    queue_name = ctx.unique_name("sim2real-behav-grpq-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_if_present(sqs, queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-grprole-")
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
    _wait_role_assumable(iam, role_name)

    group_name = ctx.unique_name("sim2real-behav-grp-")
    schedule_a = ctx.unique_name("sim2real-behav-sched-a-")
    schedule_b = ctx.unique_name("sim2real-behav-sched-b-")

    scheduler.create_schedule_group(
        Name=group_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
    group_deleted = False

    def _cleanup_group() -> None:
        if not group_deleted:
            _delete_group_if_present(scheduler, group_name)

    ctx.on_cleanup(_cleanup_group)

    group = scheduler.get_schedule_group(Name=group_name)
    assert group["State"] == "ACTIVE"

    target = {"Arn": queue_arn, "RoleArn": role_arn}
    for name in (schedule_a, schedule_b):
        _create_schedule_with_retry(
            scheduler,
            Name=name,
            GroupName=group_name,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Target=target,
        )

    schedule_a_deleted = False

    def _cleanup_schedule_a() -> None:
        if not schedule_a_deleted:
            _delete_schedule_if_present(scheduler, schedule_a, group_name)

    ctx.on_cleanup(_cleanup_schedule_a)

    for name in (schedule_a, schedule_b):
        schedule = scheduler.get_schedule(Name=name, GroupName=group_name)
        assert schedule["State"] == "ENABLED"
        assert schedule["GroupName"] == group_name

    scheduler.delete_schedule(Name=schedule_a, GroupName=group_name)
    schedule_a_deleted = True
    _assert_not_found(
        lambda: scheduler.get_schedule(Name=schedule_a, GroupName=group_name),
        f"Schedule {schedule_a} does not exist.",
        "schedule_a still exists after DeleteSchedule",
    )
    _assert_not_found(
        lambda: scheduler.delete_schedule(Name=schedule_a, GroupName=group_name),
        f"Schedule {schedule_a} does not exist.",
        "re-deleting schedule_a should fail, it no longer exists",
    )

    # Deleting the group cascades to removing the remaining schedule inside it.
    scheduler.delete_schedule_group(Name=group_name)
    group_deleted = True

    deadline = time.monotonic() + 120
    group_gone = False
    while time.monotonic() < deadline:
        try:
            state = scheduler.get_schedule_group(Name=group_name)["State"]
            if state != "DELETING":
                raise AssertionError(f"unexpected group state after delete: {state}")
        except scheduler.exceptions.ResourceNotFoundException:
            group_gone = True
            break
        time.sleep(2)
    assert group_gone, "schedule group was never actually removed"

    _assert_not_found(
        lambda: scheduler.get_schedule(Name=schedule_b, GroupName=group_name),
        f"Schedule group {group_name} does not exist.",
        "schedule_b still exists after DeleteScheduleGroup cascade",
    )
    _assert_not_found(
        lambda: scheduler.delete_schedule_group(Name=group_name),
        f"Schedule group {group_name} does not exist.",
        "re-deleting the schedule group should fail, it no longer exists",
    )


def _assert_not_found(fn, expected_message: str, on_success: str) -> None:
    """fn() must fail with ResourceNotFoundException carrying exactly expected_message;
    an unexpected SUCCESS raises with on_success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == "ResourceNotFoundException", f"unexpected error: {err!r}"
        assert err.get("Message") == expected_message, (
            f"ResourceNotFoundException message {err.get('Message')!r}, expected {expected_message!r}"
        )
        return
    raise AssertionError(on_success)


def _wait_role_assumable(iam, role_name: str, timeout_s: int = 30) -> None:
    """IAM is eventually consistent; poll get_role until the role itself is visible.
    Trust-policy propagation to the scheduler service is a separate, later gap handled
    by _create_schedule_with_retry's bounded retry, not by a blind sleep here."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except iam.exceptions.NoSuchEntityException:
            time.sleep(2)
    raise AssertionError(f"role {role_name} did not become visible within {timeout_s}s")


def _create_schedule_with_retry(scheduler, timeout_s: int = 60, **kwargs) -> None:
    """A freshly created IAM role is visible via GetRole before scheduler.amazonaws.com
    can assume it; retry CreateSchedule on the ValidationException that propagation gap
    produces until it succeeds or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            scheduler.create_schedule(**kwargs)
            return
        except scheduler.exceptions.ValidationException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


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


def _delete_schedule_if_present(scheduler, name: str, group_name: str) -> None:
    try:
        scheduler.delete_schedule(Name=name, GroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_group_if_present(scheduler, group_name: str) -> None:
    try:
        scheduler.delete_schedule_group(Name=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

