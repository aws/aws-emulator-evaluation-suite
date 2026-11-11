"""update-schedule-on-deleted-group-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schedule-on-deleted-group-blocked"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """Deleting a ScheduleGroup cascades to its schedules, so UpdateSchedule on a schedule of the
    deleted group is rejected; a schedule in a live group still updates (positive control)."""
    scheduler = ctx.client("scheduler")
    queue = _create_target_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue["arn"])

    group_name = ctx.unique_name("sim2real-sg-del-")
    scheduler.create_schedule_group(Name=group_name)
    ctx.on_cleanup(lambda: _best_effort_delete_group(scheduler, group_name))

    schedule_name = ctx.unique_name("sim2real-sched-ingroup-")
    _create_schedule_retrying(
        scheduler,
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue["arn"], "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: _best_effort_delete_schedule(scheduler, schedule_name, group_name))

    scheduler.delete_schedule_group(Name=group_name)
    _wait_group_deleted(scheduler, group_name, timeout_s=120.0)

    err = _error(
        lambda: scheduler.update_schedule(
            Name=schedule_name,
            GroupName=group_name,
            ScheduleExpression="rate(2 hours)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": queue["arn"], "RoleArn": role_arn},
        )
    )
    assert err.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {err.get('Code')}"
    )
    expected_update_message = f"Schedule group {group_name} does not exist."
    assert err.get("Message") == expected_update_message, (
        f"expected UpdateSchedule message {expected_update_message!r}, got {err.get('Message')!r}"
    )

    # the schedule itself must also be gone -- this is a cascading delete of the
    # group's contents, not merely the group container becoming unreachable.
    get_err = _error(lambda: scheduler.get_schedule(Name=schedule_name, GroupName=group_name))
    assert get_err.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetSchedule, got {get_err.get('Code')}"
    )
    expected_get_message = f"Schedule group {group_name} does not exist."
    assert get_err.get("Message") == expected_get_message, (
        f"expected GetSchedule message {expected_get_message!r}, got {get_err.get('Message')!r}"
    )

    # positive control: a schedule in a live (non-deleted) group can be updated.
    control_group = ctx.unique_name("sim2real-sg-live-")
    scheduler.create_schedule_group(Name=control_group)
    ctx.on_cleanup(lambda: scheduler.delete_schedule_group(Name=control_group))
    control_schedule = ctx.unique_name("sim2real-sched-live-")
    _create_schedule_retrying(
        scheduler,
        Name=control_schedule,
        GroupName=control_group,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue["arn"], "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=control_schedule, GroupName=control_group))
    update_resp = scheduler.update_schedule(
        Name=control_schedule,
        GroupName=control_group,
        ScheduleExpression="rate(2 hours)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue["arn"], "RoleArn": role_arn},
    )
    assert update_resp["ScheduleArn"]

    # independent read at the destination: the control schedule's update actually
    # landed, not merely that the mutating call itself returned without error.
    control_desc = scheduler.get_schedule(Name=control_schedule, GroupName=control_group)
    assert control_desc["ScheduleExpression"] == "rate(2 hours)", (
        f"expected rate(2 hours), got {control_desc['ScheduleExpression']}"
    )


def _error(fn):
    """The botocore Error dict (Code, Message) a call raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_target_queue(ctx: Any) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"))["QueueUrl"]
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": resource_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_retrying(scheduler, **kwargs):
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


def _wait_group_deleted(scheduler, group_name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            scheduler.get_schedule_group(Name=group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"schedule group {group_name} was not deleted within {timeout_s}s")


def _best_effort_delete_schedule(scheduler, name: str, group_name: str) -> None:
    try:
        scheduler.delete_schedule(Name=name, GroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete_group(scheduler, name: str) -> None:
    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
