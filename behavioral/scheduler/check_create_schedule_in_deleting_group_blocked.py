"""create-schedule-in-deleting-group-blocked."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-schedule-in-deleting-group-blocked"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedule against a group that is being deleted is rejected with ValidationException
    and the schedule is absent once the group is gone; an ACTIVE group accepts CreateSchedule."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    scheduler = ctx.client("scheduler")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-dg-q-"),
        tags={"sim2real": "create-schedule-in-deleting-group-blocked"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    role_arn = _create_scheduler_role(ctx, iam)

    # Give the group many schedules of its own so the cascade delete has real work to
    # do, widening the window during which the group is observably DELETING. All are
    # DISABLED so none actually fire during the test.
    dying_group = ctx.unique_name("sim2real-sched-dg-grp-")
    scheduler.create_schedule_group(
        Name=dying_group,
        Tags=[{"Key": "sim2real", "Value": "create-schedule-in-deleting-group-blocked"}],
    )
    group_gone = {"done": False}
    ctx.on_cleanup(lambda: None if group_gone["done"] else _safe_delete_group(scheduler, dying_group))

    for i in range(40):
        seed_schedule = ctx.unique_name(f"sim2real-sched-dg-seed-{i}-")
        _create_schedule_retrying(
            ctx,
            scheduler,
            Name=seed_schedule,
            GroupName=dying_group,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="DISABLED",
            Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "seed"},
        )

    scheduler.delete_schedule_group(Name=dying_group)

    # Race to observe the DELETING window: fire CreateSchedule attempts immediately
    # and repeatedly, back-to-back with no sleep, until either one is rejected
    # (expected) or the group fully disappears (window missed).
    from botocore.exceptions import ClientError

    rejection_code = None
    rejection_message = None
    saw_deleting = False
    attempt = 0
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and rejection_code is None:
        attempt += 1
        try:
            grp = scheduler.get_schedule_group(Name=dying_group)
            if grp.get("State") == "DELETING":
                saw_deleting = True
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                group_gone["done"] = True
                break
            raise

        blocked_name = ctx.unique_name(f"sim2real-sched-dg-blocked-{attempt}-")
        try:
            scheduler.create_schedule(
                Name=blocked_name,
                GroupName=dying_group,
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "blocked"},
            )
            # Accepted before DELETING took effect: clean up and keep racing.
            scheduler.delete_schedule(Name=blocked_name, GroupName=dying_group)
        except ClientError as err:
            rejection_code = err.response["Error"]["Code"]
            rejection_message = err.response["Error"].get("Message")

    if not group_gone["done"]:
        try:
            scheduler.get_schedule_group(Name=dying_group)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                group_gone["done"] = True

    if rejection_code is None:
        raise AssertionError(
            "never observed the schedule group reject CreateSchedule "
            f"(saw_deleting={saw_deleting}, group_gone={group_gone['done']}, attempts={attempt})"
        )
    # Empirically, real AWS rejects CreateSchedule against a group that is in the
    # process of being deleted with ValidationException (not ConflictException).
    assert rejection_code == "ValidationException", f"expected ValidationException, got {rejection_code!r}"
    expected = f"You cannot perform this operation because schedule group {dying_group} is being deleted."
    assert rejection_message == expected, f"expected message {expected!r}, got {rejection_message!r}"

    # Poll the group to not-found first so the absence read does not race the cascade delete.
    gone_deadline = time.monotonic() + 120.0
    while not group_gone["done"]:
        try:
            scheduler.get_schedule_group(Name=dying_group)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            group_gone["done"] = True
            break
        if time.monotonic() >= gone_deadline:
            raise AssertionError(f"schedule group {dying_group!r} did not finish deleting within 120s")
        time.sleep(2.0)
    absence_code = absence_message = None
    try:
        scheduler.get_schedule(Name=blocked_name, GroupName=dying_group)
    except ClientError as err:
        absence_code = err.response["Error"]["Code"]
        absence_message = err.response["Error"].get("Message")
    assert absence_code == "ResourceNotFoundException", (
        f"expected the rejected schedule {blocked_name!r} to be absent with "
        f"ResourceNotFoundException, got {absence_code!r}"
    )
    expected_absent = f"Schedule group {dying_group} does not exist."
    assert absence_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absence_message!r}"
    )

    # Positive control: CreateSchedule against a healthy, unrelated ACTIVE group succeeds.
    healthy_group = ctx.unique_name("sim2real-sched-dg-healthy-")
    scheduler.create_schedule_group(
        Name=healthy_group,
        Tags=[{"Key": "sim2real", "Value": "create-schedule-in-deleting-group-blocked"}],
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule_group(Name=healthy_group))
    control_name = ctx.unique_name("sim2real-sched-dg-control-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=control_name,
        GroupName=healthy_group,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "control"},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=control_name, GroupName=healthy_group))
    got_name = scheduler.get_schedule(Name=control_name, GroupName=healthy_group)["Name"]
    assert got_name == control_name, f"expected control schedule {control_name!r}, got {got_name!r}"


def _create_scheduler_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "create-schedule-in-deleting-group-blocked"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _safe_delete_group(scheduler, name):
    from botocore.exceptions import ClientError

    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
