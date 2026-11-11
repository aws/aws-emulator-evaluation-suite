"""schedule-start-end-date-timestamp-precision-round-trip."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-start-end-date-timestamp-precision-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartDate/EndDate are rounded to the nearest millisecond on read-back (777777us -> 778ms,
    654321us -> 654ms), neither floored nor truncated to the whole second."""
    scheduler = ctx.client("scheduler")

    queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)

    start = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1, microseconds=777777)
    end = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=2, microseconds=654321)
    expected_start = start.replace(microsecond=0) + timedelta(milliseconds=round(start.microsecond / 1000))
    expected_end = end.replace(microsecond=0) + timedelta(milliseconds=round(end.microsecond / 1000))

    schedule_name = ctx.unique_name("sim2real-sched-")
    _create_schedule_with_retry(
        scheduler,
        Name=schedule_name,
        ScheduleExpression="rate(1 day)",
        State="DISABLED",
        StartDate=start,
        EndDate=end,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "unused"},
    )

    def _delete_if_present():
        try:
            scheduler.delete_schedule(Name=schedule_name)
        except scheduler.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_delete_if_present)

    fetched = scheduler.get_schedule(Name=schedule_name)
    assert fetched["StartDate"] == expected_start, (
        f"expected StartDate rounded to the nearest millisecond ({expected_start.isoformat()}), "
        f"got {fetched['StartDate'].isoformat()}"
    )
    assert fetched["EndDate"] == expected_end, (
        f"expected EndDate rounded to the nearest millisecond ({expected_end.isoformat()}), "
        f"got {fetched['EndDate'].isoformat()}"
    )

    # After delete, an independent read and a second mutation on the dead id must both fail.
    scheduler.delete_schedule(Name=schedule_name)
    try:
        still_there = scheduler.get_schedule(Name=schedule_name)
        raise AssertionError(
            f"expected GetSchedule({schedule_name!r}) to 404 after delete, got {still_there!r}"
        )
    except scheduler.exceptions.ResourceNotFoundException as exc:
        got_message = exc.response["Error"].get("Message")
        expected = f"Schedule {schedule_name} does not exist."
        assert got_message == expected, f"expected {expected!r}, got {got_message!r}"
    try:
        scheduler.delete_schedule(Name=schedule_name)
        raise AssertionError(
            f"expected a second DeleteSchedule({schedule_name!r}) on an already-deleted schedule to fail"
        )
    except scheduler.exceptions.ResourceNotFoundException as exc:
        got_message = exc.response["Error"].get("Message")
        expected = f"Schedule {schedule_name} does not exist."
        assert got_message == expected, f"expected {expected!r}, got {got_message!r}"


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_scheduler_role(ctx, queue_arn):
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_with_retry(scheduler, retries=10, delay=3, **kwargs):
    """CreateSchedule can transiently reject the just-created RoleArn as a ValidationException
    while IAM trust-policy propagation is still in flight. Retry briefly on that signature only."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
