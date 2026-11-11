"""schedule-start-end-date-timestamp-precision-preserved."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "schedule-start-end-date-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartDate/EndDate sub-second precision is rounded to the nearest millisecond on GetSchedule,
    neither truncated to whole seconds nor preserved at microsecond resolution."""
    scheduler = ctx.client("scheduler")
    account_id = _account_id(ctx)
    role_arn = _create_execution_role(ctx)
    name = ctx.unique_name("sim2real-behav-sched-")

    # Far-future window so the (fake) target is never actually invoked during the check.
    # Microsecond components are deliberately NOT millisecond-aligned, so a truncation to
    # millisecond precision would be distinguishable from exact preservation.
    start = datetime(2099, 6, 15, 12, 30, 45, 123456, tzinfo=timezone.utc)
    end = start + timedelta(days=30, microseconds=654321)

    _create_schedule_with_retry(
        scheduler,
        Name=name,
        ScheduleExpression="rate(1 hour)",
        StartDate=start,
        EndDate=end,
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=_fake_target(ctx, account_id, role_arn),
    )

    def _cleanup_schedule():
        try:
            scheduler.delete_schedule(Name=name)
        except scheduler.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup_schedule)

    got = scheduler.get_schedule(Name=name)
    got_start = got["StartDate"]
    got_end = got["EndDate"]

    # Real AWS rounds the sub-second component to the nearest millisecond (777777us rounds
    # up to 778ms, 123456us rounds down to 123ms) -- not a floor, and the rounded
    # millisecond component is neither zeroed nor dropped.
    expected_start = _rounded_to_millisecond(start)
    expected_end = _rounded_to_millisecond(end)

    assert got_start.microsecond % 1000 == 0, f"expected StartDate rounded to millisecond precision, got {got_start!r}"
    assert got_end.microsecond % 1000 == 0, f"expected EndDate rounded to millisecond precision, got {got_end!r}"
    assert got_start == expected_start, (
        f"StartDate not rounded to millisecond precision: sent {start!r}, expected {expected_start!r}, got {got_start!r}"
    )
    assert got_end == expected_end, (
        f"EndDate not rounded to millisecond precision: sent {end!r}, expected {expected_end!r}, got {got_end!r}"
    )

    scheduler.delete_schedule(Name=name)
    try:
        scheduler.get_schedule(Name=name)
        raise AssertionError(f"expected schedule {name!r} to be gone after delete, but GetSchedule still returned it")
    except scheduler.exceptions.ResourceNotFoundException as exc:
        got_message = exc.response["Error"].get("Message")
        expected = f"Schedule {name} does not exist."
        assert got_message == expected, f"expected {expected!r}, got {got_message!r}"


def _rounded_to_millisecond(dt: datetime) -> datetime:
    millis = round(dt.microsecond / 1000)
    return dt.replace(microsecond=0) + timedelta(milliseconds=millis)


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_execution_role(ctx) -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "scheduler.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Role"]["Arn"]


def _create_schedule_with_retry(scheduler, **kwargs):
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + 45
    last_err = None
    while time.time() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume" in message.lower():
                last_err = err
                time.sleep(3)
                continue
            raise
    raise last_err


def _fake_target(ctx, account_id: str, role_arn: str) -> dict:
    # The target ARN need not resolve to a real queue for CreateSchedule to succeed:
    # EventBridge Scheduler only validates ARN format at creation time, but it DOES
    # validate that RoleArn's trust policy allows scheduler.amazonaws.com to assume it.
    return {
        "Arn": f"arn:aws:sqs:{ctx.region}:{account_id}:sim2real-behav-fake-queue",
        "RoleArn": role_arn,
        "Input": '{"k": "v"}',
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
