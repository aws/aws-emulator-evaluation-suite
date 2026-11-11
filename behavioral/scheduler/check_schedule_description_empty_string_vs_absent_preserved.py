"""schedule-description-empty-string-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "schedule-description-empty-string-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicit empty-string Description is distinguishable from an omitted one on GetSchedule."""
    scheduler = ctx.client("scheduler")
    account_id = _account_id(ctx)
    role_arn = _create_execution_role(ctx)

    name_with_empty = ctx.unique_name("sim2real-behav-sched-empty-")
    name_without = ctx.unique_name("sim2real-behav-sched-absent-")

    _create_schedule_with_retry(
        scheduler,
        Name=name_with_empty,
        Description="",
        ScheduleExpression="rate(1 hour)",
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=_fake_target(ctx, account_id, role_arn),
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name_with_empty))

    _create_schedule_with_retry(
        scheduler,
        Name=name_without,
        ScheduleExpression="rate(1 hour)",
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=_fake_target(ctx, account_id, role_arn),
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name_without))

    got_empty = scheduler.get_schedule(Name=name_with_empty)
    got_absent = scheduler.get_schedule(Name=name_without)

    assert "Description" in got_empty, "explicit empty-string Description was dropped entirely"
    assert got_empty["Description"] == "", f"expected empty Description, got {got_empty['Description']!r}"
    assert "Description" not in got_absent, (
        f"omitted Description should not appear as a key in GetSchedule, got {got_absent.get('Description')!r}"
    )


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
        Tags=[{"Key": "sim2real", "Value": "behav-sched-description-empty-vs-absent"}],
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
