"""schedule-description-exceeds-max-length-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "schedule-description-exceeds-max-length-rejected"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule rejects a 513-character Description with ValidationException and creates
    nothing, while a Description of exactly 512 characters succeeds and is stored verbatim."""
    scheduler = ctx.client("scheduler")
    account_id = _account_id(ctx)
    role_arn = _create_execution_role(ctx)

    # --- negative: one character over the documented maximum length ---
    bad_name = ctx.unique_name("sim2real-behav-sched-toolong-")
    too_long_description = "d" * 513
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            Description=too_long_description,
            ScheduleExpression="rate(1 hour)",
            State="DISABLED",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target=_fake_target(ctx, account_id, role_arn),
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{too_long_description}' at 'description' "
        "failed to satisfy constraint: Member must have length less than or equal to 512"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    list_resp = scheduler.list_schedules(NamePrefix=bad_name)
    assert list_resp["Schedules"] == [], (
        f"rejected over-length-Description schedule was created anyway: {list_resp['Schedules']!r}"
    )

    # --- positive control: exactly at the documented maximum succeeds ---
    good_name = ctx.unique_name("sim2real-behav-sched-atmax-")
    max_description = "d" * 512
    _create_schedule_with_retry(
        scheduler,
        Name=good_name,
        Description=max_description,
        ScheduleExpression="rate(1 hour)",
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=_fake_target(ctx, account_id, role_arn),
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))

    got = scheduler.get_schedule(Name=good_name)
    assert got["Description"] == max_description, (
        f"max-length Description was not stored verbatim: expected 512 'd' chars, "
        f"got {len(got['Description'])} chars"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises rather
    than being reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)

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
