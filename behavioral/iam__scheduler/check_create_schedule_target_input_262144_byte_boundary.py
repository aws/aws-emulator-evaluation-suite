"""create-schedule-target-input-262144-byte-boundary."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-target-input-262144-byte-boundary"
GROUP = "representation"
SERVICES = ["iam", "scheduler"]

_MAX_BYTES = 262144


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule rejects a Target.Input of 262,145 bytes with ValidationException and creates
    nothing, while an Input of exactly 262,144 bytes succeeds and is stored byte-exact."""
    scheduler = ctx.client("scheduler")
    role_arn = _create_execution_role(ctx)
    fake_target_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:sim2real-behav-sched-input-fake-queue"

    # --- negative: one byte over the documented 256 KB limit ---
    too_big_name = ctx.unique_name("sim2real-sched-input-over-")
    too_big_input = "x" * (_MAX_BYTES + 1)
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=too_big_name,
            ScheduleExpression="rate(1 hour)",
            State="DISABLED",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": fake_target_arn, "RoleArn": role_arn, "Input": too_big_input},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected_message = f"The input size for the target cannot exceed {_MAX_BYTES} bytes."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    list_resp = scheduler.list_schedules(NamePrefix=too_big_name)
    assert list_resp["Schedules"] == [], (
        f"rejected over-size-Input schedule was created anyway: {list_resp['Schedules']!r}"
    )

    # --- positive control: exactly at the documented maximum succeeds and round-trips ---
    at_max_name = ctx.unique_name("sim2real-sched-input-atmax-")
    at_max_input = "x" * _MAX_BYTES
    _create_schedule_with_retry(
        ctx,
        scheduler,
        Name=at_max_name,
        ScheduleExpression="rate(1 hour)",
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": fake_target_arn, "RoleArn": role_arn, "Input": at_max_input},
    )

    got = scheduler.get_schedule(Name=at_max_name)
    assert got["Target"]["Input"] == at_max_input, (
        f"max-size Input was not stored byte-exact: expected {_MAX_BYTES} 'x' chars, "
        f"got {len(got['Target']['Input'])} chars"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises rather
    than being reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-input-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Role"]["Arn"]


def _create_schedule_with_retry(ctx, scheduler, **kwargs) -> None:
    """CreateSchedule assumes the role to validate it; freshly-created IAM roles are not instantly
    visible, so retry the IAM-propagation ValidationException within a bound."""
    name = kwargs["Name"]
    deadline = time.monotonic() + 45
    last_err = None
    while time.monotonic() < deadline:
        try:
            scheduler.create_schedule(**kwargs)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume" in message.lower():
                last_err = err
                time.sleep(3)
                continue
            raise
    else:
        raise last_err
    ctx.on_cleanup(lambda: _delete_schedule(scheduler, name))


def _delete_schedule(scheduler, name: str) -> None:
    try:
        scheduler.delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
