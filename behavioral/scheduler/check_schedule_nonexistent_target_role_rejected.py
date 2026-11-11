"""schedule-nonexistent-target-role-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "schedule-nonexistent-target-role-rejected"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule rejects a RoleArn naming a nonexistent IAM role with ValidationException.

    The message says the role must allow EventBridge Scheduler to assume it, the schedule is not
    persisted, and the same request with a real role persists its Target.RoleArn.
    """
    scheduler = ctx.client("scheduler")
    iam = ctx.client("iam")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_role_name = ctx.unique_name("sim2real-behav-sched-ghost-role-")
    fake_role_arn = f"arn:aws:iam::{account_id}:role/{fake_role_name}"

    dummy_target = {
        "Arn": "arn:aws:sqs:" + ctx.region + ":000000000000:sim2real-nonexistent-placeholder",
        "RoleArn": fake_role_arn,
    }

    bad_name = ctx.unique_name("sim2real-behav-sched-badrole-")
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(1 day)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target=dummy_target,
            State="DISABLED",
        )
    )
    # A RoleArn naming a role that was never created can never be assumed by EventBridge
    # Scheduler; real AWS surfaces this as a ValidationException on the trust-policy check
    # rather than a ResourceNotFoundException (which is reserved for e.g. a missing schedule).
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "The execution role you provide must allow AWS EventBridge Scheduler to assume the role."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    not_found_code, not_found_message = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected schedule must not have been persisted, but GetSchedule returned {not_found_code!r}"
    )
    assert not_found_message == f"Schedule {bad_name} does not exist.", (
        f"unexpected not-found message: {not_found_message!r}"
    )

    # Positive control: identical request, but the RoleArn points at a role that really exists.
    real_role_arn = _create_scheduler_role(ctx, iam)
    good_name = ctx.unique_name("sim2real-behav-sched-goodrole-")
    _create_schedule_with_retry(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 day)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": "arn:aws:sqs:" + ctx.region + ":000000000000:sim2real-nonexistent-placeholder",
            "RoleArn": real_role_arn,
        },
        State="DISABLED",
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))
    got = scheduler.get_schedule(Name=good_name)
    assert got["Target"]["RoleArn"] == real_role_arn, (
        f"expected persisted Target.RoleArn {real_role_arn!r}, got {got['Target']['RoleArn']!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting input real AWS rejects never reads as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_scheduler_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust_policy = {
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
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Role"]["Arn"]


def _create_schedule_with_retry(ctx, scheduler, **kwargs):
    """CreateSchedule can transiently reject a freshly-created RoleArn while IAM trust-policy
    propagation is still in flight -- surfaced either as ResourceNotFoundException or as a
    ValidationException whose message complains the role must allow EventBridge Scheduler to
    assume it. Retry briefly on those transient signatures only."""
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except scheduler.exceptions.ResourceNotFoundException as exc:
            last_err = exc
            time.sleep(2.0)
        except scheduler.exceptions.ValidationException as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "must allow" not in msg and "assume" not in msg:
                raise
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"CreateSchedule kept failing on role propagation: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
