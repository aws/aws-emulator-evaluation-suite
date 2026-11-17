"""create-schedule-retry-policy-bounds-and-refusals."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-retry-policy-bounds-and-refusals"
GROUP = "retry-policy"
SERVICES = ["iam", "scheduler"]

_EVENT_AGE_TOO_LOW = (
    "ValidationException",
    "1 validation error detected: Value '59' at 'target.retryPolicy.maximumEventAgeInSeconds' "
    "failed to satisfy constraint: Member must have value greater than or equal to 60",
)
_RETRY_ATTEMPTS_TOO_HIGH = (
    "ValidationException",
    "1 validation error detected: Value '186' at 'target.retryPolicy.maximumRetryAttempts' "
    "failed to satisfy constraint: Member must have value less than or equal to 185",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message):
    """Assert fn() raises ClientError with exactly (code, message); raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response["Error"]["Code"]
        got_message = exc.response["Error"]["Message"]
        assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _create_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_name = ctx.unique_name("sim2real-behav-sched-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"
    ))
    return role_arn


def _create_schedule_retrying(sch, **kwargs):
    """A freshly created IAM role is not always immediately assumable by Scheduler; retry
    past the transient ValidationException while the role propagates."""
    deadline = time.monotonic() + 45.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"create_schedule never succeeded (IAM role propagation?): {last_exc}")


def _expect_create_refused(ctx, sch, code, message, **kwargs):
    """CreateSchedule(**kwargs) must be refused with exactly (code, message) and create nothing;
    registers cleanup only if it unexpectedly succeeds."""
    name = kwargs["Name"]
    try:
        sch.create_schedule(**kwargs)
    except ClientError as exc:
        got_code = exc.response["Error"]["Code"]
        got_message = exc.response["Error"]["Message"]
        assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    ctx.on_cleanup(_teardown(lambda: sch.delete_schedule(Name=name), "ResourceNotFoundException"))
    raise AssertionError(f"expected {code} for {name!r} but create_schedule succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule and UpdateSchedule store a RetryPolicy at its 60 s/0 and 86400 s/185 bounds;
    CreateSchedule refuses 59 s and 186 attempts with the exact constraint message and creates
    nothing, and a full-replace update omitting RetryPolicy reverts to the 86400/185 default."""
    sch = ctx.client("scheduler")
    sch_raw = ctx.client("scheduler", config=Config(parameter_validation=False))
    role_arn = _create_role(ctx)
    target_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{ctx.unique_name('sim2real-behav-sched-tgt-')}"

    # Schedule A: lower bound (60/0) round-trips, then a full-replace update to the upper bound.
    name_a = ctx.unique_name("sim2real-behav-sched-a-")
    _create_schedule_retrying(
        sch,
        Name=name_a,
        ScheduleExpression="rate(10 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={
            "Arn": target_arn, "RoleArn": role_arn,
            "RetryPolicy": {"MaximumEventAgeInSeconds": 60, "MaximumRetryAttempts": 0},
        },
    )
    ctx.on_cleanup(_teardown(lambda: sch.delete_schedule(Name=name_a), "ResourceNotFoundException"))

    rp = sch.get_schedule(Name=name_a)["Target"]["RetryPolicy"]
    assert rp["MaximumEventAgeInSeconds"] == 60, f"expected 60 at the lower bound, got {rp!r}"
    assert rp["MaximumRetryAttempts"] == 0, f"expected 0 at the lower bound, got {rp!r}"

    sch.update_schedule(
        Name=name_a,
        ScheduleExpression="rate(10 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={
            "Arn": target_arn, "RoleArn": role_arn,
            "RetryPolicy": {"MaximumEventAgeInSeconds": 86400, "MaximumRetryAttempts": 185},
        },
    )
    rp = sch.get_schedule(Name=name_a)["Target"]["RetryPolicy"]
    assert rp["MaximumEventAgeInSeconds"] == 86400, f"expected 86400 at the upper bound, got {rp!r}"
    assert rp["MaximumRetryAttempts"] == 185, f"expected 185 at the upper bound, got {rp!r}"

    # Schedule B: a non-default RetryPolicy, then a full-replace update that omits RetryPolicy
    # reverts GetSchedule to the documented default of 86400/185.
    name_b = ctx.unique_name("sim2real-behav-sched-b-")
    sch.create_schedule(
        Name=name_b,
        ScheduleExpression="rate(10 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={
            "Arn": target_arn, "RoleArn": role_arn,
            "RetryPolicy": {"MaximumEventAgeInSeconds": 3600, "MaximumRetryAttempts": 5},
        },
    )
    ctx.on_cleanup(_teardown(lambda: sch.delete_schedule(Name=name_b), "ResourceNotFoundException"))

    rp = sch.get_schedule(Name=name_b)["Target"]["RetryPolicy"]
    assert rp["MaximumEventAgeInSeconds"] == 3600, f"expected 3600 before the revert, got {rp!r}"
    assert rp["MaximumRetryAttempts"] == 5, f"expected 5 before the revert, got {rp!r}"

    sch.update_schedule(
        Name=name_b,
        ScheduleExpression="rate(10 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": target_arn, "RoleArn": role_arn},
    )
    rp = sch.get_schedule(Name=name_b)["Target"]["RetryPolicy"]
    assert rp["MaximumEventAgeInSeconds"] == 86400, f"expected the default 86400 restored, got {rp!r}"
    assert rp["MaximumRetryAttempts"] == 185, f"expected the default 185 restored, got {rp!r}"

    # Refusals: one member each side of its documented bound, and the refused name never exists.
    name_c = ctx.unique_name("sim2real-behav-sched-c-")
    _expect_create_refused(
        ctx, sch_raw, *_EVENT_AGE_TOO_LOW,
        Name=name_c,
        ScheduleExpression="rate(10 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={
            "Arn": target_arn, "RoleArn": role_arn,
            "RetryPolicy": {"MaximumEventAgeInSeconds": 59, "MaximumRetryAttempts": 0},
        },
    )
    expect_error(
        lambda: sch.get_schedule(Name=name_c),
        "ResourceNotFoundException", f"Schedule {name_c} does not exist.",
    )

    name_d = ctx.unique_name("sim2real-behav-sched-d-")
    _expect_create_refused(
        ctx, sch_raw, *_RETRY_ATTEMPTS_TOO_HIGH,
        Name=name_d,
        ScheduleExpression="rate(10 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={
            "Arn": target_arn, "RoleArn": role_arn,
            "RetryPolicy": {"MaximumEventAgeInSeconds": 3600, "MaximumRetryAttempts": 186},
        },
    )
    expect_error(
        lambda: sch.get_schedule(Name=name_d),
        "ResourceNotFoundException", f"Schedule {name_d} does not exist.",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
