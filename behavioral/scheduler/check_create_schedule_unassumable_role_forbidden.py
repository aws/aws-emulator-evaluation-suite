"""create-schedule-unassumable-role-forbidden."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-schedule-unassumable-role-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['scheduler']


def _flexible_window(mode="OFF", max_minutes=None):
    window = {"Mode": mode}
    if max_minutes is not None:
        window["MaximumWindowInMinutes"] = max_minutes
    return window


def _sqs_target(queue_arn, role_arn, input_payload=None):
    target = {"Arn": queue_arn, "RoleArn": role_arn}
    if input_payload is not None:
        target["Input"] = json.dumps(input_payload)
    return target


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected CreateSchedule to raise, but it succeeded")


def _schedule_exists(sch, name):
    try:
        sch.get_schedule(Name=name)
        return True
    except sch.exceptions.ResourceNotFoundException:
        return False


def _create_scheduler_role(ctx, iam):
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Role"]["Arn"]


def _create_schedule_with_retry(sch, **kwargs):
    """CreateSchedule can transiently reject a freshly-created RoleArn while IAM trust-policy
    propagation is still in flight. Retry briefly on that specific transient signature only."""
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sch.create_schedule(**kwargs)
        except sch.exceptions.ValidationException as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "assume" not in msg and "must allow" not in msg:
                raise
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"CreateSchedule kept failing on role propagation: {last_err}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedule rejects a Target.RoleArn naming a nonexistent role with ValidationException
    and persists nothing; the identical request with a real, correctly-trusted role succeeds."""
    sch = ctx.client("scheduler")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    placeholder_queue_arn = f"arn:aws:sqs:{ctx.region}:{account_id}:sim2real-behav-sched-placeholder"

    # Positive control: a real role, correctly trusted by scheduler.amazonaws.com.
    real_role_arn = _create_scheduler_role(ctx, iam)
    good_name = ctx.unique_name("sim2real-behav-sched-good-")
    _create_schedule_with_retry(
        sch,
        Name=good_name,
        ScheduleExpression="rate(5 minutes)",
        FlexibleTimeWindow=_flexible_window("OFF"),
        Target=_sqs_target(placeholder_queue_arn, real_role_arn),
        State="DISABLED",
    )
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=good_name))
    assert _schedule_exists(sch, good_name), "positive control: a real, correctly-trusted role must be accepted"

    # Break exactly one thing: point at a role name that was never created.
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-behav-sched-ghost-')}"
    bad_name = ctx.unique_name("sim2real-behav-sched-bad-")
    code, message = _error(
        lambda: sch.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(5 minutes)",
            FlexibleTimeWindow=_flexible_window("OFF"),
            Target=_sqs_target(placeholder_queue_arn, bogus_role_arn),
            State="DISABLED",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "The execution role you provide must allow AWS EventBridge Scheduler to assume the role."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert not _schedule_exists(sch, bad_name), "schedule was persisted despite an unassumable role"

    # Restore: the identical request, with the real role substituted back in, succeeds.
    _create_schedule_with_retry(
        sch,
        Name=bad_name,
        ScheduleExpression="rate(5 minutes)",
        FlexibleTimeWindow=_flexible_window("OFF"),
        Target=_sqs_target(placeholder_queue_arn, real_role_arn),
        State="DISABLED",
    )
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=bad_name))
    assert _schedule_exists(sch, bad_name), "identical request with a real role must now succeed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
