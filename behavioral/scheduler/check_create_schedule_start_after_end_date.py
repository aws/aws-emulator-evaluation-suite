"""create-schedule-start-after-end-date."""
from __future__ import annotations

import json
import time
import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-schedule-start-after-end-date"
GROUP = 'error-semantics'
SERVICES = ['scheduler']


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _create_scheduler_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))

    def _del_role():
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduler-target",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
        }),
    )
    return role["Role"]["Arn"]


def _create_schedule_with_retry(scheduler, **kwargs):
    """CreateSchedule can transiently reject a freshly-created RoleArn while IAM trust-policy
    propagation is still in flight -- surfaced either as ResourceNotFoundException or as a
    ValidationException whose message complains the role must allow EventBridge Scheduler to
    assume it. Retry briefly on those transient signatures only; a *genuine* validation error
    (e.g. StartDate after EndDate) carries a different message and must propagate immediately."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartDate later than EndDate raises ValidationException, the rejected schedule is never
    persisted, and an otherwise-identical schedule with a valid ordering still succeeds
    (positive control in the same file)."""
    sch = ctx.client("scheduler")
    role_arn = _create_scheduler_role(ctx)
    target = {
        "Arn": f"arn:aws:sqs:{ctx.region}:000000000000:sim2real-behav-placeholder-target",
        "RoleArn": role_arn,
    }

    bad_name = ctx.unique_name("sim2real-behav-sched-bad-")
    start = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    end = datetime.datetime(2029, 1, 1, tzinfo=datetime.timezone.utc)
    code, message = _error(lambda: _create_schedule_with_retry(
        sch,
        Name=bad_name,
        ScheduleExpression="rate(1 hour)",
        StartDate=start,
        EndDate=end,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=target,
        State="DISABLED",
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "The StartDate you specify must come before the EndDate."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error(lambda: sch.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected schedule must not have been persisted, but GetSchedule returned {not_found_code!r}"
    )
    expected_missing = f"Schedule {bad_name} does not exist."
    assert not_found_message == expected_missing, (
        f"expected message {expected_missing!r}, got {not_found_message!r}"
    )

    # Positive control: identical setup, but with a valid StartDate < EndDate ordering.
    good_name = ctx.unique_name("sim2real-behav-sched-good-")
    _create_schedule_with_retry(
        sch,
        Name=good_name,
        ScheduleExpression="rate(1 hour)",
        StartDate=datetime.datetime(2029, 1, 1, tzinfo=datetime.timezone.utc),
        EndDate=datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=target,
        State="DISABLED",
    )
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=good_name))
    got = sch.get_schedule(Name=good_name)
    assert got["Name"] == good_name, f"expected positive control to be persisted as {good_name!r}, got {got.get('Name')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
