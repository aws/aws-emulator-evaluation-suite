"""one-time-at-schedule-start-after-end-date-rejected."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "one-time-at-schedule-start-after-end-date-rejected"
GROUP = "schedule-expressions"
SERVICES = ["iam", "scheduler"]

_CREATE_TIMEOUT_S = 150


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedule rejects a one-time at() schedule whose explicit StartDate comes after its
    EndDate with a ValidationException, leaving no schedule persisted; a sibling with a valid
    ordering still succeeds.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
    """
    scheduler = ctx.client("scheduler")
    role_arn = _create_scheduler_role(ctx)

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    at_expression = f"at({(now + datetime.timedelta(hours=3)).strftime('%Y-%m-%dT%H:%M:%S')})"
    target = {
        "Arn": f"arn:aws:sqs:{ctx.region}:{ctx.account}:sim2real-nonexistent-placeholder",
        "RoleArn": role_arn,
    }

    bad_name = ctx.unique_name("sim2real-behav-sched-atstart-")
    start_date = now + datetime.timedelta(hours=2)
    end_date = now + datetime.timedelta(hours=1)  # before start_date -> invalid

    code, message = _error(
        lambda: _create_schedule_with_retry(
            ctx,
            scheduler,
            Name=bad_name,
            ScheduleExpression=at_expression,
            StartDate=start_date,
            EndDate=end_date,
            FlexibleTimeWindow={"Mode": "OFF"},
            Target=target,
            State="DISABLED",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "The StartDate you specify must come before the EndDate."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected schedule must not have been persisted, but GetSchedule returned "
        f"{not_found_code!r}"
    )
    assert not_found_message == f"Schedule {bad_name} does not exist.", (
        f"unexpected not-found message: {not_found_message!r}"
    )

    # Positive control: the identical at() schedule, but with a valid StartDate < EndDate ordering.
    good_name = ctx.unique_name("sim2real-behav-sched-atstart-ok-")
    _create_schedule_with_retry(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression=at_expression,
        StartDate=now + datetime.timedelta(hours=1),
        EndDate=now + datetime.timedelta(hours=2),
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=target,
        State="DISABLED",
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))
    got = scheduler.get_schedule(Name=good_name)
    assert got["Name"] == good_name, f"GetSchedule returned Name {got['Name']!r}, expected {good_name!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_scheduler_role(ctx) -> str:
    iam = ctx.client("iam")
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
    propagation is still in flight. Retry briefly on that transient signature only; a genuine
    validation error (e.g. EndDate before StartDate) carries a different message and propagates
    immediately."""
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
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
