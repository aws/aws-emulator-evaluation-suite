"""schedule-timestamp-precision-round-trip."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "schedule-timestamp-precision-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSchedule returns StartDate/EndDate rounded to the nearest millisecond: neither truncated
    to whole seconds nor preserved at full microsecond precision.
    """
    scheduler = ctx.client("scheduler")
    role_arn = _create_scheduler_role(ctx)

    now = datetime.datetime.now(datetime.timezone.utc)
    start_date = (now + datetime.timedelta(hours=1)).replace(microsecond=284400)
    end_date = (now + datetime.timedelta(hours=25)).replace(microsecond=613600)

    name = ctx.unique_name("sim2real-behav-sched-")
    _create_schedule_with_retry(
        ctx,
        scheduler,
        Name=name,
        ScheduleExpression="rate(1 day)",
        StartDate=start_date,
        EndDate=end_date,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": "arn:aws:sqs:" + ctx.region + ":000000000000:sim2real-nonexistent-placeholder",
            "RoleArn": role_arn,
        },
        State="DISABLED",
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    got = scheduler.get_schedule(Name=name)
    got_start = got["StartDate"]
    got_end = got["EndDate"]

    # Microsecond values chosen so rounding, flooring and full precision all give distinct results.
    expected_start = _round_to_millisecond(start_date)
    expected_end = _round_to_millisecond(end_date)

    assert got_start == expected_start, (
        f"StartDate should round to the nearest millisecond: wrote {start_date.isoformat()}, "
        f"expected {expected_start.isoformat()}, got {got_start.isoformat()}"
    )
    assert got_end == expected_end, (
        f"EndDate should round to the nearest millisecond: wrote {end_date.isoformat()}, "
        f"expected {expected_end.isoformat()}, got {got_end.isoformat()}"
    )




def _round_to_millisecond(dt: datetime.datetime) -> datetime.datetime:
    """Round `dt` to the nearest millisecond, carrying into the second on overflow."""
    whole_ms = round(dt.microsecond / 1000.0)
    return dt.replace(microsecond=0) + datetime.timedelta(milliseconds=whole_ms)


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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
