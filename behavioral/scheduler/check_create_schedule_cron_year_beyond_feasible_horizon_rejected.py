"""create-schedule-cron-year-beyond-feasible-horizon-rejected."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-cron-year-beyond-feasible-horizon-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]

_CREATE_TIMEOUT_S = 180
_FAR_FUTURE_YEARS = 150
_NEAR_FUTURE_YEARS = 5


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _create_scheduler_role(ctx, resource_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": resource_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _create_schedule_retrying(ctx, scheduler, interval_s=3.0, **kwargs):
    """CreateSchedule, retried only while Scheduler cannot yet assume the fresh role."""
    timeout_s = _budget_s(ctx, _CREATE_TIMEOUT_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code != "ValidationException" or "assume the role" not in msg:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"CreateSchedule could not assume the role for {timeout_s:.0f}s: {msg!r}"
                ) from exc
            time.sleep(interval_s)


def _iso_no_tz(dt):
    """Render a UTC datetime the way CreateSchedule's error message echoes it back."""
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
    if dt.second:
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    return dt.strftime("%Y-%m-%dT%H:%M")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A cron() schedule whose Year field puts every occurrence beyond EventBridge
    Scheduler's feasible lookahead from StartDate is rejected as never-firing, while the
    same cron with a reachable Year succeeds."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    target_name = ctx.unique_name("sim2real-sched-target-")
    target_url = sqs.create_queue(QueueName=target_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=target_url))
    target_arn = sqs.get_queue_attributes(
        QueueUrl=target_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    role_arn = _create_scheduler_role(ctx, target_arn)

    start_date = datetime.datetime.now(datetime.timezone.utc).replace(
        second=0, microsecond=0
    ) + datetime.timedelta(days=1)

    # Positive control first, so the role is assumable before the refusal is asserted.
    near_year = start_date.year + _NEAR_FUTURE_YEARS
    good_name = ctx.unique_name("sim2real-sched-nearyear-")
    good_expr = f"cron(0 12 * * ? {near_year})"
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression=good_expr,
        StartDate=start_date,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": target_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))

    got = scheduler.get_schedule(Name=good_name)
    assert got["ScheduleExpression"] == good_expr, (
        f"positive control: expected ScheduleExpression {good_expr!r}, got {got['ScheduleExpression']!r}"
    )

    far_year = start_date.year + _FAR_FUTURE_YEARS
    bad_name = ctx.unique_name("sim2real-sched-faryear-")
    bad_expr = f"cron(0 12 * * ? {far_year})"
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression=bad_expr,
            StartDate=start_date,
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": target_arn, "RoleArn": role_arn},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        f"The schedule expression {bad_expr}, with StartDate {_iso_no_tz(start_date)} and "
        "EndDate null, is invalid because it will never schedule an invocation."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, _ = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"a refused create must not leave a schedule behind, got {not_found_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
