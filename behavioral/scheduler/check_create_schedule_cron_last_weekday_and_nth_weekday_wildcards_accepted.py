"""create-schedule-cron-last-weekday-and-nth-weekday-wildcards-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-cron-last-weekday-and-nth-weekday-wildcards-accepted"
GROUP = "representation"
SERVICES = ["scheduler"]

_CREATE_TIMEOUT_S = 180


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cron() schedule accepts the L (last day-of-month/week), W (nearest weekday) and
    # (nth weekday-of-month) wildcards and each round-trips through GetSchedule unchanged, while
    L in day-of-month beside 3#2 in day-of-week, where one field must be ?, is refused."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    target_name = ctx.unique_name("sim2real-sched-target-")
    target_url = sqs.create_queue(QueueName=target_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=target_url))
    target_arn = sqs.get_queue_attributes(
        QueueUrl=target_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    role_arn = _create_scheduler_role(ctx, target_arn)

    expressions = {
        "last-day-of-month": "cron(0 12 L * ? *)",
        "last-day-of-week": "cron(0 12 ? * L *)",
        "nearest-weekday-to-3rd": "cron(0 12 3W * ? *)",
        "2nd-tuesday-of-month": "cron(0 12 ? * 3#2 *)",
    }

    created = {}
    for label, expr in expressions.items():
        name = ctx.unique_name(f"sim2real-sched-{label[:20]}-")
        _create_schedule_retrying(
            ctx,
            scheduler,
            Name=name,
            ScheduleExpression=expr,
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": target_arn, "RoleArn": role_arn},
        )
        ctx.on_cleanup(lambda name=name: scheduler.delete_schedule(Name=name))
        created[label] = (name, expr)

    for label, (name, expr) in created.items():
        got = scheduler.get_schedule(Name=name)
        assert got["ScheduleExpression"] == expr, (
            f"{label}: expected ScheduleExpression {expr!r}, got {got['ScheduleExpression']!r}"
        )
        assert got["State"] == "ENABLED", (
            f"{label}: expected State 'ENABLED', got {got['State']!r}"
        )

    # Control: the same wildcards in both day fields, which cron() never allows, are refused.
    bad_name = ctx.unique_name("sim2real-sched-bothdays-")
    bad_expr = "cron(0 12 L * 3#2 *)"
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression=bad_expr,
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": target_arn, "RoleArn": role_arn},
        )
    )
    assert (code, message) == ("ValidationException", f"Invalid Schedule Expression {bad_expr}."), (
        f"{bad_expr}: expected ValidationException 'Invalid Schedule Expression {bad_expr}.', got "
        f"{code!r} {message!r}"
    )
    not_found_code, _ = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"a refused create must not leave a schedule behind, got {not_found_code!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
