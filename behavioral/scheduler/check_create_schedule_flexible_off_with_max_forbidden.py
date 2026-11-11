"""create-schedule-flexible-off-with-max-forbidden."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-flexible-off-with-max-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['scheduler']

def _account_id(ctx):
    cached = getattr(ctx, "_sched_account_id", None)
    if cached is None:
        try:
            cached = ctx.client("sts").get_caller_identity()["Account"]
        except Exception:
            cached = ctx.account
        ctx._sched_account_id = cached
    return cached


def _scheduler_role_arn(ctx):
    cached = getattr(ctx, "_sched_role_arn", None)
    if cached is not None:
        return cached
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    assume_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=assume_doc,
        Tags=[{"Key": "sim2real-behav", "Value": "create-schedule-flexible-off-with-max-forbidden"}],
    )

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
    arn = resp["Role"]["Arn"]
    ctx._sched_role_arn = arn
    return arn


def _create_schedule_retrying(sch, *, timeout_s=45.0, interval_s=3.0, **kwargs):
    """IAM trust/policy attachment is eventually consistent, so the positive-control create can
    briefly fail with AccessDenied/ValidationException; retry only that call, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


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


def _default_schedule_kwargs(ctx, name, group=None, expression="rate(5 minutes)", target=None, state=None, flexible_window=None, **extra):
    kwargs = {
        "Name": name,
        "ScheduleExpression": expression,
        "FlexibleTimeWindow": flexible_window or _flexible_window("OFF"),
        "Target": target or _sqs_target(
            f"arn:aws:sqs:{ctx.region}:{_account_id(ctx)}:sim2real-behav-placeholder-target",
            _scheduler_role_arn(ctx),
        ),
    }
    if group:
        kwargs["GroupName"] = group
    if state:
        kwargs["State"] = state
    kwargs.update(extra)
    return kwargs


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises rather
    than being reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedule with Mode=OFF and MaximumWindowInMinutes set is rejected with
    ValidationException and persists nothing; the same request without the maximum succeeds."""
    sch = ctx.client("scheduler")

    good_name = ctx.unique_name("sim2real-behav-sched-ok-")
    good_kwargs = _default_schedule_kwargs(ctx, good_name, flexible_window=_flexible_window("OFF"))
    _create_schedule_retrying(sch, **good_kwargs)
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=good_name))
    good = sch.get_schedule(Name=good_name)
    assert good["FlexibleTimeWindow"]["Mode"] == "OFF", (
        f"positive control: expected Mode=OFF, got {good['FlexibleTimeWindow']!r}"
    )
    assert "MaximumWindowInMinutes" not in good["FlexibleTimeWindow"], (
        f"positive control: MaximumWindowInMinutes should be absent for Mode=OFF, "
        f"got {good['FlexibleTimeWindow']!r}"
    )

    bad_name = ctx.unique_name("sim2real-behav-sched-bad-")
    bad_kwargs = _default_schedule_kwargs(ctx, bad_name, flexible_window=_flexible_window("OFF", max_minutes=15))
    code, message = _error_code(lambda: sch.create_schedule(**bad_kwargs))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "MaximumWindowInMinutes must not be provided when FlexibleTimeWindowMode is set to OFF."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    not_found_code, not_found_message = _error_code(lambda: sch.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected OFF+max create must not persist a schedule, got {not_found_code}"
    )
    assert not_found_message == f"Schedule {bad_name} does not exist.", (
        f"expected the not-found message for {bad_name!r}, got {not_found_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
