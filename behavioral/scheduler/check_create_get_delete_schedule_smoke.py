"""create-get-delete-schedule-smoke."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-get-delete-schedule-smoke"
GROUP = 'state-machine'
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
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
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
    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="scheduler-target",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
            }),
        )
    except Exception:
        pass
    arn = resp["Role"]["Arn"]
    ctx._sched_role_arn = arn
    return arn


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


def _track_schedule(ctx, name, group=None):
    sch = ctx.client("scheduler")

    def _del():
        kwargs = {"Name": name}
        if group:
            kwargs["GroupName"] = group
        try:
            sch.delete_schedule(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_del)


def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"the call was expected to be REFUSED but it succeeded, returning {result!r}")


def _create_schedule_with_role_propagation_retry(sch, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs):
    """Freshly-created IAM roles/policies are eventually consistent: CreateSchedule can reject a
    just-minted execution role with a ValidationException until the role has propagated. Retry the
    create for a bounded window rather than treating this as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "execution role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule -> GetSchedule reflects submitted fields -> DeleteSchedule removes it."""
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-" + "sched-")
    kwargs = _default_schedule_kwargs(ctx, name, expression="rate(10 minutes)", state="ENABLED")
    resp = _create_schedule_with_role_propagation_retry(sch, **kwargs)
    _track_schedule(ctx, name)
    assert resp["ScheduleArn"].endswith(f"/{name}") or name in resp["ScheduleArn"]

    got = sch.get_schedule(Name=name)
    assert got["Name"] == name
    assert got["ScheduleExpression"] == "rate(10 minutes)"
    assert got["State"] == "ENABLED"
    assert got["FlexibleTimeWindow"]["Mode"] == "OFF"

    sch.delete_schedule(Name=name)
    code, message = _error_code(lambda: sch.get_schedule(Name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Schedule {name} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
