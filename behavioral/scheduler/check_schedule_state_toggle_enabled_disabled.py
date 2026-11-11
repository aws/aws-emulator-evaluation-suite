"""schedule-state-toggle-enabled-disabled."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-state-toggle-enabled-disabled"
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


def _create_schedule_retrying(ctx, sch, **kwargs):
    """IAM role trust/policy propagation is eventually consistent; retry CreateSchedule
    on Scheduler's own validation of the role, bounded by a deadline, instead of a blind sleep."""
    last_exc = None
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as e:
            last_exc = e
            if e.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3.0)
                continue
            raise
    raise last_exc


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
        sch.delete_schedule(**kwargs)

    ctx.on_cleanup(_del)

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchedule can flip State ENABLED<->DISABLED and GetSchedule reflects the change."""
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-" + "sched-")
    create_kwargs = _default_schedule_kwargs(ctx, name, state="ENABLED")
    _create_schedule_retrying(ctx, sch, **create_kwargs)
    _track_schedule(ctx, name)

    got = sch.get_schedule(Name=name)
    assert got["State"] == "ENABLED", f"expected State=ENABLED after create, got {got['State']!r}"

    update_kwargs = dict(create_kwargs)
    update_kwargs["State"] = "DISABLED"
    sch.update_schedule(**update_kwargs)

    got = sch.get_schedule(Name=name)
    assert got["State"] == "DISABLED", f"expected State=DISABLED after update, got {got['State']!r}"

    update_kwargs["State"] = "ENABLED"
    sch.update_schedule(**update_kwargs)
    got = sch.get_schedule(Name=name)
    assert got["State"] == "ENABLED", f"expected State=ENABLED after re-enable, got {got['State']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
