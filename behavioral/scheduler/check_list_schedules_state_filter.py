"""list-schedules-state-filter."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-schedules-state-filter"
GROUP = 'state-machine'
SERVICES = ['scheduler']

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]

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
        RoleName=role_name, AssumeRolePolicyDocument=assume_doc, Tags=_MANAGED_TAGS_KV
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


def _create_schedule_retrying(ctx, sch, **kwargs):
    """IAM role/policy propagation to the Scheduler service can lag CreateRole by tens of
    seconds; retry CreateSchedule itself against that window instead of sleeping blind."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(3)
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
    """ListSchedules with State filters to only schedules currently in that state."""
    sch = ctx.client("scheduler")
    enabled_name = ctx.unique_name("sim2real-behav-" + "sched-en-")
    _create_schedule_retrying(ctx, sch, **_default_schedule_kwargs(ctx, enabled_name, state="ENABLED"))
    _track_schedule(ctx, enabled_name)

    disabled_name = ctx.unique_name("sim2real-behav-" + "sched-dis-")
    _create_schedule_retrying(ctx, sch, **_default_schedule_kwargs(ctx, disabled_name, state="DISABLED"))
    _track_schedule(ctx, disabled_name)

    resp = sch.list_schedules(State="DISABLED")
    names = {s["Name"] for s in resp["Schedules"]}
    assert disabled_name in names, f"expected DISABLED schedule {disabled_name!r} in State=DISABLED list, got {names!r}"
    assert enabled_name not in names, f"ENABLED schedule {enabled_name!r} leaked into State=DISABLED list: {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
