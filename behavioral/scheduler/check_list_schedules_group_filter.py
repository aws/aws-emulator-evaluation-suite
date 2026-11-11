"""list-schedules-group-filter."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-schedules-group-filter"
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


def _create_schedule_with_role_propagation_retry(ctx, kwargs, *, timeout_s=60, interval_s=3.0):
    """IAM is eventually consistent; Scheduler validates the execution role synchronously
    at CreateSchedule time and rejects it with ValidationException until it has propagated.
    Bound the wait to a deadline instead of a blind sleep, and raise on genuine timeout."""
    sch = ctx.client("scheduler")
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return sch.create_schedule(**kwargs)
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None
            if code == "ValidationException":
                last_error = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"create_schedule for {kwargs.get('Name')!r} never succeeded within {timeout_s}s "
        f"(role propagation timeout); last error: {last_error!r}"
    )


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


def _track_group(ctx, name):
    sch = ctx.client("scheduler")
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=name))


def _list_group_schedule_names(ctx, group):
    sch = ctx.client("scheduler")
    names = set()
    token = None
    while True:
        kw = {"GroupName": group, "MaxResults": 100}
        if token:
            kw["NextToken"] = token
        resp = sch.list_schedules(**kw)
        names.update(s["Name"] for s in resp["Schedules"])
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _poll_until(probe, predicate, *, timeout_s=30, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSchedules with GroupName filters to only schedules within that group."""
    sch = ctx.client("scheduler")
    group = ctx.unique_name("sim2real-behav-" + "sched-grp-")
    sch.create_schedule_group(Name=group, Tags=_MANAGED_TAGS_KV)
    _track_group(ctx, group)

    in_group = ctx.unique_name("sim2real-behav-" + "sched-in-")
    _create_schedule_with_role_propagation_retry(
        ctx, _default_schedule_kwargs(ctx, in_group, group=group)
    )
    _track_schedule(ctx, in_group, group)

    outside_group = ctx.unique_name("sim2real-behav-" + "sched-out-")
    _create_schedule_with_role_propagation_retry(
        ctx, _default_schedule_kwargs(ctx, outside_group)
    )
    _track_schedule(ctx, outside_group)

    names = _poll_until(
        lambda: _list_group_schedule_names(ctx, group),
        lambda ns: in_group in ns,
        description="in-group schedule listed under its group",
    )
    assert in_group in names, f"expected {in_group!r} in group listing, got {names!r}"
    assert outside_group not in names, f"group filter leaked {outside_group!r}: {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
