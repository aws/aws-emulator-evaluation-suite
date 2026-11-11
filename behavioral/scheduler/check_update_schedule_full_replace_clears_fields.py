"""update-schedule-full-replace-clears-fields."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schedule-full-replace-clears-fields"
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
    _wait_for_role_ready(ctx, arn)
    ctx._sched_role_arn = arn
    return arn


def _wait_for_role_ready(ctx, role_arn, max_wait_s=90, interval_s=5):
    """Probe with a throwaway schedule until Scheduler accepts the freshly-created execution
    role (IAM trust-policy propagation can lag CreateRole by tens of seconds)."""
    sch = ctx.client("scheduler")
    queue_arn = f"arn:aws:sqs:{ctx.region}:{_account_id(ctx)}:sim2real-behav-placeholder-target"
    probe_name = ctx.unique_name("sim2real-behav-sched-warmup-")
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            sch.create_schedule(
                Name=probe_name,
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="DISABLED",
                Target={"Arn": queue_arn, "RoleArn": role_arn},
            )
            sch.delete_schedule(Name=probe_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
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


def _track_schedule(ctx, name, group=None):
    sch = ctx.client("scheduler")

    def _del():
        kwargs = {"Name": name}
        if group:
            kwargs["GroupName"] = group
        try:
            sch.delete_schedule(**kwargs)
        except sch.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_del)

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchedule is a full replace: omitting a previously-set optional field clears it."""
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-" + "sched-")
    create_kwargs = _default_schedule_kwargs(ctx, name)
    create_kwargs["Description"] = "original description"
    sch.create_schedule(**create_kwargs)
    _track_schedule(ctx, name)

    got = sch.get_schedule(Name=name)
    assert got.get("Description") == "original description", (
        f"expected Description='original description' right after create, got {got.get('Description')!r}"
    )

    update_kwargs = _default_schedule_kwargs(ctx, name)  # no Description this time
    sch.update_schedule(**update_kwargs)

    got = sch.get_schedule(Name=name)
    assert not got.get("Description"), (
        f"UpdateSchedule omitted Description; expected it cleared (full replace), "
        f"but GetSchedule still returned {got.get('Description')!r}"
    )

    sch.delete_schedule(Name=name)
    try:
        sch.get_schedule(Name=name)
        raise AssertionError("expected ResourceNotFoundException from get_schedule after delete_schedule, "
                              "the schedule is still visible")
    except sch.exceptions.ResourceNotFoundException as exc:
        got_message = exc.response["Error"].get("Message")
        expected = f"Schedule {name} does not exist."
        assert got_message == expected, f"expected {expected!r}, got {got_message!r}"

    try:
        sch.update_schedule(**update_kwargs)
        raise AssertionError("expected ResourceNotFoundException, update_schedule succeeded against a "
                              "deleted schedule")
    except sch.exceptions.ResourceNotFoundException as exc:
        got_message = exc.response["Error"].get("Message")
        expected = f"Schedule {name} does not exist."
        assert got_message == expected, f"expected {expected!r}, got {got_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
