"""update-schedule-change-group-forbidden."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schedule-change-group-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['scheduler']

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_doc, Tags=_MANAGED_TAGS)

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


def _create_schedule_with_role_propagation_retry(scheduler, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs) -> None:
    """Freshly-created IAM roles/policies are eventually consistent: CreateSchedule can
    reject a just-minted execution role with a ValidationException until the role has
    propagated. Retry the create for a bounded window rather than treating this as a
    hard failure or waiting out a fixed, unconditional sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            scheduler.create_schedule(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "execution role" in msg and time.monotonic() < deadline:
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
        sch.delete_schedule(**kwargs)

    ctx.on_cleanup(_del)


def _track_group(ctx, name):
    sch = ctx.client("scheduler")
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=name))


def _error(fn):
    """Call fn(); return its ClientError Error dict (Code, Message). An unexpected SUCCESS raises -- an
    emulator that accepts a cross-group move real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected UpdateSchedule to reject the cross-group move, but it SUCCEEDED: {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: UpdateSchedule must reject an attempt to move a schedule to a
    different group. A positive control proves an ordinary in-group UpdateSchedule works first,
    so the rejection cannot be mistaken for a target that rejects every update."""
    sch = ctx.client("scheduler")
    group_a = ctx.unique_name("sim2real-behav-" + "sched-grp-a-")
    group_b = ctx.unique_name("sim2real-behav-" + "sched-grp-b-")
    sch.create_schedule_group(Name=group_a, Tags=_MANAGED_TAGS)
    _track_group(ctx, group_a)
    sch.create_schedule_group(Name=group_b, Tags=_MANAGED_TAGS)
    _track_group(ctx, group_b)

    name = ctx.unique_name("sim2real-behav-" + "sched-")
    create_kwargs = _default_schedule_kwargs(ctx, name, group=group_a)
    _create_schedule_with_role_propagation_retry(sch, **create_kwargs)
    _track_schedule(ctx, name, group_a)

    # Positive control: an ordinary in-group update succeeds. Without this, "rejects a
    # cross-group move" would be indistinguishable from "rejects every UpdateSchedule call".
    control_kwargs = _default_schedule_kwargs(ctx, name, group=group_a, expression="rate(10 minutes)")
    sch.update_schedule(**control_kwargs)
    after_control = sch.get_schedule(Name=name, GroupName=group_a)
    assert after_control["ScheduleExpression"] == "rate(10 minutes)", (
        f"positive-control update did not take effect: expected ScheduleExpression "
        f"'rate(10 minutes)', got {after_control.get('ScheduleExpression')!r}"
    )

    update_kwargs = _default_schedule_kwargs(ctx, name, group=group_b)
    err = _error(lambda: sch.update_schedule(**update_kwargs))
    assert err.get("Code") == "ResourceNotFoundException", (
        f"expected update to reject cross-group move with ResourceNotFoundException, got {err.get('Code')!r}"
    )
    expected_message = f"Schedule {name} does not exist."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Terminal independent read at the destination: the schedule is still addressable in
    # group_a, and the positive control's change survived the rejected negative attempt
    # untouched -- proving the rejected call had no side effect at all.
    still = sch.get_schedule(Name=name, GroupName=group_a)
    assert still["GroupName"] == group_a, (
        f"schedule moved out of {group_a!r} despite the rejected UpdateSchedule call: "
        f"now reports GroupName {still.get('GroupName')!r}"
    )
    assert still["ScheduleExpression"] == "rate(10 minutes)", (
        f"schedule state changed after the rejected cross-group update: expected the "
        f"positive control's 'rate(10 minutes)', got {still.get('ScheduleExpression')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
