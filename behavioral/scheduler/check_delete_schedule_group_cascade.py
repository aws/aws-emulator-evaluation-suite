"""delete-schedule-group-cascade."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-schedule-group-cascade"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def _del_role():
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

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


def _create_schedule_with_role_propagation_retry(sch, kwargs, *, timeout_s=90, interval_s=3):
    """CreateSchedule assumes the target role to validate it; a freshly-minted role is not
    immediately assumable because IAM is eventually consistent. Retry within a bound instead of
    guessing how long propagation takes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sch.create_schedule(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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


def _track_group(ctx, name):
    sch = ctx.client("scheduler")

    def _del():
        try:
            sch.delete_schedule_group(Name=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_del)


def _error(fn):
    """The (code, message) a call was refused with. Raises if the call unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail but succeeded")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _schedule_exists(ctx, name, group=None):
    sch = ctx.client("scheduler")
    kwargs = {"Name": name}
    if group:
        kwargs["GroupName"] = group
    try:
        sch.get_schedule(**kwargs)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise


def _group_exists(ctx, name):
    sch = ctx.client("scheduler")
    try:
        sch.get_schedule_group(Name=name)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a schedule group cascades to its member schedule: both become unreachable by an
    independent read (the specific ResourceNotFoundException, not just absence), and a further
    delete on the already-dead group also fails rather than silently no-op'ing."""
    sch = ctx.client("scheduler")
    group = ctx.unique_name("sim2real-behav-" + "sched-grp-")
    sch.create_schedule_group(Name=group, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    _track_group(ctx, group)

    name = ctx.unique_name("sim2real-behav-" + "sched-")
    _create_schedule_with_role_propagation_retry(
        sch, _default_schedule_kwargs(ctx, name, group=group)
    )
    _track_schedule(ctx, name, group)

    assert _schedule_exists(ctx, name, group), f"schedule {name} not visible in group {group} right after creation"

    sch.delete_schedule_group(Name=group)

    # Group should end up gone (or DELETING transiently), and so should the member schedule.
    _poll_until(
        lambda: _group_exists(ctx, group),
        lambda exists: not exists,
        timeout_s=45,
        interval_s=1,
    )
    gone_message = f"Schedule group {group} does not exist."
    assert _error(lambda: sch.get_schedule_group(Name=group)) == ("ResourceNotFoundException", gone_message), (
        f"group {group} did not report the specific not-found code and message after its own cascade delete"
    )

    _poll_until(
        lambda: _schedule_exists(ctx, name, group),
        lambda exists: not exists,
        timeout_s=45,
        interval_s=1,
    )
    member_error = _error(lambda: sch.get_schedule(Name=name, GroupName=group))
    assert member_error == ("ResourceNotFoundException", gone_message), (
        f"member schedule {name} did not report the specific not-found code and message after its "
        f"group's cascade delete: got {member_error!r}"
    )

    # The dead group also refuses a mutation, not just a read.
    redelete_error = _error(lambda: sch.delete_schedule_group(Name=group))
    assert redelete_error == ("ResourceNotFoundException", gone_message), (
        f"a second delete of the already-deleted group {group} did not report the specific "
        f"not-found code and message: got {redelete_error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
