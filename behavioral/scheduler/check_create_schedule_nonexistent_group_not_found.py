"""create-schedule-nonexistent-group-not-found."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-nonexistent-group-not-found"
GROUP = 'error-semantics'
SERVICES = ['scheduler']

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _del_role():
        try:
            for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
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


def _create_schedule_with_retry(sch, kwargs, timeout_s=30.0):
    """A freshly created IAM role can be rejected by Scheduler until IAM trust
    propagates (a ValidationException); retry CreateSchedule on that window instead of a fixed
    sleep. Every other refusal raises at once."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"create_schedule did not succeed within {timeout_s}s: {last_err}")


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
            f"arn:aws:sqs:{ctx.region}:{ctx.account}:sim2real-behav-placeholder-target",
            _scheduler_role_arn(ctx),
        ),
    }
    if group:
        kwargs["GroupName"] = group
    if state:
        kwargs["State"] = state
    kwargs.update(extra)
    return kwargs


def _error(fn):
    """Call fn(); return the (code, message, HTTP status) it is refused with. An unexpected
    success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _schedule_exists(ctx, name, group=None):
    sch = ctx.client("scheduler")
    try:
        kwargs = {"Name": name}
        if group:
            kwargs["GroupName"] = group
        sch.get_schedule(**kwargs)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a schedule referencing a non-existent GroupName raises
    ResourceNotFoundException, while the identical call against the real "default"
    group succeeds and the rejected schedule is never persisted."""
    sch = ctx.client("scheduler")
    control_name = ctx.unique_name("sim2real-behav-" + "sched-ctl-")
    name = ctx.unique_name("sim2real-behav-" + "sched-")
    bogus_group = ctx.unique_name("sim2real-behav-" + "no-such-group-")

    # Positive control: the identical shape of call succeeds against the real "default" group.
    _create_schedule_with_retry(sch, _default_schedule_kwargs(ctx, control_name))
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=control_name))
    assert _schedule_exists(ctx, control_name), "control schedule was not created in the default group"

    # Break exactly one thing: point the identical call at a group that was never created.
    code, message, status = _error(
        lambda: sch.create_schedule(**_default_schedule_kwargs(ctx, name, group=bogus_group))
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert status == 404, f"expected HTTP 404, got {status!r}"
    expected_message = f"Schedule group {bogus_group} does not exist."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Effect absent: an independent read at the destination confirms nothing was persisted.
    assert not _schedule_exists(ctx, name, group=bogus_group), (
        "schedule was persisted despite referencing a non-existent group"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
