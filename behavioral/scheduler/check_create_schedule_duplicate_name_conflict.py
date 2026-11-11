"""create-schedule-duplicate-name-conflict."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-duplicate-name-conflict"
GROUP = 'error-semantics'
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_doc)

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


def _create_schedule_with_retry(sch, kwargs, timeout_s=180, interval_s=3):
    """CreateSchedule with a freshly-created execution role can be refused with
    ValidationException until the role's trust policy propagates to the Scheduler service
    (tens of seconds). Retry that specific, message-scoped refusal within a bound; anything
    else raises immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sch.create_schedule(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if code != "ValidationException" or "assume the role" not in msg or time.monotonic() >= deadline:
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
        sch.delete_schedule(**kwargs)

    ctx.on_cleanup(_del)


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_or_none(sch, name):
    try:
        return sch.get_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _poll_until_absent(sch, name, timeout_s=60, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        got = _get_or_none(sch, name)
        if got is None:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"schedule {name!r} still present {timeout_s}s after DeleteSchedule")
        time.sleep(interval_s)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a schedule with a Name that already exists raises ConflictException, the
    rejected duplicate leaves the original untouched, and freeing the name (delete) makes the
    identical call succeed again -- proving the refusal is specifically about name collision."""
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-" + "sched-")
    kwargs = _default_schedule_kwargs(ctx, name)

    # Positive control: the name is free, so the first create succeeds.
    _create_schedule_with_retry(sch, kwargs)
    _track_schedule(ctx, name)
    before = sch.get_schedule(Name=name)

    # Break: create again with the identical Name.
    code, message = _error_code(lambda: sch.create_schedule(**kwargs))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected_message = f"Schedule {name} already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected duplicate must not have touched the original resource --
    # an independent read at the destination, not the mutating call's own response.
    after = sch.get_schedule(Name=name)
    assert after["Arn"] == before["Arn"] and after["CreationDate"] == before["CreationDate"], (
        f"the rejected duplicate create mutated the original schedule: before={before!r} after={after!r}"
    )

    # Restore: free the name and prove it via an independent read, then...
    sch.delete_schedule(Name=name)
    _poll_until_absent(sch, name)

    # ...the identical call now succeeds, confirming the earlier refusal was the name
    # collision and nothing else about this request shape.
    sch.create_schedule(**kwargs)
    recreated = sch.get_schedule(Name=name)
    assert recreated["Name"] == name, f"expected the freed name to be recreatable, got {recreated!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
