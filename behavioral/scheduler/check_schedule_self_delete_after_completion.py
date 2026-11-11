"""schedule-self-delete-after-completion."""
from __future__ import annotations

import json
import time
import datetime
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-self-delete-after-completion"
GROUP = 'data-plane'
SERVICES = ['scheduler']

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS_DICT = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. The BOUNDED RETRY is the wait; the short sleep only
# makes it cheaper.
_CREATE_TIMEOUT_S = 180

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
    # IAM is eventually consistent; the bounded retry in _create_schedule_with_role_retry is the wait.
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


def _create_schedule_with_role_retry(sch, **kwargs):
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound."""
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(3)


def _track_queue(ctx, queue_url):
    sqs = ctx.client("sqs")
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))


def _create_test_queue(ctx):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sched-target-")
    queue_url = sqs.create_queue(QueueName=name, tags=_MANAGED_TAGS_DICT)["QueueUrl"]
    _track_queue(ctx, queue_url)
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return queue_url, queue_arn


def _allow_role_to_send(ctx, queue_url, queue_arn, role_arn):
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": role_arn},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
        }],
    }
    try:
        sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    except Exception:
        # Identity-based permissions on the role are already sufficient in-account.
        pass


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a
    target that still serves the self-deleted schedule never reads as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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

# timing:real-time — schedule: 75 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-delete.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """Temporal: a one-time 'at()' schedule fires near its due time, delivers its
    Input payload to the target, and with ActionAfterCompletion=DELETE removes itself.
    """
    sch = ctx.client("scheduler")

    queue_url, queue_arn = _create_test_queue(ctx)
    role_arn = _scheduler_role_arn(ctx)
    _allow_role_to_send(ctx, queue_url, queue_arn, role_arn)

    name = ctx.unique_name("sim2real-behav-" + "sched-")
    payload = {"marker": name}
    fire_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=75)
    expression = "at(" + fire_at.strftime("%Y-%m-%dT%H:%M:%S") + ")"

    target = _sqs_target(queue_arn, role_arn, input_payload=payload)
    kwargs = _default_schedule_kwargs(ctx, 
        name,
        expression=expression,
        target=target,
        state="ENABLED",
    )
    kwargs["ScheduleExpressionTimezone"] = "UTC"
    kwargs["ActionAfterCompletion"] = "DELETE"
    _create_schedule_with_role_retry(sch, **kwargs)
    _track_schedule(ctx, name)

    # Before the due time the schedule must still exist (no premature firing/deletion).
    assert _schedule_exists(ctx, name), "one-time schedule vanished before its due time"

    def probe():
        msgs = ctx.client("sqs").receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        return msgs.get("Messages", [])

    messages = _poll_until(probe, lambda msgs: len(msgs) > 0, timeout_s=180, interval_s=2)
    body = json.loads(messages[0]["Body"])
    assert body.get("marker") == name, f"unexpected payload delivered: {body}"

    # ActionAfterCompletion=DELETE must remove the schedule after it completes.
    _poll_until(
        lambda: _schedule_exists(ctx, name),
        lambda exists: not exists,
        timeout_s=120,
        interval_s=3,
    )
    missing = f"Schedule {name} does not exist."
    get_code, get_message = _error(lambda: sch.get_schedule(Name=name))
    assert get_code == "ResourceNotFoundException", (
        f"expected GetSchedule to report ResourceNotFoundException for the self-deleted "
        f"schedule {name!r}, got {get_code!r}"
    )
    assert get_message == missing, f"expected message {missing!r}, got {get_message!r}"

    # The self-delete is not just absence from GetSchedule: a mutation on the now-dead id
    # must fail the same way, not silently no-op.
    delete_code, delete_message = _error(lambda: sch.delete_schedule(Name=name))
    assert delete_code == "ResourceNotFoundException", (
        f"expected DeleteSchedule on the already self-deleted schedule {name!r} to report "
        f"ResourceNotFoundException, got {delete_code!r}"
    )
    assert delete_message == missing, f"expected message {missing!r}, got {delete_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
