"""xsvc-lambda-3-scheduler-throwing-lambda-fails-to-onfailure-not-scheduler-dlq."""
from __future__ import annotations

import datetime
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-lambda-3-scheduler-throwing-lambda-fails-to-onfailure-not-scheduler-dlq"
GROUP = "error-propagation"
SERVICES = ["lambda", "scheduler", "sqs"]

_FIRE_OFFSET_S = 10
_RETRY_POLICY = {"MaximumRetryAttempts": 1, "MaximumEventAgeInSeconds": 60}
_DELIVERY_TIMEOUT_S = 150
# How long the Scheduler DLQ is drained once every expected delivery has arrived.
_QUIET_S = 6.0


# timing:real-time — schedule: 10 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A Scheduler Lambda target that throws lands on the function's OnFailure destination, not the
    schedule's DeadLetterConfig queue; a barrier schedule on a deleted function proves the DLQ works.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
    """
    _log_groups_for(ctx)  # registered first, so it runs last
    sch = ctx.client("scheduler")
    lam = ctx.client("lambda")

    on_failure = _create_queue(ctx)
    dlq = _create_queue(ctx)

    lambda_role = _create_role(
        ctx, "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": on_failure["arn"]}],
    )
    thrower = _create_function(ctx, _THROW_CODE, lambda_role, {"UNUSED_VAR": "x"})
    barrier_fn = _create_function(ctx, _THROW_CODE, lambda_role, {"UNUSED_VAR": "x"})

    lam.put_function_event_invoke_config(
        FunctionName=thrower["name"], MaximumRetryAttempts=0, MaximumEventAgeInSeconds=60,
        DestinationConfig={"OnFailure": {"Destination": on_failure["arn"]}},
    )
    ctx.on_cleanup(lambda: lam.delete_function_event_invoke_config(FunctionName=thrower["name"]))
    cfg = lam.get_function_event_invoke_config(FunctionName=thrower["name"])
    assert cfg["DestinationConfig"]["OnFailure"]["Destination"] == on_failure["arn"], (
        f"OnFailure destination not stored: {cfg.get('DestinationConfig')!r}"
    )

    sched_role = _create_role(
        ctx, "scheduler.amazonaws.com",
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction",
          "Resource": [thrower["arn"], barrier_fn["arn"]]},
         {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq["arn"]}],
    )

    marker = ctx.unique_name("throw-")
    payload = {"marker": marker, "mode": "throw"}
    thrower_sched, _ = _create_schedule(
        ctx,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": thrower["arn"], "RoleArn": sched_role, "Input": json.dumps(payload),
                "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": dlq["arn"]}},
    )
    # Created after the thrower's schedule, so the shared role has propagated and the barrier's
    # instant still lies ahead of the function delete below.
    barrier_sched, nominal = _create_schedule(
        ctx,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": barrier_fn["arn"], "RoleArn": sched_role,
                "Input": json.dumps({"marker": "barrier"}),
                "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": dlq["arn"]}},
    )
    thrower_arn = sch.get_schedule(Name=thrower_sched)["Arn"]
    barrier_arn = sch.get_schedule(Name=barrier_sched)["Arn"]
    lam.delete_function(FunctionName=barrier_fn["name"])
    now = datetime.datetime.now(datetime.timezone.utc)
    assert now < nominal, (
        f"setup overran the scheduled instant ({nominal.isoformat()} <= {now.isoformat()})"
    )

    # (2) The barrier: the shared DLQ demonstrably receives Scheduler-level failures.
    barrier_dead = _await_message(ctx, dlq["url"], timeout_s=_budget_s(ctx, _FIRE_OFFSET_S + _DELIVERY_TIMEOUT_S),
                                  description="the barrier schedule's dead-letter event")
    b_attrs = {k: v.get("StringValue") for k, v in
               (barrier_dead.get("MessageAttributes") or {}).items()}
    assert b_attrs.get("SCHEDULE_ARN") == barrier_arn, (
        f"the first dead-letter event in the shared DLQ is not the barrier's: "
        f"SCHEDULE_ARN={b_attrs.get('SCHEDULE_ARN')!r} (thrower is {thrower_arn!r}); "
        f"attrs {b_attrs!r}"
    )
    assert b_attrs.get("ERROR_CODE") == "ResourceNotFoundException", (
        f"barrier ERROR_CODE is {b_attrs.get('ERROR_CODE')!r}, expected 'ResourceNotFoundException'"
    )
    assert b_attrs.get("ERROR_MESSAGE") == f"Function not found: {barrier_fn['arn']}", (
        f"barrier ERROR_MESSAGE is {b_attrs.get('ERROR_MESSAGE')!r}"
    )

    # (3) The thrower's failure lands on Lambda's OnFailure destination.
    rec_msg = _await_message(ctx, on_failure["url"], timeout_s=_budget_s(ctx, _DELIVERY_TIMEOUT_S),
                             description="the thrower's failure record on its OnFailure queue")
    record = json.loads(rec_msg["Body"])
    rc = record.get("requestContext", {})
    assert record.get("version") == "1.0", f"record version is {record.get('version')!r}"
    assert rc.get("condition") == "RetriesExhausted", (
        f"requestContext.condition is {rc.get('condition')!r}, expected 'RetriesExhausted'"
    )
    assert rc.get("approximateInvokeCount") == 1, (
        f"MaximumRetryAttempts=0 must yield approximateInvokeCount 1, got "
        f"{rc.get('approximateInvokeCount')!r}"
    )
    assert rc.get("functionArn", "").startswith(thrower["arn"]), (
        f"requestContext.functionArn {rc.get('functionArn')!r} is not the thrower {thrower['arn']!r}"
    )
    assert record.get("requestPayload") == payload, (
        f"requestPayload {record.get('requestPayload')!r} is not the schedule Input {payload!r}"
    )
    assert record.get("responseContext", {}).get("functionError") == "Unhandled", (
        f"responseContext is {record.get('responseContext')!r}, expected functionError Unhandled"
    )
    rp = record.get("responsePayload") or {}
    assert rp.get("errorType") == "RuntimeError" and rp.get("errorMessage") == f"scheduled-failure:{marker}", (
        f"responsePayload does not carry the handler's RuntimeError: {rp!r}"
    )

    # (4) The thrower never reaches the Scheduler DLQ: Lambda accepted its invoke (the OnFailure
    # record proves it), so no Scheduler retry remains that could dead-letter it later.
    rest = _drain(ctx, dlq["url"], window_s=_QUIET_S)
    thrower_dead = [m for m in rest if (m.get("MessageAttributes") or {}).get(
        "SCHEDULE_ARN", {}).get("StringValue") != barrier_arn]
    assert not thrower_dead, (
        f"the throwing target was ALSO dead-lettered by Scheduler -- the failure was counted in "
        f"both layers: {[(m.get('MessageAttributes'), m['Body']) for m in thrower_dead]!r}"
    )
    dup = [json.loads(m["Body"]) for m in _drain(ctx, on_failure["url"], window_s=4.0)]
    assert all(d.get("requestPayload") == payload for d in dup), (
        f"the OnFailure queue received a record for some other payload: {dup!r}"
    )


_THROW_CODE = """
def handler(event, context):
    raise RuntimeError("scheduled-failure:" + str(event.get("marker")))
"""


_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true"}
_ROLE_PROPAGATION_S = 90
_LOG_REAP_BOUND_S = 40
_LOG_QUIET_S = 20
_LOG_GROUPS: dict = {}


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _error_code(fn) -> str:
    """The AWS error code `fn` raised. A call that SUCCEEDS is itself the finding, so it raises
    rather than returning a falsy sentinel that would read like a naming mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "<no code>")
    raise AssertionError(f"call was expected to fail but succeeded: {result!r}")


def _create_queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]
    return {"url": url, "arn": arn}


def _create_role(ctx, service: str, statements: list) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    if service == "lambda.amazonaws.com":
        statements = statements + [{"Effect": "Allow", "Action": [
            "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*"}]
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    return arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=name, PolicyName=pname)
    iam.delete_role(RoleName=name)


def _log_groups_for(ctx) -> list:
    """The single log-group cleanup for this run; registered first in run() so LIFO runs it last,
    after every function, queue and role is deleted."""
    key = id(ctx)
    if key not in _LOG_GROUPS:
        groups: list = []
        _LOG_GROUPS[key] = groups
        ctx.on_cleanup(lambda: _reap_log_groups(ctx, _LOG_GROUPS.pop(key, groups)))
    return _LOG_GROUPS[key]


def _reap_log_groups(ctx, groups: list) -> None:
    """Delete each /aws/lambda/<fn> until all stay absent for a quiet window: a buffered log
    stream can flush after DeleteFunction and recreate the group."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + _LOG_REAP_BOUND_S
    absent_since = None
    while time.monotonic() < deadline:
        present = False
        for group in groups:
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if any(g["logGroupName"] == group for g in found):
                present = True
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                        raise
        if present:
            absent_since = None
        elif absent_since is None:
            absent_since = time.monotonic()
        elif time.monotonic() - absent_since >= _LOG_QUIET_S:
            return
        time.sleep(4)
    raise RuntimeError(
        f"log groups {groups!r} did not stay deleted within {_LOG_REAP_BOUND_S}s"
    )


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_function(ctx, code: str, role_arn: str, env: dict) -> dict:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    # Deleted by the run's single log-group cleanup, which LIFO runs after this delete.
    _log_groups_for(ctx).append(f"/aws/lambda/{name}")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip(code)}, Timeout=30, MemorySize=128,
                Environment={"Variables": env}, Tags=dict(_TAGS),
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException" \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_function(ctx, name))
    deadline = time.monotonic() + 90
    while lam.get_function_configuration(FunctionName=name).get("State") != "Active":
        assert time.monotonic() < deadline, f"function {name} never became Active"
        time.sleep(2)
    return {"name": name, "arn": arn}


def _delete_function(ctx, name: str) -> None:
    try:
        ctx.client("lambda").delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_schedule(ctx, **kwargs) -> tuple[str, datetime.datetime]:
    """CreateSchedule assumes the role to validate it; retry the IAM-propagation
    ValidationException within a bound. Each attempt targets at(now + _FIRE_OFFSET_S)."""
    sch = ctx.client("scheduler")
    name = _xname(ctx, "sched")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        nominal = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + \
            datetime.timedelta(seconds=_FIRE_OFFSET_S)
        try:
            sch.create_schedule(
                Name=name, ScheduleExpression=f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})",
                **kwargs,
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationException" \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return name, nominal


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_message(ctx, url: str, *, timeout_s: float, description: str) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
                                   MessageAttributeNames=["All"]).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description}: nothing arrived within {timeout_s:.0f}s")


def _drain(ctx, url: str, *, window_s: float) -> list:
    """Receive-and-delete everything visible for a bounded window."""
    sqs = ctx.client("sqs")
    out: list = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = int(max(1, min(5, deadline - time.monotonic())))
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait,
                                     MessageAttributeNames=["All"]).get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
