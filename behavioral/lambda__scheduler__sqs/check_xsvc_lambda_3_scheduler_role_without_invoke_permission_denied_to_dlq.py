"""xsvc-lambda-3-scheduler-role-without-invoke-permission-denied-to-dlq."""
from __future__ import annotations

import datetime
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-lambda-3-scheduler-role-without-invoke-permission-denied-to-dlq"
GROUP = "permission-boundary"
SERVICES = ["lambda", "scheduler", "sqs"]

_FIRE_OFFSET_S = 75
_RETRY_POLICY = {"MaximumRetryAttempts": 1, "MaximumEventAgeInSeconds": 60}
_DELIVERY_TIMEOUT_S = 150
_QUIET_SLACK_S = 20
# An IAM denial on the Lambda Invoke is
# non-retryable, so RETRY_ATTEMPTS is "0" despite MaximumRetryAttempts=1.
_EXPECTED_ERROR_CODE = "AccessDeniedException"


# timing:real-time — schedule: 75 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
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
    """A schedule whose role lacks lambda:InvokeFunction never invokes its target and dead-letters
    one AccessDeniedException event (RETRY_ATTEMPTS=0, original Payload), while a schedule on the
    same function at the same instant with the permission invokes it and leaves its DLQ empty."""
    _log_groups_for(ctx)  # registered first, so it runs last
    sch = ctx.client("scheduler")

    sink = _create_queue(ctx)
    dlq = _create_queue(ctx)
    control_dlq = _create_queue(ctx)
    lambda_role = _create_role(
        ctx, "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink["arn"]}],
    )
    fn = _create_function(ctx, _SINK_CODE, lambda_role, {"SINK_URL": sink["url"]})

    denied_role = _create_role(
        ctx, "scheduler.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq["arn"]}],
    )
    permitted_role = _create_role(
        ctx, "scheduler.amazonaws.com",
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn["arn"]},
         {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": control_dlq["arn"]}],
    )

    nominal = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + \
        datetime.timedelta(seconds=_FIRE_OFFSET_S)
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"
    denied_marker = ctx.unique_name("denied-")
    permitted_marker = ctx.unique_name("permitted-")
    denied_input = json.dumps({"marker": denied_marker})

    denied_sched = _create_schedule(
        ctx,
        ScheduleExpression=expression, ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": fn["arn"], "RoleArn": denied_role, "Input": denied_input,
                "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": dlq["arn"]}},
    )
    _create_schedule(
        ctx,
        ScheduleExpression=expression, ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": fn["arn"], "RoleArn": permitted_role,
                "Input": json.dumps({"marker": permitted_marker}),
                "RetryPolicy": dict(_RETRY_POLICY),
                "DeadLetterConfig": {"Arn": control_dlq["arn"]}},
    )
    denied_sched_arn = sch.get_schedule(Name=denied_sched)["Arn"]
    now = datetime.datetime.now(datetime.timezone.utc)
    assert now < nominal, (
        f"setup overran the scheduled instant ({nominal.isoformat()} <= {now.isoformat()})"
    )

    ctrl = _await_message(ctx, sink["url"], timeout_s=_FIRE_OFFSET_S + _DELIVERY_TIMEOUT_S,
                          description="the permitted schedule invoking the function")
    received = [json.loads(ctrl["Body"])["event"].get("marker")]

    dead = _await_message(ctx, dlq["url"], timeout_s=_DELIVERY_TIMEOUT_S,
                          description="the denied invocation reaching its DLQ")
    attrs = {k: v.get("StringValue") for k, v in (dead.get("MessageAttributes") or {}).items()}
    assert attrs.get("ERROR_CODE") == _EXPECTED_ERROR_CODE, (
        f"ERROR_CODE is {attrs.get('ERROR_CODE')!r}, expected {_EXPECTED_ERROR_CODE!r}; "
        f"attrs {attrs!r}"
    )
    message = attrs.get("ERROR_MESSAGE") or ""
    assert "lambda:InvokeFunction" in message and fn["arn"] in message, (
        f"ERROR_MESSAGE does not name the denied action on {fn['arn']!r}: {message!r}"
    )
    assert attrs.get("RETRY_ATTEMPTS") == "0", (
        f"RETRY_ATTEMPTS is {attrs.get('RETRY_ATTEMPTS')!r}; a non-retryable denial must spend 0"
    )
    assert attrs.get("SCHEDULE_ARN") == denied_sched_arn, (
        f"SCHEDULE_ARN is {attrs.get('SCHEDULE_ARN')!r}, expected {denied_sched_arn!r}"
    )
    assert attrs.get("TARGET_ARN") == fn["arn"], (
        f"TARGET_ARN is {attrs.get('TARGET_ARN')!r}, expected {fn['arn']!r}"
    )
    body = json.loads(dead["Body"])
    assert body.get("Payload") == denied_input, (
        f"dead-letter body Payload {body.get('Payload')!r} is not the Input {denied_input!r}"
    )

    quiet_until = nominal + datetime.timedelta(
        seconds=_RETRY_POLICY["MaximumEventAgeInSeconds"] + _QUIET_SLACK_S)
    window = max(10.0, (quiet_until - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    received += [json.loads(m["Body"])["event"].get("marker")
                 for m in _drain(ctx, sink["url"], window_s=window)]
    assert permitted_marker in received, f"control payload missing; sink saw {received!r}"
    assert denied_marker not in received, (
        f"the function WAS invoked by the role lacking lambda:InvokeFunction -- the execution "
        f"role's policy was not enforced; sink saw {received!r}"
    )
    extra = [m for m in _drain(ctx, dlq["url"], window_s=4.0) if m["MessageId"] != dead["MessageId"]]
    assert not extra, f"more than one dead-letter event for one denial: {[m['Body'] for m in extra]!r}"
    stray = _drain(ctx, control_dlq["url"], window_s=4.0)
    assert not stray, (
        f"the permitted leg was ALSO dead-lettered: {[m['Body'] for m in stray]!r}"
    )


_SINK_CODE = """
import json, os, boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    _sqs.send_message(QueueUrl=os.environ["SINK_URL"], MessageBody=json.dumps({"event": event}))
    return {"ok": True}
"""


# ===== helpers =====

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
    """The single log-group cleanup for this check run. Called as the first statement of run(), so
    LIFO runs it LAST -- after every DeleteFunction and after the queues and roles are gone, so
    if the engine's bounded cleanup budget runs out, the residue is a log group rather than a
    queue or role. One quiet window covers every function's group, so its cost does not scale
    with the number of functions."""
    key = id(ctx)
    if key not in _LOG_GROUPS:
        groups: list = []
        _LOG_GROUPS[key] = groups
        ctx.on_cleanup(lambda: _reap_log_groups(ctx, _LOG_GROUPS.pop(key, groups)))
    return _LOG_GROUPS[key]


def _reap_log_groups(ctx, groups: list) -> None:
    """Delete each /aws/lambda/<fn> until all have stayed absent for a continuous quiet window:
    a log stream buffered by an invocation that already returned can flush after DeleteFunction
    and recreate the group (measured: >16 s after an async destination record arrived)."""
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


def _create_schedule(ctx, **kwargs) -> str:
    """CreateSchedule assumes the role to validate it; retry the IAM-propagation
    ValidationException within a bound."""
    sch = ctx.client("scheduler")
    name = _xname(ctx, "sched")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationException" \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return name


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
