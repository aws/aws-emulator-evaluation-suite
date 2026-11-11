"""scheduler-lambda-universal-target-invalid-input-dead-letters."""
from __future__ import annotations

import datetime
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-lambda-universal-target-invalid-input-dead-letters"
GROUP = "universal-target-invalid-input"
SERVICES = ["iam", "lambda", "logs", "scheduler", "sqs"]

_UNIVERSAL_ARN = "arn:aws:scheduler:::aws-sdk:lambda:invoke"
_FIRE_OFFSET_S = 75
_RETRY_POLICY = {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
_DELIVERY_TIMEOUT_S = 150


# timing:real-time — schedule: 75 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:negative-delivery",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A Lambda universal target whose Input has a FunctionName version mismatching Qualifier, or a
    whitespace-only FunctionName, is accepted at CreateSchedule time but dead-letters the exact
    downstream error on every invocation, while a correctly-formed sibling target invokes it."""
    _log_groups_for(ctx)  # registered first, so it runs last
    sch = ctx.client("scheduler")
    sqs = ctx.client("sqs")

    sink = _create_queue(ctx)
    dlq_mismatch = _create_queue(ctx)
    dlq_whitespace = _create_queue(ctx)
    control_dlq = _create_queue(ctx)

    lambda_role = _create_role(
        ctx, "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink["arn"]}],
    )
    fn = _create_function(ctx, lambda_role, {"SINK_URL": sink["url"]})
    published_version = ctx.client("lambda").publish_version(FunctionName=fn["name"])["Version"]
    assert published_version == "1", f"expected the first published version to be '1', got {published_version!r}"

    sched_role = _create_role(
        ctx, "scheduler.amazonaws.com",
        [
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"},
            {"Effect": "Allow", "Action": "sqs:SendMessage",
             "Resource": [dlq_mismatch["arn"], dlq_whitespace["arn"], control_dlq["arn"]]},
        ],
    )

    nominal = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + \
        datetime.timedelta(seconds=_FIRE_OFFSET_S)
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"

    mismatch_marker = ctx.unique_name("mismatch-")
    control_marker = ctx.unique_name("control-")

    mismatch_input = json.dumps({
        "FunctionName": f"{fn['name']}:2",
        "Qualifier": "1",
        "InvocationType": "Event",
        "Payload": json.dumps({"marker": mismatch_marker}),
    })
    whitespace_input = json.dumps({"FunctionName": "     ", "InvocationType": "Event"})
    control_input = json.dumps({
        "FunctionName": fn["arn"],
        "InvocationType": "Event",
        "Payload": json.dumps({"marker": control_marker}),
    })

    mismatch_sched = _create_schedule(
        ctx, sch,
        ScheduleExpression=expression, ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": _UNIVERSAL_ARN, "RoleArn": sched_role, "Input": mismatch_input,
                "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": dlq_mismatch["arn"]}},
    )
    whitespace_sched = _create_schedule(
        ctx, sch,
        ScheduleExpression=expression, ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": _UNIVERSAL_ARN, "RoleArn": sched_role, "Input": whitespace_input,
                "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": dlq_whitespace["arn"]}},
    )
    _create_schedule(
        ctx, sch,
        ScheduleExpression=expression, ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": _UNIVERSAL_ARN, "RoleArn": sched_role, "Input": control_input,
                "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": control_dlq["arn"]}},
    )
    mismatch_sched_arn = sch.get_schedule(Name=mismatch_sched)["Arn"]
    whitespace_sched_arn = sch.get_schedule(Name=whitespace_sched)["Arn"]
    now = datetime.datetime.now(datetime.timezone.utc)
    assert now < nominal, f"setup overran the scheduled instant ({nominal.isoformat()} <= {now.isoformat()})"

    ctrl = _await_message(ctx, sink["url"], timeout_s=_FIRE_OFFSET_S + _DELIVERY_TIMEOUT_S,
                          description="the correctly-formed sibling target invoking the function")
    received = [json.loads(ctrl["Body"])["event"].get("marker")]
    assert received == [control_marker], (
        f"the control invocation delivered marker {received!r}, expected [{control_marker!r}]"
    )

    mismatch_dead = _await_message(ctx, dlq_mismatch["url"], timeout_s=_DELIVERY_TIMEOUT_S,
                                   description="the qualifier-mismatch invocation reaching its DLQ")
    mismatch_attrs = {k: v.get("StringValue") for k, v in (mismatch_dead.get("MessageAttributes") or {}).items()}
    assert mismatch_attrs.get("ERROR_CODE") == "InvalidParameterValueException", (
        f"ERROR_CODE is {mismatch_attrs.get('ERROR_CODE')!r}, expected 'InvalidParameterValueException'"
    )
    assert mismatch_attrs.get("ERROR_MESSAGE") == (
        "The derived qualifier from the function name does not match the specified qualifier."
    ), f"ERROR_MESSAGE is {mismatch_attrs.get('ERROR_MESSAGE')!r}"
    assert mismatch_attrs.get("SCHEDULE_ARN") == mismatch_sched_arn, (
        f"SCHEDULE_ARN is {mismatch_attrs.get('SCHEDULE_ARN')!r}, expected {mismatch_sched_arn!r}"
    )

    whitespace_dead = _await_message(ctx, dlq_whitespace["url"], timeout_s=_DELIVERY_TIMEOUT_S,
                                     description="the whitespace-FunctionName invocation reaching its DLQ")
    whitespace_attrs = {k: v.get("StringValue") for k, v in (whitespace_dead.get("MessageAttributes") or {}).items()}
    assert whitespace_attrs.get("ERROR_CODE") == "ValidationException", (
        f"ERROR_CODE is {whitespace_attrs.get('ERROR_CODE')!r}, expected 'ValidationException'"
    )
    expected_whitespace_message = (
        "1 validation error detected: Value '     ' at 'functionName' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"(arn:(aws[a-zA-Z-]*)?:lambda:)?((eusc-)?[a-z]{2}((-gov)|(-iso([a-z]?)))?-[a-z]+-\d{1}:)?"
        r"(\d{12}:)?(function:)?([a-zA-Z0-9-_\.]+)(:(\$LATEST(\.PUBLISHED)?|[a-zA-Z0-9-_]+))?"
    )
    assert whitespace_attrs.get("ERROR_MESSAGE") == expected_whitespace_message, (
        f"ERROR_MESSAGE is {whitespace_attrs.get('ERROR_MESSAGE')!r}"
    )
    assert whitespace_attrs.get("SCHEDULE_ARN") == whitespace_sched_arn, (
        f"SCHEDULE_ARN is {whitespace_attrs.get('SCHEDULE_ARN')!r}, expected {whitespace_sched_arn!r}"
    )

    # A later direct invocation must reach the sink; everything the sink holds before its marker
    # shows the qualifier-mismatch target never ran.
    late_marker = ctx.unique_name("late-")
    ctx.client("lambda").invoke(FunctionName=fn["arn"], InvocationType="RequestResponse",
                                Payload=json.dumps({"marker": late_marker}).encode())
    received += [json.loads(m["Body"])["event"].get("marker")
                 for m in _receive_through(ctx, sink["url"], late_marker, _event_marker)]
    assert mismatch_marker not in received, (
        f"the qualifier-mismatch target WAS invoked despite the invalid Input: sink saw {received!r}"
    )
    # A sentinel sent after both dead letters arrived must be the only message on the control DLQ.
    sentinel = ctx.unique_name("sentinel-")
    sqs.send_message(QueueUrl=control_dlq["url"], MessageBody=sentinel)
    on_control_dlq = [m["Body"] for m in _receive_through(ctx, control_dlq["url"], sentinel, _body)]
    assert on_control_dlq == [sentinel], (
        f"the correctly-formed sibling target WAS ALSO dead-lettered: {on_control_dlq!r}"
    )


def _event_marker(message: dict):
    return json.loads(message["Body"])["event"].get("marker")


def _body(message: dict):
    return message["Body"]


_SINK_CODE = """
import json, os, boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    _sqs.send_message(QueueUrl=os.environ["SINK_URL"], MessageBody=json.dumps({"event": event}))
    return {"ok": True}
"""


# ===== helpers =====

_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real": "true"}
_ROLE_PROPAGATION_S = 90
_LOG_REAP_BOUND_S = 40
_LOG_QUIET_S = 20
_LOG_GROUPS: dict = {}
_LAMBDA_ROLE_UNPROPAGATED = (
    "InvalidParameterValueException", "The role defined for the function cannot be assumed by Lambda.",
)
_SCHEDULER_ROLE_UNPROPAGATED = (
    "ValidationException", "The execution role you provide must allow AWS EventBridge Scheduler to assume the role.",
)


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _create_queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
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
    LIFO runs it LAST -- after DeleteFunction and after the queues and roles are gone, so if the
    engine's bounded cleanup budget runs out, the residue is a log group rather than a queue or
    role."""
    key = id(ctx)
    if key not in _LOG_GROUPS:
        groups: list = []
        _LOG_GROUPS[key] = groups
        ctx.on_cleanup(lambda: _reap_log_groups(ctx, _LOG_GROUPS.pop(key, groups)))
    return _LOG_GROUPS[key]


def _reap_log_groups(ctx, groups: list) -> None:
    """Delete each /aws/lambda/<fn> until all have stayed absent for a continuous quiet window: a
    log stream buffered by an invocation that already returned can flush after DeleteFunction and
    recreate the group."""
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
    raise RuntimeError(f"log groups {groups!r} did not stay deleted within {_LOG_REAP_BOUND_S}s")


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_function(ctx, role_arn: str, env: dict) -> dict:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    _log_groups_for(ctx).append(f"/aws/lambda/{name}")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip(_SINK_CODE)}, Timeout=30, MemorySize=128,
                Environment={"Variables": env}, Tags=dict(_TAGS),
            )["FunctionArn"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _LAMBDA_ROLE_UNPROPAGATED \
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


def _create_schedule(ctx, sch, **kwargs) -> str:
    """CreateSchedule assumes the role to validate it; retry the IAM-propagation refusal within a
    bound."""
    name = _xname(ctx, "sched")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _SCHEDULER_ROLE_UNPROPAGATED \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, sch, name))
    return name


def _delete_schedule(ctx, sch, name: str) -> None:
    try:
        sch.delete_schedule(Name=name)
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


def _receive_through(ctx, url: str, marker: str, key, timeout_s: float = 90.0) -> list:
    """Receive-and-delete from ``url`` until the message whose ``key`` is ``marker`` arrives;
    return every message received, that one included."""
    sqs = ctx.client("sqs")
    out: list = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                     MessageAttributeNames=["All"]).get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if any(key(m) == marker for m in out):
            return out
    raise AssertionError(f"{marker!r} never arrived on {url} within {timeout_s:.0f}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
