"""xsvc-lambda-3-scheduler-deleted-lambda-target-dead-letters-once."""
from __future__ import annotations

import datetime
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-lambda-3-scheduler-deleted-lambda-target-dead-letters-once"
GROUP = "error-propagation"
SERVICES = ["lambda", "scheduler", "sqs"]

_FIRE_OFFSET_S = 75
_RETRY_POLICY = {"MaximumRetryAttempts": 1, "MaximumEventAgeInSeconds": 60}
# Poll BUDGETS, never asserted deadlines: nominal instant + attempt + dead-letter composition.
_DELIVERY_TIMEOUT_S = 150
# After the dead-letter event lands, keep reading until the event's own MaximumEventAgeInSeconds
# has elapsed past the scheduled instant (plus slack): any retry Scheduler could still make, and
# therefore any second dead-letter event, is bounded by that age.
_QUIET_SLACK_S = 25
# Scheduler's dead-letter event for an async Invoke
# of a deleted function. The error is non-retryable, so RETRY_ATTEMPTS is "0" even with
# MaximumRetryAttempts=1 -- the retry budget is a ceiling, not a count Scheduler spends.
_EXPECTED_ERROR_CODE = "ResourceNotFoundException"
_EXPECTED_RETRY_ATTEMPTS = "0"


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
    """A schedule whose Lambda target is deleted before it fires dead-letters exactly ONE event with
    ERROR_CODE=ResourceNotFoundException and RETRY_ATTEMPTS=0, while an identically wired schedule
    on a live function firing at the same instant delivers its payload and leaves its DLQ empty."""
    _log_groups_for(ctx)  # registered first, so it runs last
    sch = ctx.client("scheduler")
    lam = ctx.client("lambda")

    sink = _create_queue(ctx)
    dlq = _create_queue(ctx)
    control_dlq = _create_queue(ctx)

    lambda_role = _create_role(
        ctx, "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink["arn"]}],
    )
    doomed = _create_function(ctx, _SINK_CODE, lambda_role, {"SINK_URL": sink["url"]})
    live = _create_function(ctx, _SINK_CODE, lambda_role, {"SINK_URL": sink["url"]})

    sched_role = _create_role(
        ctx, "scheduler.amazonaws.com",
        [
            {"Effect": "Allow", "Action": "lambda:InvokeFunction",
             "Resource": [doomed["arn"], live["arn"]]},
            {"Effect": "Allow", "Action": "sqs:SendMessage",
             "Resource": [dlq["arn"], control_dlq["arn"]]},
        ],
    )

    nominal = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + \
        datetime.timedelta(seconds=_FIRE_OFFSET_S)
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"
    doomed_input = json.dumps({"marker": ctx.unique_name("doomed-"), "n": 1})
    live_marker = ctx.unique_name("live-")

    doomed_sched = _create_schedule(
        ctx,
        ScheduleExpression=expression, ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": doomed["arn"], "RoleArn": sched_role, "Input": doomed_input,
                "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": dlq["arn"]}},
    )
    _create_schedule(
        ctx,
        ScheduleExpression=expression, ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target={"Arn": live["arn"], "RoleArn": sched_role,
                "Input": json.dumps({"marker": live_marker}),
                "RetryPolicy": dict(_RETRY_POLICY),
                "DeadLetterConfig": {"Arn": control_dlq["arn"]}},
    )
    doomed_sched_arn = sch.get_schedule(Name=doomed_sched)["Arn"]

    # (1) The one broken thing.
    lam.delete_function(FunctionName=doomed["name"])
    gone, gone_message = _expect_error(lambda: lam.get_function(FunctionName=doomed["name"]))
    assert gone == "ResourceNotFoundException", (
        f"the doomed function is still resolvable after DeleteFunction: GetFunction gave {gone!r}"
    )
    expected_gone = f"Function not found: {doomed['arn']}"
    assert gone_message == expected_gone, (
        f"expected GetFunction message {expected_gone!r}, got {gone_message!r}"
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    assert now < nominal, (
        f"setup overran the scheduled instant ({nominal.isoformat()} <= {now.isoformat()}); the "
        f"deletion must precede the fire for the scenario to mean anything"
    )

    # (2) Positive control and barrier.
    ctrl = _await_message(ctx, sink["url"], timeout_s=_FIRE_OFFSET_S + _DELIVERY_TIMEOUT_S,
                          description="the live schedule's invocation reaching the sink")
    ctrl_event = json.loads(ctrl["Body"])["event"]
    assert ctrl_event == {"marker": live_marker}, (
        f"the live control function received {ctrl_event!r}, expected its schedule's Input"
    )

    # (3) The dead-letter event.
    dead = _await_message(ctx, dlq["url"], timeout_s=_DELIVERY_TIMEOUT_S,
                          description="the deleted-target invocation reaching its DLQ")
    attrs = {k: v.get("StringValue") for k, v in (dead.get("MessageAttributes") or {}).items()}
    assert "ERROR_CODE" in attrs and "ERROR_MESSAGE" in attrs, (
        f"dead-letter event lacks ERROR_CODE/ERROR_MESSAGE attributes; got {sorted(attrs)!r}"
    )
    assert attrs["ERROR_CODE"] == _EXPECTED_ERROR_CODE, (
        f"ERROR_CODE is {attrs['ERROR_CODE']!r}, expected {_EXPECTED_ERROR_CODE!r}; attrs {attrs!r}"
    )
    assert doomed["arn"] in attrs["ERROR_MESSAGE"], (
        f"ERROR_MESSAGE does not name the missing function {doomed['arn']!r}: "
        f"{attrs['ERROR_MESSAGE']!r}"
    )
    assert attrs.get("RETRY_ATTEMPTS") == _EXPECTED_RETRY_ATTEMPTS, (
        f"RETRY_ATTEMPTS is {attrs.get('RETRY_ATTEMPTS')!r}; a non-retryable ResourceNotFound "
        f"under MaximumRetryAttempts={_RETRY_POLICY['MaximumRetryAttempts']} must spend "
        f"{_EXPECTED_RETRY_ATTEMPTS!r} retries"
    )
    assert int(attrs["RETRY_ATTEMPTS"]) <= _RETRY_POLICY["MaximumRetryAttempts"], (
        f"RETRY_ATTEMPTS {attrs['RETRY_ATTEMPTS']!r} exceeds the configured budget"
    )
    assert attrs.get("TARGET_ARN") == doomed["arn"], (
        f"TARGET_ARN is {attrs.get('TARGET_ARN')!r}, expected {doomed['arn']!r}"
    )
    assert attrs.get("SCHEDULE_ARN") == doomed_sched_arn, (
        f"SCHEDULE_ARN is {attrs.get('SCHEDULE_ARN')!r}, expected {doomed_sched_arn!r}"
    )
    body = json.loads(dead["Body"])
    assert body.get("FunctionName") == doomed["arn"], (
        f"dead-letter body FunctionName is {body.get('FunctionName')!r}, expected {doomed['arn']!r}"
    )
    assert body.get("InvocationType") == "Event", (
        f"Scheduler must invoke a Lambda target asynchronously; body says "
        f"{body.get('InvocationType')!r}"
    )
    assert body.get("Payload") == doomed_input, (
        f"dead-letter body Payload {body.get('Payload')!r} is not the Input {doomed_input!r}"
    )

    # (4) Exactly one, and only on the broken leg.
    quiet_until = nominal + datetime.timedelta(
        seconds=_RETRY_POLICY["MaximumEventAgeInSeconds"] + _QUIET_SLACK_S)
    window = max(10.0, (quiet_until - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    more = _drain(ctx, dlq["url"], window_s=window)
    extra = [m for m in more if m["MessageId"] != dead["MessageId"]]
    assert not extra, (
        f"expected exactly one dead-letter event; {len(extra)} more arrived within the event-age "
        f"bound: {[m['Body'] for m in extra]!r}"
    )
    stray = _drain(ctx, control_dlq["url"], window_s=6.0)
    assert not stray, (
        f"the live control leg was ALSO dead-lettered, so dead-lettering is not attributable to "
        f"the deleted function: {[m['Body'] for m in stray]!r}"
    )
    doomed_hits = [m for m in _drain(ctx, sink["url"], window_s=4.0)
                   if json.loads(m["Body"])["event"].get("marker") != live_marker]
    assert not doomed_hits, f"the deleted function was somehow invoked: {doomed_hits!r}"


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


def _expect_error(fn) -> tuple:
    """The AWS error (code, message) `fn` raised. A call that SUCCEEDS is itself the finding, so
    it raises rather than returning a falsy sentinel that would read like a naming mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", "<no code>"), error.get("Message")
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
