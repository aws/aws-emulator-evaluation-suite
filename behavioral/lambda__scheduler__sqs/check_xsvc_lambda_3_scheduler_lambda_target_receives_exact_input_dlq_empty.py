"""xsvc-lambda-3-scheduler-lambda-target-receives-exact-input-dlq-empty."""
from __future__ import annotations

import datetime
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-lambda-3-scheduler-lambda-target-receives-exact-input-dlq-empty"
GROUP = "data-plane"
SERVICES = ["lambda", "scheduler", "sqs"]

_FIRE_OFFSET_S = 10
_RETRY_POLICY = {"MaximumRetryAttempts": 1, "MaximumEventAgeInSeconds": 60}
_DELIVERY_TIMEOUT_S = 150
# How long the Scheduler DLQ is drained once every expected delivery has arrived.
_QUIET_S = 6.0


# timing:real-time — schedule: 10 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A one-time schedule with RetryPolicy and an SQS DLQ delivers its exact Target.Input to a
    healthy Lambda as a parsed object and leaves the DLQ empty, while a twin whose role lacks
    lambda:InvokeFunction dead-letters its event.
    """
    _log_groups_for(ctx)  # registered first, so it runs last
    sch = ctx.client("scheduler")

    sink = _create_queue(ctx)
    dlq = _create_queue(ctx)
    lambda_role = _create_role(
        ctx, "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink["arn"]}],
    )
    fn = _create_function(ctx, _ECHO_CODE, lambda_role, {"SINK_URL": sink["url"]})
    sched_role = _create_role(
        ctx, "scheduler.amazonaws.com",
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn["arn"]},
         {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq["arn"]}],
    )
    # Twin control on the DLQ wiring: the identical RetryPolicy + DLQ, but a role without
    # lambda:InvokeFunction, so its event must dead-letter.
    twin_dlq = _create_queue(ctx)
    twin_role = _create_role(
        ctx, "scheduler.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": twin_dlq["arn"]}],
    )

    payload = {
        "marker": ctx.unique_name("exact-"),
        "nested": {"list": [1, 2.5, -3, True, False, None], "empty": {}, "deep": {"k": ["v"]}},
        "unicode": "caf\u00e9 \u2713 \u65e5\u672c",
        "quote": "she said \"hi\"",
        "big": 12345678901234,
    }
    target_input = json.dumps(payload, ensure_ascii=False)

    target = {"Arn": fn["arn"], "RoleArn": sched_role, "Input": target_input,
              "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": dlq["arn"]}}
    name = _create_schedule(
        ctx,
        ScheduleExpressionTimezone="UTC", FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target=target,
    )
    twin_input = json.dumps({"marker": ctx.unique_name("twin-")})
    twin_target = {"Arn": fn["arn"], "RoleArn": twin_role, "Input": twin_input,
                   "RetryPolicy": dict(_RETRY_POLICY), "DeadLetterConfig": {"Arn": twin_dlq["arn"]}}
    twin_name = _create_schedule(
        ctx,
        ScheduleExpressionTimezone="UTC", FlexibleTimeWindow={"Mode": "OFF"}, State="ENABLED",
        Target=twin_target,
    )
    stored = sch.get_schedule(Name=name)["Target"]
    assert stored.get("Input") == target_input, (
        f"GetSchedule echoed Input {stored.get('Input')!r}, expected {target_input!r}"
    )

    got = _await_message(ctx, sink["url"], timeout_s=_budget_s(ctx, _FIRE_OFFSET_S + _DELIVERY_TIMEOUT_S),
                         description=f"schedule {name} invoking the healthy function")
    record = json.loads(got["Body"])
    assert record["event"] == payload, (
        f"the function received {record['event']!r}, not the schedule's exact Input {payload!r}"
    )
    assert record["event_type"] == "dict", (
        f"Scheduler must hand a JSON-object Input to the handler as an object, got "
        f"{record['event_type']!r}"
    )
    assert record["function_arn"] == fn["arn"], (
        f"the function was invoked as {record['function_arn']!r}, expected {fn['arn']!r}"
    )

    # The twin's dead-letter proves the DLQ wiring delivers; only then is the healthy DLQ's
    # emptiness evidence. The healthy invoke already succeeded, so no retry can dead-letter it later.
    twin_dead = _await_message(ctx, twin_dlq["url"], timeout_s=_budget_s(ctx, _DELIVERY_TIMEOUT_S),
                               description=f"twin schedule {twin_name} dead-lettering its denied invoke")
    assert json.loads(twin_dead["Body"]).get("Payload") == twin_input, (
        f"the twin's dead-letter body does not carry its Input {twin_input!r}: {twin_dead['Body']!r}"
    )

    dead = _drain(ctx, dlq["url"], window_s=_QUIET_S)
    assert not dead, (
        f"a healthy invocation was dead-lettered: "
        f"{[(m.get('MessageAttributes'), m['Body']) for m in dead]!r}"
    )
    others = [json.loads(m["Body"])["event"] for m in _drain(ctx, sink["url"], window_s=4.0)]
    assert all(e == payload for e in others), (
        f"the function received an invocation carrying some other payload: {others!r}"
    )

    # Tear down in reverse dependency order and prove each resource gone.
    _gone_schedule(ctx, name, target)
    _gone_schedule(ctx, twin_name, twin_target)
    _gone_role(ctx, sched_role.split("/")[-1])
    _gone_role(ctx, twin_role.split("/")[-1])
    _gone_lambda(ctx, fn["name"], fn["arn"])
    _gone_role(ctx, lambda_role.split("/")[-1])
    for q in (twin_dlq, dlq, sink):
        _gone_queue(ctx, q["url"].rstrip("/").split("/")[-1], q["url"])


_ECHO_CODE = """
import json, os, boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    _sqs.send_message(
        QueueUrl=os.environ["SINK_URL"],
        MessageBody=json.dumps({"event": event, "event_type": type(event).__name__,
                                "function_arn": context.invoked_function_arn}),
    )
    return {"ok": True}
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
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
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
    ctx.on_cleanup(_tolerant(lambda: _delete_role(ctx, name), "NoSuchEntity"))
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
    """The single log-group cleanup for this run, registered first so LIFO runs it last, after every
    function, queue and role is gone; one quiet window covers every function's group."""
    key = id(ctx)
    if key not in _LOG_GROUPS:
        groups: list = []
        _LOG_GROUPS[key] = groups
        ctx.on_cleanup(lambda: _reap_log_groups(ctx, _LOG_GROUPS.pop(key, groups)))
    return _LOG_GROUPS[key]


def _reap_log_groups(ctx, groups: list) -> None:
    """Delete each /aws/lambda/<fn> until all have stayed absent for a continuous quiet window:
    a log stream buffered by an invocation that already returned can flush after DeleteFunction
    and recreate the group, more than 16 s later."""
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
    return name


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


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, expected: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly the message ``expected``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == expected, f"{what}: {code} message {msg!r}, expected {expected!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, expected, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, expected)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")


def _gone_schedule(ctx, name: str, target: dict) -> None:
    sch = ctx.client("scheduler")
    sch.delete_schedule(Name=name)
    nf = ("ResourceNotFoundException",)
    gone = f"Schedule {name} does not exist."
    _poll_refused(lambda: sch.get_schedule(Name=name), nf, 404, f"GetSchedule {name}", gone)
    listed = {s["Name"] for s in _paged(sch, "list_schedules", "Schedules", NamePrefix=name)}
    assert name not in listed, f"ListSchedules still lists deleted schedule {name}"
    _refused(
        lambda: sch.update_schedule(Name=name, ScheduleExpression="rate(1 day)", State="DISABLED",
                                    FlexibleTimeWindow={"Mode": "OFF"}, Target=target),
        nf, 404, f"UpdateSchedule {name}", gone,
    )


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    gone = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", gone)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", gone,
    )


def _gone_lambda(ctx, name: str, arn: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}",
                  f"Function not found: {arn}")
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    _poll_refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}",
                  f"Function not found: {arn}:$LATEST")


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    gone = "The specified queue does not exist."
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", gone)
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}",
             gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
