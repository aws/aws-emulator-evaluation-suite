"""xsvc-lambda-3-sync-invoke-produces-no-onsuccess-destination-record."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-lambda-3-sync-invoke-produces-no-onsuccess-destination-record"
GROUP = "error-propagation"
SERVICES = ["lambda", "sqs"]

_DELIVERY_TIMEOUT_S = 150
_AFTER_BARRIER_S = 15


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """Destinations fire only for asynchronous invocations: a synchronous invoke of a function with an
    SQS OnSuccess destination produces NO record, while an async invoke issued afterwards does; the
    async record arriving is the barrier that proves the sync record is absent, not late.
    """
    _log_groups_for(ctx)  # registered first, so it runs last
    lam = ctx.client("lambda")
    dest = _create_queue(ctx)
    role = _create_role(
        ctx, "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dest["arn"]}],
    )
    fn = _create_function(ctx, _ECHO_CODE, role, {"UNUSED_VAR": "x"})
    lam.put_function_event_invoke_config(
        FunctionName=fn["name"], MaximumRetryAttempts=0, MaximumEventAgeInSeconds=60,
        DestinationConfig={"OnSuccess": {"Destination": dest["arn"]}},
    )
    ctx.on_cleanup(lambda: lam.delete_function_event_invoke_config(FunctionName=fn["name"]))

    sync_marker = ctx.unique_name("sync-")
    sync = lam.invoke(FunctionName=fn["name"], InvocationType="RequestResponse",
                      Payload=json.dumps({"marker": sync_marker}).encode())
    assert sync["StatusCode"] == 200, f"sync invoke returned {sync['StatusCode']!r}, not 200"
    assert "FunctionError" not in sync, f"sync invoke failed: {sync.get('FunctionError')!r}"
    sync_out = json.loads(sync["Payload"].read())
    assert sync_out == {"echo": sync_marker}, f"sync invoke returned {sync_out!r}"

    async_marker = ctx.unique_name("async-")
    resp = lam.invoke(FunctionName=fn["name"], InvocationType="Event",
                      Payload=json.dumps({"marker": async_marker}).encode())
    assert resp["StatusCode"] == 202, f"async invoke returned {resp['StatusCode']!r}, not 202"

    first = _await_message(ctx, dest["url"], timeout_s=_DELIVERY_TIMEOUT_S,
                           description="the async control's OnSuccess record (the barrier)")
    seen = [json.loads(first["Body"])]
    seen += [json.loads(m["Body"]) for m in _drain(ctx, dest["url"], window_s=_AFTER_BARRIER_S)]
    markers = [r.get("requestPayload", {}).get("marker") for r in seen]
    assert async_marker in markers, (
        f"the async control never produced a destination record; saw markers {markers!r}"
    )
    assert sync_marker not in markers, (
        f"the SYNCHRONOUS invoke produced an OnSuccess destination record -- destinations must "
        f"fire only for async invokes; records: {seen!r}"
    )
    control = next(r for r in seen if r.get("requestPayload", {}).get("marker") == async_marker)
    assert control.get("requestContext", {}).get("condition") == "Success", (
        f"control record condition is {control.get('requestContext')!r}"
    )
    assert control.get("responsePayload") == {"echo": async_marker}, (
        f"control record responsePayload is {control.get('responsePayload')!r}"
    )
    _await_log_group(ctx, fn["name"])


_ECHO_CODE = """
def handler(event, context):
    return {"echo": event["marker"]}
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
    """The ONE log-group cleanup for this check run. Called as the first statement of run(), so
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


def _await_log_group(ctx, fn_name: str) -> None:
    """Teardown prep, not an assertion: wait until the invoked function's log group exists, so its
    first flush has already landed before teardown deletes it."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if any(g["logGroupName"] == group for g in found):
            return
        time.sleep(3)


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
