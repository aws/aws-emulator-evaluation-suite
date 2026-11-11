"""published-version-failure-uses-its-publish-time-dead-letter-queue."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "published-version-failure-uses-its-publish-time-dead-letter-queue"
GROUP = "data-plane"
SERVICES = ["lambda", "sqs"]

_DELIVERY_TIMEOUT_S = 150
_AFTER_BARRIER_S = 20


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A published version keeps the dead-letter queue it was published with: after $LATEST moves to
    queue B, version 1 still reports queue A and its failed async events land in A while nothing
    reaches B.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html
    """
    _log_groups_for(ctx)  # registered first, so it runs last
    lam = ctx.client("lambda")
    dlq_a = _create_queue(ctx, "dlq-a")
    dlq_b = _create_queue(ctx, "dlq-b")
    role = _create_role(ctx, [{"Effect": "Allow", "Action": "sqs:SendMessage",
                               "Resource": [dlq_a["arn"], dlq_b["arn"]]}])
    fn = _create_function(ctx, _FAIL_CODE, role,
                          extra={"DeadLetterConfig": {"TargetArn": dlq_a["arn"]}})
    version = lam.publish_version(FunctionName=fn["name"])["Version"]
    assert version == "1", f"the first PublishVersion returned {version!r}"
    _wait_ready(lam, fn["name"], version)
    _put_eic(ctx, fn["name"], version, MaximumRetryAttempts=0)

    _retry_iam(lambda: lam.update_function_configuration(
        FunctionName=fn["name"], DeadLetterConfig={"TargetArn": dlq_b["arn"]}))
    _wait_ready(lam, fn["name"])
    latest = lam.get_function_configuration(FunctionName=fn["name"])
    assert latest.get("DeadLetterConfig", {}).get("TargetArn") == dlq_b["arn"], (
        f"$LATEST did not take the new DLQ: {latest.get('DeadLetterConfig')!r}"
    )

    marker = ctx.unique_name("v1-fail-")
    _invoke_event(lam, fn["name"], {"marker": marker}, qualifier=version)

    v1_cfg = lam.get_function_configuration(FunctionName=fn["name"], Qualifier=version)
    assert v1_cfg.get("DeadLetterConfig", {}).get("TargetArn") == dlq_a["arn"], (
        f"version {version} must keep its publish-time DLQ, reports "
        f"{v1_cfg.get('DeadLetterConfig')!r}"
    )
    got = _await_messages(ctx, dlq_a["url"], 1, timeout_s=_DELIVERY_TIMEOUT_S,
                          description="version 1's failure on its publish-time DLQ (A)")
    assert [_body(m) for m in got] == [{"marker": marker}], (
        f"queue A received {[m['Body'][:200] for m in got]!r}"
    )
    on_b = _drain(ctx, dlq_b["url"], window_s=_AFTER_BARRIER_S)
    assert on_b == [], (
        f"$LATEST's current DLQ (B) received {len(on_b)} message(s) for a version-1 failure: "
        f"{[m['Body'][:200] for m in on_b]!r}"
    )


_FAIL_CODE = """
def handler(event, context):
    raise RuntimeError("poison-event:" + event["marker"])
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


def _error(fn) -> tuple:
    """(code, message) of the AWS error `fn` raised. A call that SUCCEEDS is itself the finding,
    so it raises rather than returning a sentinel that would read like a naming mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message", "<no message>")
    raise AssertionError(f"call was expected to fail but succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_queue(ctx, kind: str = "q") -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, kind), tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]
    return {"url": url, "arn": arn}


def _create_role(ctx, statements: list) -> str:
    """This check's own Lambda execution role, granted exactly `statements` plus log writes."""
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    statements = statements + [{"Effect": "Allow", "Action": [
        "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}]
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
    LIFO runs it LAST, after every DeleteFunction; one quiet window covers every function."""
    key = id(ctx)
    if key not in _LOG_GROUPS:
        groups: list = []
        _LOG_GROUPS[key] = groups
        ctx.on_cleanup(lambda: _reap_log_groups(ctx, _LOG_GROUPS.pop(key, groups)))
    return _LOG_GROUPS[key]


def _reap_log_groups(ctx, groups: list) -> None:
    """Delete each /aws/lambda/<fn> until all have stayed absent for a continuous quiet window:
    a buffered log stream can flush after DeleteFunction and recreate the group."""
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


def _create_function(ctx, code: str, role_arn: str, *, env: dict | None = None,
                     timeout: int = 30, extra: dict | None = None) -> dict:
    """Create a python3.12 function, retrying only while the new role is not yet assumable."""
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    _log_groups_for(ctx).append(f"/aws/lambda/{name}")
    kwargs = dict(FunctionName=name, Runtime="python3.12", Role=role_arn,
                  Handler="index.handler", Code={"ZipFile": _zip(code)}, Timeout=timeout,
                  MemorySize=128, Environment={"Variables": env or {"UNUSED_VAR": "x"}},
                  Tags=dict(_TAGS))
    kwargs.update(extra or {})
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException" \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_ready(lam, name)
    return {"name": name, "arn": arn}


def _wait_ready(lam, name: str, qualifier: str | None = None) -> None:
    """Poll until the function (or version) is Active with no update in flight."""
    deadline = time.monotonic() + 90
    while True:
        kw = {"FunctionName": name}
        if qualifier:
            kw["Qualifier"] = qualifier
        cfg = lam.get_function_configuration(**kw)
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return
        assert cfg.get("State") != "Failed", f"function {name} failed: {cfg.get('StateReason')!r}"
        assert time.monotonic() < deadline, (
            f"function {name} never became Active/Successful: {cfg.get('State')!r} "
            f"{cfg.get('LastUpdateStatus')!r}")
        time.sleep(2)


def _retry_iam(fn, *, budget_s: float = _ROLE_PROPAGATION_S):
    """Run `fn`, retrying only the execution-role permission refusal Lambda raises while a policy
    this check just attached is still propagating."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException" \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _put_eic(ctx, function: str, qualifier: str | None = None, **kwargs) -> None:
    """PutFunctionEventInvokeConfig, its delete registered at once."""
    lam = ctx.client("lambda")
    q = {"Qualifier": qualifier} if qualifier else {}
    _retry_iam(lambda: lam.put_function_event_invoke_config(FunctionName=function, **q, **kwargs))
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function_event_invoke_config(FunctionName=function, **q),
        "ResourceNotFoundException"))


def _invoke_event(lam, function: str, payload, qualifier: str | None = None) -> str:
    """An asynchronous Invoke; asserts the 202 and returns the request id."""
    q = {"Qualifier": qualifier} if qualifier else {}
    resp = lam.invoke(FunctionName=function, InvocationType="Event",
                      Payload=json.dumps(payload).encode(), **q)
    assert resp["StatusCode"] == 202, f"async invoke returned {resp['StatusCode']!r}, not 202"
    body = resp["Payload"].read()
    assert body == b"", f"async invoke returned a non-empty body: {body[:200]!r}"
    return resp["ResponseMetadata"]["RequestId"]


def _receive(ctx, url: str, wait_s: int = 2) -> list:
    sqs = ctx.client("sqs")
    out = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
                                 MessageAttributeNames=["All"]).get("Messages", []):
        out.append(m)
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _await_messages(ctx, url: str, count: int, *, timeout_s: float, description: str) -> list:
    """Receive-and-delete until `count` messages arrived; raises naming what was missing."""
    got: list = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got.extend(_receive(ctx, url, wait_s=2))
        if len(got) >= count:
            return got
    raise AssertionError(f"{description}: {len(got)} of {count} message(s) arrived within "
                         f"{timeout_s:.0f}s")


def _drain(ctx, url: str, *, window_s: float) -> list:
    """Receive-and-delete everything visible over a bounded window."""
    out: list = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        out.extend(_receive(ctx, url, wait_s=int(max(1, min(5, deadline - time.monotonic())))))
    return out


def _body(msg: dict) -> dict:
    try:
        return json.loads(msg["Body"])
    except ValueError:
        raise AssertionError(f"non-JSON message body: {msg['Body'][:300]!r}") from None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
