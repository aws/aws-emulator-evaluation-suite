"""deleted-event-invoke-config-stops-destination-delivery-until-put-again."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-event-invoke-config-stops-destination-delivery-until-put-again"
GROUP = "data-plane"
SERVICES = ["lambda", "sqs"]

_DELIVERY_TIMEOUT_S = 150
_AFTER_BARRIER_S = 15
_CONVERGE_S = 180


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """After DeleteFunctionEventInvokeConfig (Get then answers ResourceNotFoundException) async invokes
    stop producing destination records while a twin keeps delivering; putting the config back
    restores delivery with a Success record.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_DeleteFunctionEventInvokeConfig.html
    """
    _log_groups_for(ctx)  # registered first, so it runs last
    lam = ctx.client("lambda")
    dest = _create_queue(ctx, "onsuccess")
    role = _create_role(ctx, [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dest["arn"]}])
    subject = _create_function(ctx, _ECHO_CODE, role)
    twin = _create_function(ctx, _ECHO_CODE, role)
    config = {"MaximumRetryAttempts": 0,
              "DestinationConfig": {"OnSuccess": {"Destination": dest["arn"]}}}
    _put_eic(ctx, subject["name"], **config)
    _put_eic(ctx, twin["name"], **config)

    first = ctx.unique_name("configured-")
    _invoke_event(lam, subject["name"], {"marker": first})
    rec = _body(_await_messages(ctx, dest["url"], 1, timeout_s=_DELIVERY_TIMEOUT_S,
                                description="the configured subject's record")[0])
    assert rec.get("requestPayload") == {"marker": first}, f"record: {rec!r}"

    lam.delete_function_event_invoke_config(FunctionName=subject["name"])
    code, msg = _error(lambda: lam.get_function_event_invoke_config(FunctionName=subject["name"]))
    assert code == "ResourceNotFoundException", f"Get after Delete answered {code}: {msg}"
    assert msg == (f"The function {subject['arn']}:$LATEST doesn't have an EventInvokeConfig"), (
        f"Get after Delete message: {msg!r}"
    )

    # The delete is eventually consistent on the invoke path: each round fans one invoke to the
    # subject and one to the twin; the twin's record is the barrier, and the round converges when
    # the subject's invoke left no record. Bounded; a target consistent at once converges in one.
    rounds: list = []
    deadline = time.monotonic() + _CONVERGE_S
    while True:
        deleted = ctx.unique_name("deleted-")
        barrier = ctx.unique_name("twin-")
        _invoke_event(lam, subject["name"], {"marker": deleted})
        _invoke_event(lam, twin["name"], {"marker": barrier})
        markers = _markers_until(ctx, dest["url"], barrier, timeout_s=_DELIVERY_TIMEOUT_S)
        markers |= {_body(m).get("requestPayload", {}).get("marker")
                    for m in _drain(ctx, dest["url"], window_s=_AFTER_BARRIER_S)}
        rounds.append(deleted in markers)
        if deleted not in markers:
            break
        assert time.monotonic() < deadline, (
            f"the subject's config was deleted, yet {len(rounds)} rounds over {_CONVERGE_S}s "
            f"still produced its destination record"
        )

    lam.put_function_event_invoke_config(FunctionName=subject["name"], **config)
    sent: list = []
    record = None
    deadline = time.monotonic() + _CONVERGE_S
    while record is None:
        restored = ctx.unique_name("restored-")
        sent.append(restored)
        _invoke_event(lam, subject["name"], {"marker": restored})
        for m in _drain(ctx, dest["url"], window_s=15):
            rec = _body(m)
            if rec.get("requestPayload", {}).get("marker") in sent:
                record = record or rec
        assert record is not None or time.monotonic() < deadline, (
            f"the re-put config produced no record for {len(sent)} invoke(s) in {_CONVERGE_S}s"
        )
    assert record.get("requestContext", {}).get("functionArn") == f"{subject['arn']}:$LATEST", (
        f"record functionArn: {record.get('requestContext')!r}"
    )
    assert record.get("requestContext", {}).get("condition") == "Success", f"record: {record!r}"


def _markers_until(ctx, url: str, wanted: str, *, timeout_s: float) -> set:
    """Receive records until one carries `wanted`; returns every requestPayload marker seen."""
    seen: set = set()
    deadline = time.monotonic() + timeout_s
    while wanted not in seen:
        assert time.monotonic() < deadline, (
            f"the twin's record never arrived within {timeout_s:.0f}s; saw {sorted(seen)!r}"
        )
        seen |= {_body(m).get("requestPayload", {}).get("marker") for m in _receive(ctx, url)}
    return seen

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
