"""eventbridge-rule-on-detail-content-invokes-lambda-only-for-the-matching-entry."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-on-detail-content-invokes-lambda-only-for-the-matching-entry"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "sqs"]

_DETAIL_TYPE = "Order Placed"
# The rule matches kind "order" with amount > 100; each decoy breaks exactly one of the two.
_MATCH = {"kind": "order", "amount": 150, "lines": [{"sku": "ü-1", "qty": 2}], "note": "中文"}
_DECOYS = [
    {"kind": "order", "amount": 50, "lines": [], "note": "small"},
    {"kind": "refund", "amount": 500, "lines": [], "note": "refund"},
]
_PATTERN_DETAIL = {"kind": ["order"], "amount": [{"numeric": [">", 100]}]}


def _forwarder_code(queue_url: str) -> str:
    """Lambda code that forwards the raw invocation event to an SQS queue."""
    return f'''
import boto3
import json


def lambda_handler(event, context):
    sqs = boto3.client("sqs")
    sqs.send_message(
        QueueUrl="{queue_url}",
        MessageBody=json.dumps(event),
    )
    return {{"ok": True}}
'''


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule matching a detail string and a numeric range invokes its Lambda target only for the
    entry meeting both, with its exact nested detail, never for the two same-source decoys that each
    break one condition, graded over a quiet window after a later matching fence is relayed.
    """
    results = _create_queue(ctx)
    fn = _create_lambda(
        ctx,
        _forwarder_code(results["url"]),
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": results["arn"]}],
    )
    events = ctx.client("events")
    lambda_client = ctx.client("lambda")
    rule_name = ctx.unique_name("rule-eb-lambda-")
    source = ctx.unique_name("custom.itest.")
    rule = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {"source": [source], "detail-type": [_DETAIL_TYPE], "detail": _PATTERN_DETAIL}
        ),
    )
    ctx.on_cleanup(
        _tolerant(
            lambda: ctx.client("events").delete_rule(Name=rule_name), "ResourceNotFoundException"
        )
    )
    lambda_client.add_permission(
        FunctionName=fn["name"],
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule["RuleArn"],
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": fn["arn"]}])
    ctx.on_cleanup(
        _tolerant(
            lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"]),
            "ResourceNotFoundException",
        )
    )

    entries = [
        {"Source": source, "DetailType": _DETAIL_TYPE, "Detail": json.dumps(d)}
        for d in [_DECOYS[0], _MATCH, _DECOYS[1]]
    ]
    bodies = _reemit_until(ctx, results["url"], entries, lambda b: b.get("detail") == _MATCH)
    # Positive control ordered after every decoy: a matching fence event.
    fence = {**_MATCH, "amount": 999, "note": ctx.unique_name("fence-")}
    fence_entry = {"Source": source, "DetailType": _DETAIL_TYPE, "Detail": json.dumps(fence)}
    # The fence is re-emitted until relayed; its copies are allowed relays.
    bodies += _reemit_until(
        ctx, results["url"], [fence_entry], lambda b: b.get("detail") == fence, every_s=15.0
    )
    # Delivery order is not guaranteed, so relays are collected for a quiet window after the fence
    # and every one of them is graded.
    bodies += _collect_messages(ctx, results["url"], expected_count=10**6, timeout_s=_QUIET_S)
    wrong = [b for b in bodies if b.get("detail") not in (_MATCH, fence)]
    assert not wrong, f"the rule invoked its target for an entry it does not match: {wrong!r}"
    body = bodies[0]
    for field, want in (
        ("source", source),
        ("detail-type", _DETAIL_TYPE),
        ("account", ctx.account),
        ("region", ctx.region),
        ("detail", _MATCH),
    ):
        assert body.get(field) == want, (
            f"expected relayed event {field}={want!r}, got {body.get(field)!r}"
        )
    role_name = fn["role"]
    _gone_rule(ctx, rule_name, ["t1"])
    _gone_lambda(ctx, fn["name"])
    _gone_role(ctx, role_name)
    _gone_queue(ctx, results["name"], results["url"])


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

#: Bounded convergence for a delete to reach its terminal not-found answer; a deadline, never an
#: assertion on elapsed time.
_GONE_S = 40.0

#: How long relays are still collected after the fence arrives.
_QUIET_S = 10.0

_SQS_NF = "AWS.SimpleQueueService.NonExistentQueue"
_SQS_NF_MSG = "The specified queue does not exist."
_ESM_NF_MSG = "The resource you requested does not exist."


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=40.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _grade(exc: ClientError, code: str, status: int, what: str, message: str) -> None:
    got = _err(exc)
    assert got == (code, status, message), (
        f"{what}: expected {(code, status, message)!r}, got {(got[0], got[1], got[2][:200])!r}"
    )


def _refused(fn, code: str, status: int, what: str, message: str) -> None:
    """One call of ``fn`` must fail with exactly ``code``, ``status`` and ``message``."""
    try:
        fn()
    except ClientError as exc:
        _grade(exc, code, status, what, message)
        return
    raise AssertionError(f"{what}: expected {code} HTTP {status}, the call succeeded")


def _poll_refused(read, code: str, status: int, what: str, message: str) -> None:
    """Poll the read-only ``read`` until it answers ``code``, and grade that answer exactly.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + _GONE_S
    while True:
        try:
            last = read()
        except ClientError as exc:
            if _err(exc)[0] == code:
                _grade(exc, code, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what}: still readable {_GONE_S:.0f}s after the delete; last answer {last!r:.300}"
            )
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


def _create_role(ctx, inline_policy: dict) -> dict[str, str]:
    """Create a Lambda execution role with one inline policy; register its teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role-lambda")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """Remove the inline policies, then the role; DeleteConflict is retried while IAM catches up,
    and only an already-gone role (NoSuchEntity) is tolerated."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + 40.0
    while True:
        try:
            for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                return
            if code != "DeleteConflict" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _zip(code: str) -> bytes:
    """A deployment package holding ``code`` as lambda_function.py."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(code))
    return buf.getvalue()


def _delete_function_log_group(ctx, name: str) -> None:
    """Delete /aws/lambda/<name>; a function that never ran has none to delete."""
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except logs.exceptions.ResourceNotFoundException:
        pass


def _create_lambda(ctx, handler_code: str, permissions: list[dict]) -> dict[str, str]:
    """Create a python3.12 function whose role allows logs plus ``permissions``; retry through the
    role-propagation window, wait until Active, and register the function and log-group teardown.
    Returns {name, arn, role}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements += [{"Effect": "Allow", **p} for p in permissions]
    role = _create_role(ctx, {"Version": "2012-10-17", "Statement": statements})
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 30
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role["arn"],
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": _zip(handler_code)},
                Timeout=30,
                MemorySize=128,
                Tags=_xsvc_resource_tags(),
            )
            break
        except ClientError as exc:
            # A new role is briefly not assumable by Lambda.
            if _err(exc)[0] != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(
        _tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")
    )
    # The first invocation creates /aws/lambda/<name>, which outlives the function.
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=40.0,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"], "role": role["name"]}


def _create_queue(ctx) -> dict[str, str]:
    """Create a standard SQS queue (registers its teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), _SQS_NF))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = "ResourceNotFoundException"
    msg = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}", msg)
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    # Invoke keeps reaching a just-deleted function for a while, so it is polled; DryRun runs no
    # code. It resolves the unqualified name to $LATEST and names that in its message.
    _poll_refused(
        lambda: lam.invoke(FunctionName=name, InvocationType="DryRun"),
        nf,
        404,
        f"Invoke {name}",
        f"{msg}:$LATEST",
    )


def _gone_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    msg = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), "NoSuchEntity", 404, f"GetRole {name}", msg)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix="/sim2real/")}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:GetQueueUrl", "Resource": "*"}],
        }
    )
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        "NoSuchEntity",
        404,
        f"PutRolePolicy {name}",
        msg,
    )


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # A deleted queue can keep answering for a while, so the read is polled.
    _poll_refused(
        lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_NF_MSG
    )
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"),
        _SQS_NF,
        400,
        f"SendMessage {name}",
        _SQS_NF_MSG,
    )


def _collect_messages(ctx, queue_url: str, expected_count: int, timeout_s: float) -> list[dict]:
    """Receive (and delete) until ``expected_count`` messages arrived or ``timeout_s`` passed;
    return the JSON-decoded bodies."""
    sqs = ctx.client("sqs")
    bodies: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while len(bodies) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            bodies.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


def _reemit_until(
    ctx, queue_url: str, entries: list[dict], done, *, every_s: float = 6.0
) -> list[dict]:
    """Emit ``entries`` every ``every_s`` until ``done(body)`` holds for a relayed body; return every
    body relayed meanwhile. A fresh rule and target can drop the first events."""
    events = ctx.client("events")
    bodies: list[dict] = []
    deadline = time.monotonic() + _GONE_S
    while time.monotonic() < deadline:
        resp = events.put_events(Entries=entries)
        assert resp.get("FailedEntryCount") == 0, f"PutEvents rejected an entry: {resp!r}"
        bodies += _collect_messages(ctx, queue_url, expected_count=1, timeout_s=every_s)
        if any(done(b) for b in bodies):
            return bodies
    raise AssertionError(
        f"no relay of the awaited event reached {queue_url} within {_GONE_S}s; relayed {bodies!r:.300}"
    )


def _gone_rule(ctx, name: str, target_ids: list[str]) -> None:
    ev = ctx.client("events")
    ev.remove_targets(Rule=name, Ids=target_ids)
    ev.delete_rule(Name=name)
    nf = "ResourceNotFoundException"
    msg = f"Rule {name} does not exist on EventBus default."
    _poll_refused(lambda: ev.describe_rule(Name=name), nf, 400, f"DescribeRule {name}", msg)
    listed = {r["Name"] for r in ev.list_rules(NamePrefix=name).get("Rules", [])}
    assert name not in listed, f"ListRules still lists deleted rule {name}"
    gone_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:gone"
    _refused(
        lambda: ev.put_targets(Rule=name, Targets=[{"Id": "gone", "Arn": gone_arn}]),
        nf,
        400,
        f"PutTargets {name}",
        msg,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
