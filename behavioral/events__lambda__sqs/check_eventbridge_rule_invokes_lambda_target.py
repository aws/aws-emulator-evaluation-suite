"""eventbridge-rule-invokes-lambda-target."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-invokes-lambda-target"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "sqs"]


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
    """An EventBridge rule with a Lambda target invokes the function for the matching entry of a
    PutEvents and never for the decoy entry beside it, which the rule's source pattern excludes."""
    results = _create_queue(ctx)
    fn = _create_lambda(
        ctx,
        _forwarder_code(results["url"]),
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": results["arn"]}],
    )

    events = ctx.client("events")
    lambda_client = ctx.client("lambda")
    rule_name = ctx.unique_name("rule-eb-lambda-")
    # A per-run source keeps the rule hermetic on the shared default bus.
    source = ctx.unique_name("custom.itest.")
    rule = events.put_rule(
        Name=rule_name, EventPattern=json.dumps({"source": [source]})
    )
    ctx.on_cleanup(
        _tolerant(
            lambda: ctx.client("events").delete_rule(Name=rule_name),
            "ResourceNotFoundException",
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

    # Re-emit until delivered: a freshly created rule/target can drop the first
    # event before the EB->Lambda->SQS path is live, and EventBridge never
    # retries a dropped event. Every PutEvents also carries a decoy the rule does not match.
    decoy_source = ctx.unique_name("custom.decoy.")
    entries = [
        {
            "Source": source,
            "DetailType": "Test",
            "Resources": [results["arn"]],
            "Detail": json.dumps({"key": "val"}),
        },
        {
            "Source": decoy_source,
            "DetailType": "Test",
            "Resources": [results["arn"]],
            "Detail": json.dumps({"key": "decoy"}),
        },
    ]
    messages, latency_s = _reemit_until_delivered(ctx, results["url"], entries, source)
    body = messages[0]["body"]
    # Absence of the decoy is graded for at least as long as the match took (floor 10 s, cap 60 s).
    window_s = min(max(latency_s, _ABSENCE_FLOOR_S), _ABSENCE_CAP_S)
    late = _collect_messages(ctx, results["url"], expected_count=10**6, timeout_s=window_s)
    decoys = [m["body"] for m in late if isinstance(m["body"], dict) and m["body"].get("source") != source]
    assert not decoys, f"the rule invoked its target for an entry it does not match: {decoys!r}"
    assert body["detail"]["key"] == "val", (
        f"expected the EventBridge->Lambda->SQS relay to deliver detail.key='val', "
        f"got forwarded body={body!r}"
    )
    for field, want in (
        ("source", source),
        ("detail-type", "Test"),
        ("account", ctx.account),
        ("region", ctx.region),
        ("resources", [results["arn"]]),
    ):
        assert body.get(field) == want, (
            f"expected relayed event {field}={want!r}, got {body.get(field)!r}"
        )
    role_name = lambda_client.get_function_configuration(FunctionName=fn["name"])[
        "Role"
    ].split("/")[-1]
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_rule(ctx, rule_name, ["t1"])
    _gone_lambda(ctx, fn["name"])
    _gone_role(ctx, role_name, "/sim2real/")
    _gone_queue(ctx, results["name"], results["url"])


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion; DeleteConflict is
    retried while IAM catches up with the removals, and only an already-gone role (NoSuchEntity)
    is tolerated."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + 60
    while True:
        try:
            for p in iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            ):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
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


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(
                _tolerant(
                    lambda: lam.delete_function(FunctionName=name),
                    "ResourceNotFoundException",
                )
            )
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion, so it is deleted too. A
            # function that is never invoked never creates it, so its absence is not a failure.
            ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _collect_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive or timeout_s passes; return what arrived."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return messages


#: The fixed bounds of a "nothing arrives" window.
_ABSENCE_FLOOR_S = 10.0
_ABSENCE_CAP_S = 60.0


def _reemit_until_delivered(ctx, queue_url, entries, source, *, poll_s=6.0):
    """Emit the entries repeatedly until the one from ``source`` lands on the SQS queue; return the
    messages and the seconds from the delivering emission to its arrival. A relayed event from any
    other source fails at once. The deadline is the default class budget (_GONE_S)."""
    events = ctx.client("events")
    deadline = time.monotonic() + _GONE_S
    emitted = 0
    while True:
        resp = events.put_events(Entries=entries)
        assert resp.get("FailedEntryCount") == 0, f"PutEvents rejected an entry: {resp!r}"
        sent = time.monotonic()
        emitted += 1
        messages = _collect_messages(ctx, queue_url, expected_count=1, timeout_s=poll_s)
        if messages:
            latency_s = time.monotonic() - sent
            others = [m["body"] for m in messages
                      if not isinstance(m["body"], dict) or m["body"].get("source") != source]
            assert not others, f"the rule invoked its target for an entry it does not match: {others!r}"
            return messages, latency_s
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"event never delivered to {queue_url} within {_GONE_S}s "
                f"({emitted} emissions, re-emitted every {poll_s}s)"
            )


def _delete_function_log_group(ctx, name: str) -> None:
    """Delete /aws/lambda/<name>; a function that never ran has none to delete."""
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except logs.exceptions.ResourceNotFoundException:
        pass


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str) -> None:
    """``fn()`` must fail with one of ``codes`` in the HTTP class of ``status``, a non-empty message."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        in_class = isinstance(got, int) and got // 100 == status // 100
        assert code in codes and in_class, (
            f"{what}: expected {'/'.join(codes)} HTTP {status // 100}xx, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, timeout_s: float = _GONE_S) -> None:
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
                _refused(fn, codes, status, what)
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


def _gone_rule(ctx, name: str, target_ids: list[str], bus: str = "default") -> None:
    ev = ctx.client("events")
    if target_ids:
        ev.remove_targets(Rule=name, EventBusName=bus, Ids=target_ids)
    ev.delete_rule(Name=name, EventBusName=bus)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: ev.describe_rule(Name=name, EventBusName=bus), nf, 400, f"DescribeRule {name}")
    listed = {r["Name"] for r in ev.list_rules(NamePrefix=name, EventBusName=bus).get("Rules", [])}
    assert name not in listed, f"ListRules still lists deleted rule {name}"
    _refused(
        lambda: ev.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "gone", "Arn": f"arn:aws:sqs:{ctx.region}:{ctx.account}:gone"}]),
        nf, 400, f"PutTargets {name}",
    )


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}")
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    # Invoke keeps reaching a just-deleted function for a while on AWS, so it converges like GetFunction.
    _poll_refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}")


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}")
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}",
    )


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}")
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
