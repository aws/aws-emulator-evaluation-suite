"""eventbridge-lambda-target-without-resource-policy-no-invoke."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-lambda-target-without-resource-policy-no-invoke"

GROUP = "overly-permissive"

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


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without a Lambda resource policy grant, EventBridge must not be able to invoke it -- proven
    against a positive control on identical wiring, not a bare timeout (a target with no delivery
    path at all must not score as correctly blocked)."""
    events = ctx.client("events")
    lam = ctx.client("lambda")

    ctrl_queue = _create_queue(ctx)
    ctrl_fn = _create_lambda(
        ctx,
        _forwarder_code(ctrl_queue["url"]),
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": ctrl_queue["arn"]}],
    )
    noperm_queue = _create_queue(ctx)
    noperm_fn = _create_lambda(
        ctx,
        _forwarder_code(noperm_queue["url"]),
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": noperm_queue["arn"]}],
    )

    ctrl_rule = ctx.unique_name("rule-ctrlperm-")
    ctrl_rule_arn = events.put_rule(
        Name=ctrl_rule, EventPattern=json.dumps({"source": ["custom.ctrlperm"]})
    )["RuleArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=ctrl_rule))
    lam.add_permission(
        FunctionName=ctrl_fn["name"],
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=ctrl_rule_arn,
    )
    events.put_targets(Rule=ctrl_rule, Targets=[{"Id": "t1", "Arn": ctrl_fn["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=ctrl_rule, Ids=["t1"])
    )

    noperm_rule = ctx.unique_name("rule-noperm-")
    events.put_rule(
        Name=noperm_rule, EventPattern=json.dumps({"source": ["custom.noperm"]})
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=noperm_rule))

    # Intentionally skip add_permission (no resource-based policy grant).
    events.put_targets(Rule=noperm_rule, Targets=[{"Id": "t1", "Arn": noperm_fn["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=noperm_rule, Ids=["t1"])
    )

    # Fire both in the same instant; the control's own measured latency on this identical
    # wiring sets the window the negative must clear -- a fixed sleep can't tell "blocked"
    # from "just slower than 30s".
    start = time.monotonic()
    events.put_events(
        Entries=[
            {"Source": "custom.ctrlperm", "DetailType": "Test", "Detail": "{}"},
            {"Source": "custom.noperm", "DetailType": "Test", "Detail": "{}"},
        ]
    )

    ctrl_messages = _wait_for_messages(ctx, ctrl_queue["url"], expected_count=1, timeout_s=60)
    assert len(ctrl_messages) == 1, (
        "positive control: an identically-wired target WITH a resource policy grant "
        f"must be invoked; got {len(ctrl_messages)} message(s)"
    )
    positive_latency_s = time.monotonic() - start

    window_s = max(15.0, positive_latency_s * 3)
    noperm_messages = _collect_messages(
        ctx, noperm_queue["url"], expected_count=1, timeout_s=window_s
    )
    assert len(noperm_messages) == 0, (
        "Lambda must not be invoked without a resource policy grant: got "
        f"{len(noperm_messages)} message(s) after waiting {window_s:.1f}s "
        f"(>= 3x the positive control's {positive_latency_s:.1f}s delivery "
        "latency on identical wiring)"
    )

    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=noperm_queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        "independent queue-attribute read must also confirm zero messages "
        f"delivered, got {attrs['ApproximateNumberOfMessages']}"
    )


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
    # IAM role trust/permission propagation before a service assumes it is a bounded
    # retry, not a sleep here: _create_function_with_retry retries CreateFunction on
    # "cannot be assumed" for up to 30s.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
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
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
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


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    messages = _collect_messages(ctx, queue_url, expected_count, timeout_s, delete)
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


def _delete_function_log_group(ctx, name: str) -> None:
    """Delete /aws/lambda/<name>; a function that never ran has none to delete."""
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except logs.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
