"""lambda-send-sqs-missing-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-send-sqs-missing-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without sqs:SendMessage gets AccessDenied (exact message) and the queue stays
    empty, while an identical function with the permission delivers its message."""
    queue = _create_queue(ctx)

    handler_code = """
import boto3, os, json
def lambda_handler(event, context):
    sqs = boto3.client('sqs')
    try:
        sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody='test')
        return {'ok': True, 'error': None}
    except Exception as e:
        err = getattr(e, 'response', {}).get('Error', {})
        return {'ok': False, 'error': str(e), 'code': err.get('Code'), 'message': err.get('Message')}
"""

    allowed_fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": queue["arn"]}],
        env={"QUEUE_URL": queue["url"]},
    )
    positive = _invoke_until_permission_effective(ctx, allowed_fn["name"], {})
    positive_payload = positive["payload"]
    assert positive_payload.get("ok") is True, (
        f"Positive control: expected success with sqs:SendMessage granted, got: {positive_payload}"
    )
    _receive_one(ctx, queue["url"], timeout_s=30)

    denied_fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        env={"QUEUE_URL": queue["url"]},
    )
    result = _invoke_lambda(ctx, denied_fn["name"], {})
    payload = result["payload"]
    assert payload.get("ok") is False, f"Expected failure, got ok=True in: {payload}"
    assert payload.get("code") == "AccessDenied", f"Expected AccessDenied, got: {payload}"
    account_id = queue["arn"].split(":")[4]
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{denied_fn['role_name']}/{denied_fn['name']} "
        f"is not authorized to perform: sqs:sendmessage on resource: {queue['arn']} "
        f"because no identity-based policy allows the sqs:sendmessage action"
    )
    assert payload.get("message") == expected_message, (
        f"Expected message {expected_message!r}, got: {payload.get('message')!r}"
    )

    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )
    count = int(attrs["Attributes"]["ApproximateNumberOfMessages"])
    assert count == 0, f"Queue should be empty after the denied send, got {count} messages"


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
    # Dedent the inline source and alias `handler` to `lambda_handler`, the fixed entrypoint;
    # without that symbol the function fails with Runtime.HandlerNotFound.
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
            # function deletion, so delete it
            # too; it may never have been created, so a missing group is not a teardown failure.
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    Returns {name,arn,role_name}."""
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
    fn = _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )
    return {**fn, "role_name": role["name"]}


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


def _invoke_until_permission_effective(
    ctx, name: str, payload: dict, timeout_s: float = 25.0, interval_s: float = 2.0
) -> dict[str, Any]:
    """Invoke, retrying only while the failure is AccessDenied: the inline permission policy has
    its own IAM propagation window, separate from the role-trust propagation
    `_create_function_with_retry` already retries through. Bounded — raises nothing itself, just
    returns the last result once the deadline passes so the caller's own assert reports it."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = _invoke_lambda(ctx, name, payload)
        payload_out = result.get("payload")
        error = payload_out.get("error") or "" if isinstance(payload_out, dict) else ""
        if "AccessDenied" not in error or time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)


def _receive_one(ctx, queue_url: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> dict:
    """Poll ReceiveMessage until one message appears; delete it and return it (raises on timeout)."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
        )
        messages = resp.get("Messages", [])
        if messages:
            sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"]
            )
            return messages[0]
        time.sleep(interval_s)
    raise AssertionError(
        f"Positive control: no message received from {queue_url} within {timeout_s}s"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
