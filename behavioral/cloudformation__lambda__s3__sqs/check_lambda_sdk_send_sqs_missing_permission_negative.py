"""lambda-sdk-send-sqs-missing-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-send-sqs-missing-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]


_LOGS_ONLY_STATEMENTS = [
    {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*",
    }
]


def _role_policy_document(queue_arn: str | None) -> str:
    """The Lambda role's inline policy: logs always allowed, sqs:SendMessage only when granted."""
    statements = list(_LOGS_ONLY_STATEMENTS)
    if queue_arn is not None:
        statements.append(
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": queue_arn}
        )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _lambda_role_name(ctx, fn_name: str) -> str:
    role_arn = ctx.client("lambda").get_function_configuration(FunctionName=fn_name)["Role"]
    return role_arn.rsplit("/", 1)[-1]


def _drain_one(ctx, queue_url: str, *, expect_substring: str, timeout_s: float = 30.0):
    """Poll for exactly one message, assert it carries the expected marker, then delete it."""
    sqs = ctx.client("sqs")
    msgs = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda m: bool(m),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"a message tagged {expect_substring!r} delivered to the queue",
    )
    body = msgs[0]["Body"]
    assert expect_substring in body, f"expected {expect_substring!r} in delivered body: {body!r}"
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])


def _purge_queue(ctx, queue_url: str, *, timeout_s: float = 20.0) -> int:
    """Delete every message currently visible in the queue; return how many were removed.

    IAM revocation is not instant, so a poll that retries a call until it starts being denied
    can itself land messages sent by earlier, not-yet-revoked attempts. Those strays must be
    swept before an absence assertion means anything."""
    sqs = ctx.client("sqs")
    removed = 0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            removed += 1
    return removed


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda's SendMessage is delivered while its role grants sqs:SendMessage, fails with
    AccessDenied and AWS's exact message and delivers nothing once revoked, and is delivered
    again once restored."""
    queue = _create_queue(ctx)
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    handler_code = """
import boto3, os, json
from botocore.exceptions import ClientError
def lambda_handler(event, context):
    sqs = boto3.client('sqs')
    try:
        sqs.send_message(
            QueueUrl=os.environ['QUEUE_URL'],
            MessageBody=json.dumps(event)
        )
        return {'statusCode': 200}
    except ClientError as e:
        return {'error': e.response['Error']['Code'], 'message': e.response['Error'].get('Message')}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": queue["arn"]}],
        env={"QUEUE_URL": queue["url"]},
    )
    role_name = _lambda_role_name(ctx, fn["name"])

    # ---- positive control: sqs:SendMessage is granted, the send succeeds and is delivered ----
    before = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {"phase": "before"}),
        lambda r: r.get("payload", {}).get("statusCode") == 200,
        timeout_s=30.0,
        interval_s=3.0,
        description="SDK send succeeds while sqs:SendMessage is granted",
    )
    assert not before.get("error"), f"positive control unexpectedly errored: {before!r}"
    _drain_one(ctx, queue["url"], expect_substring="before")

    # ---- break exactly one thing: revoke sqs:SendMessage from the role ----
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=_role_policy_document(queue_arn=None),
    )

    denied = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {"phase": "denied"}),
        lambda r: r.get("payload", {}).get("error") is not None,
        timeout_s=45.0,
        interval_s=3.0,
        description="SDK send denied after sqs:SendMessage is revoked",
    )
    error_code = denied["payload"].get("error")
    assert error_code == "AccessDenied", (
        f"Expected AccessDenied once sqs:SendMessage was revoked, got {error_code!r}: {denied!r}"
    )
    account = queue["arn"].split(":")[4]
    expected_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{fn['name']} is not authorized to "
        f"perform: sqs:sendmessage on resource: {queue['arn']} because no identity-based policy "
        f"allows the sqs:sendmessage action"
    )
    assert denied["payload"].get("message") == expected_message, (
        f"Expected message {expected_message!r}, got {denied['payload'].get('message')!r}"
    )

    # The poll above may itself have succeeded (and delivered a message) on earlier attempts
    # made while the revocation was still propagating. Sweep those strays, then re-confirm the
    # call is STABLY denied before treating an empty queue as evidence of anything.
    _purge_queue(ctx, queue["url"])
    confirm = _invoke_lambda(ctx, fn["name"], {"phase": "denied-confirm"})
    confirm_code = confirm["payload"].get("error")
    assert confirm_code == "AccessDenied", (
        f"Expected the send to still be denied once revoked, got {confirm_code!r}: {confirm!r}"
    )
    assert confirm["payload"].get("message") == expected_message, (
        f"Expected message {expected_message!r}, got {confirm['payload'].get('message')!r}"
    )

    # ---- effect is absent: no message reaches the queue while the permission is missing ----
    resp = sqs.receive_message(
        QueueUrl=queue["url"], MaxNumberOfMessages=1, WaitTimeSeconds=5
    )
    assert not resp.get("Messages"), (
        f"Queue should be empty when Lambda lacks sqs:SendMessage, got: {resp.get('Messages')!r}"
    )

    # ---- restore: the identical call now succeeds again ----
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=_role_policy_document(queue_arn=queue["arn"]),
    )

    after = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {"phase": "after"}),
        lambda r: r.get("payload", {}).get("statusCode") == 200,
        timeout_s=45.0,
        interval_s=3.0,
        description="SDK send succeeds again once sqs:SendMessage is restored",
    )
    assert not after.get("error"), f"restored call unexpectedly errored: {after!r}"
    _drain_one(ctx, queue["url"], expect_substring="after")


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
    # No fixed propagation wait here: _create_function_with_retry bounds-and-retries the
    # "cannot be assumed" / "InvalidParameterValue" window that IAM role propagation causes.
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


def _delete_log_group_if_present(ctx, group: str) -> None:
    """Delete a log group; one that was never created is already clean."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
            # The function creates /aws/lambda/<name> on its first invoke and the group outlives the
            # function, so delete it too; Lambda creates it asynchronously, so one that never
            # appeared is not a failure.
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
