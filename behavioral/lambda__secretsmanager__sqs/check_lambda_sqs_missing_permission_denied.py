"""lambda-sqs-missing-permission-denied."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sqs-missing-permission-denied"

GROUP = "overly-permissive"

SERVICES = ["lambda", "secretsmanager", "sqs"]


def _sqs_send_message_body(queue_url: str) -> str:
    return f'''
import boto3
sqs = boto3.client("sqs")
QUEUE_URL = "{queue_url}"
def handler(event, context):
    try:
        sqs.send_message(QueueUrl=QUEUE_URL, MessageBody="should-not-arrive")
        return {{"ok": True}}
    except Exception as e:
        return {{"ok": False, "error": type(e).__name__, "message": str(e)}}
'''


def _invoke_until(
    ctx, name, expect_ok, *, timeout_s=45.0, interval_s=3.0, description="condition"
) -> dict[str, Any]:
    """Invoke repeatedly until payload["ok"] matches `expect_ok`; return the final invoke result
    (raises on timeout). Rides out IAM inline-policy propagation without trusting a fixed sleep as
    a barrier — a target that is genuinely correct but a few seconds slower must not read as wrong."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _invoke_lambda(ctx, name, {})
        if last["payload"].get("ok") is expect_ok:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _statements(sqs_arn: str | None) -> list[dict[str, Any]]:
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
    if sqs_arn:
        statements.append(
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": [sqs_arn]}
        )
    return statements


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda role without sqs:SendMessage gets AccessDenied and its message never arrives, while
    a twin function whose role has the permission delivers its message; separate cold functions
    are used because a warm execution environment keeps its role credentials after a revoke."""
    control_queue = _create_queue(ctx)
    subject_queue = _create_queue(ctx)

    control_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": _statements(control_queue["arn"]),
        },
    )
    subject_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": _statements(None)},
    )
    control_fn = _create_function_with_retry(
        ctx, _sqs_send_message_body(control_queue["url"]), control_role["arn"], {}
    )
    subject_fn = _create_function_with_retry(
        ctx, _sqs_send_message_body(subject_queue["url"]), subject_role["arn"], {}
    )
    sqs = ctx.client("sqs")

    # Positive control: granted, on its own queue, the send succeeds and is independently observed.
    control = _invoke_until(
        ctx,
        control_fn["name"],
        True,
        description="control (sqs:SendMessage granted) send succeeds",
    )
    assert control["payload"]["ok"] is True, (
        f"expected ok=True with sqs:SendMessage granted, got {control['payload']!r}"
    )
    delivered = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=control_queue["url"], WaitTimeSeconds=2, MaxNumberOfMessages=10
        ),
        lambda r: "Messages" in r,
        timeout_s=30,
        description="control message delivered to its queue",
    )
    assert delivered["Messages"][0]["Body"] == "should-not-arrive", (
        f"expected the control send's body at the queue, got {delivered['Messages'][0]!r}"
    )

    # Subject: no sqs:SendMessage at all — the specific denial, and the effect absent at an
    # independent read of its own (never-permitted) queue.
    denied = _invoke_until(
        ctx,
        subject_fn["name"],
        False,
        description="subject (no sqs:SendMessage) send is denied",
    )
    assert denied["payload"]["ok"] is False, (
        f"expected ok=False without sqs:SendMessage, got {denied['payload']!r}"
    )
    assert (
        "AccessDenied" in denied["payload"]["error"]
        or "AccessDenied" in denied["payload"]["message"]
    ), f"expected AccessDenied, got {denied['payload']!r}"
    principal = (
        f"arn:aws:sts::{subject_queue['arn'].split(':')[4]}:assumed-role/{subject_role['name']}/{subject_fn['name']}"
    )
    expected_message = (
        "An error occurred (AccessDenied) when calling the SendMessage operation: "
        f"User: {principal} is not authorized to perform: sqs:sendmessage on resource: "
        f"{subject_queue['arn']} because no identity-based policy allows the sqs:sendmessage action"
    )
    assert denied["payload"]["message"] == expected_message, (
        f"expected {expected_message!r}, got {denied['payload']['message']!r}"
    )
    resp = sqs.receive_message(
        QueueUrl=subject_queue["url"], WaitTimeSeconds=1, MaxNumberOfMessages=10
    )
    assert "Messages" not in resp, (
        f"a denied send must not have delivered a message, got {resp!r}"
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
    # No fixed propagation sleep here: _create_function_with_retry bounds-retries function
    # creation on "cannot be assumed", which is this same trust/permission propagation window.
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
            # The function creates /aws/lambda/<name> on its first logged invoke and the group outlives
            # the function, so delete it too.
            logs = ctx.client("logs")
            ctx.on_cleanup(lambda: _delete_log_group(logs, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


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


def _delete_log_group(logs, group_name: str) -> None:
    """Delete the function's log group; a function that never logged has none (ResourceNotFoundException)."""
    try:
        logs.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
