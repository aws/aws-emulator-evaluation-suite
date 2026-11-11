"""lambda-no-permissions-denied-both-services."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-no-permissions-denied-both-services"

GROUP = "overly-permissive"

SERVICES = ["lambda", "secretsmanager", "sqs"]


def _handler_code(secret_arn: str, queue_url: str) -> str:
    return f'''
import boto3
sm = boto3.client("secretsmanager")
sqs = boto3.client("sqs")
SECRET_ARN = "{secret_arn}"
QUEUE_URL = "{queue_url}"
def handler(event, context):
    out = {{}}
    try:
        resp = sm.get_secret_value(SecretId=SECRET_ARN)
        out["secret_ok"] = True
        out["secret_value"] = resp["SecretString"]
    except Exception as e:
        out["secret_ok"] = False
        out["secret_error"] = str(e)
        out["secret_code"] = e.response["Error"]["Code"]
        out["secret_message"] = e.response["Error"]["Message"]
    try:
        sqs.send_message(QueueUrl=QUEUE_URL, MessageBody="x")
        out["sqs_ok"] = True
    except Exception as e:
        out["sqs_ok"] = False
        out["sqs_error"] = str(e)
        out["sqs_code"] = e.response["Error"]["Code"]
        out["sqs_message"] = e.response["Error"]["Message"]
    return out
'''


def _invoke_until(
    ctx, name, predicate, *, timeout_s=45.0, interval_s=3.0, description="condition"
) -> dict[str, Any]:
    """Invoke repeatedly until predicate(payload) is truthy; return the final invoke result
    (raises on timeout). Rides out IAM inline-policy propagation without trusting a fixed sleep as
    a barrier — a target that is genuinely correct but a few seconds slower must not read as wrong."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _invoke_lambda(ctx, name, {})
        if predicate(last.get("payload") or {}):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


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
    """A Lambda role with no permissions is denied by Secrets Manager (AccessDeniedException) and
    SQS (AccessDenied), both with exact messages, and nothing is sent, while a twin function
    whose role holds both permissions reads its secret and delivers its message."""
    sm = ctx.client("secretsmanager")
    sqs = ctx.client("sqs")

    control_secret = sm.create_secret(
        Name=ctx.unique_name("secret-"), SecretString="control-value"
    )
    ctx.on_cleanup(
        lambda: ctx.client("secretsmanager").delete_secret(
            SecretId=control_secret["ARN"], ForceDeleteWithoutRecovery=True
        )
    )
    control_queue = _create_queue(ctx)

    subject_secret = sm.create_secret(
        Name=ctx.unique_name("secret-"), SecretString="unreachable"
    )
    ctx.on_cleanup(
        lambda: ctx.client("secretsmanager").delete_secret(
            SecretId=subject_secret["ARN"], ForceDeleteWithoutRecovery=True
        )
    )
    subject_queue = _create_queue(ctx)

    control_fn = _create_lambda(
        ctx,
        _handler_code(control_secret["ARN"], control_queue["url"]),
        permissions=[
            {
                "Action": "secretsmanager:GetSecretValue",
                "Resource": control_secret["ARN"],
            },
            {"Action": "sqs:SendMessage", "Resource": control_queue["arn"]},
        ],
    )
    subject_fn = _create_lambda(
        ctx, _handler_code(subject_secret["ARN"], subject_queue["url"]), permissions=[]
    )

    # Positive control: granted both permissions, on resources of its own — both calls succeed and
    # the effect is independently observed.
    control = _invoke_until(
        ctx,
        control_fn["name"],
        lambda p: p.get("secret_ok") is True and p.get("sqs_ok") is True,
        description="control (both permissions granted) succeeds on both services",
    )
    cp = control["payload"]
    assert cp["secret_ok"] is True and cp["secret_value"] == "control-value", (
        f"expected the control's own secret value with GetSecretValue granted, got {cp!r}"
    )
    assert cp["sqs_ok"] is True, (
        f"expected sqs send to succeed with SendMessage granted, got {cp!r}"
    )
    delivered = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=control_queue["url"], WaitTimeSeconds=2, MaxNumberOfMessages=10
        ),
        lambda r: "Messages" in r,
        timeout_s=30,
        description="control message delivered to its queue",
    )
    assert delivered["Messages"][0]["Body"] == "x", (
        f"expected the control send's body at the queue, got {delivered['Messages'][0]!r}"
    )

    # Subject: no permissions at all — the specific denial on both services, and the effect
    # absent at an independent read of its own (never-permitted) queue.
    denied = _invoke_until(
        ctx,
        subject_fn["name"],
        lambda p: p.get("secret_ok") is False and p.get("sqs_ok") is False,
        description="subject (no permissions) is denied on both services",
    )
    dp = denied["payload"]
    account = subject_fn["role_arn"].split(":")[4]
    principal = f"arn:aws:sts::{account}:assumed-role/{subject_fn['role_arn'].rsplit('/', 1)[1]}/{subject_fn['name']}"
    assert dp["secret_ok"] is False and dp["secret_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException on secretsmanager, got {dp!r}"
    )
    assert dp["secret_message"] == (
        f"User: {principal} is not authorized to perform: secretsmanager:GetSecretValue on resource: "
        f"{subject_secret['ARN']} because no identity-based policy allows the secretsmanager:GetSecretValue action"
    ), f"unexpected secretsmanager AccessDeniedException message: {dp['secret_message']!r}"
    assert dp["sqs_ok"] is False and dp["sqs_code"] == "AccessDenied", (
        f"expected AccessDenied on sqs, got {dp!r}"
    )
    assert dp["sqs_message"] == (
        f"User: {principal} is not authorized to perform: sqs:sendmessage on resource: "
        f"{subject_queue['arn']} because no identity-based policy allows the sqs:sendmessage action"
    ), f"unexpected sqs AccessDenied message: {dp['sqs_message']!r}"
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
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion, so delete it
            # too; a group that was never created is already absent.
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


def _delete_log_group_if_present(ctx, name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=name)
    except logs.exceptions.ResourceNotFoundException:
        pass


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
    Returns {name,arn,role_arn}."""
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
    fn["role_arn"] = role["arn"]
    return fn


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
