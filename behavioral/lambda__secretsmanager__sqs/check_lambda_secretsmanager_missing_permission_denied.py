"""lambda-secretsmanager-missing-permission-denied."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-missing-permission-denied"

GROUP = "overly-permissive"

SERVICES = ["lambda", "secretsmanager", "sqs"]


_LOGS_ONLY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ],
}


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
    """Lambda without secretsmanager:GetSecretValue permission must be denied, not silently succeed
    -- and, once granted, the identical call must succeed, so the denial is attributable to the
    missing grant and not to a broken wiring (env var, secret, or invoke path)."""
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    name = ctx.unique_name("secret-")
    secret = sm.create_secret(Name=name, SecretString="top-secret-value")
    ctx.on_cleanup(
        lambda: ctx.client("secretsmanager").delete_secret(
            SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True
        )
    )
    code = """
import boto3, os
sm = boto3.client("secretsmanager")
def handler(event, context):
    try:
        resp = sm.get_secret_value(SecretId=os.environ["SECRET_ARN"])
        return {"ok": True, "secret": resp["SecretString"]}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "message": str(e)}
"""
    # Positive control: the role IS granted the permission, so a working invoke here proves the
    # function, env var and secret are wired correctly before anything is broken.
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {"Action": ["secretsmanager:GetSecretValue"], "Resource": secret["ARN"]}
        ],
        env={"SECRET_ARN": secret["ARN"]},
    )
    granted = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {}),
        lambda r: r["payload"]["ok"] is True,
        timeout_s=60,
        interval_s=3,
        description="positive control: the granted permission returns the secret",
    )
    assert granted["payload"]["ok"] is True, (
        f"positive control must succeed before the grant is removed: {granted['payload']!r}"
    )
    assert granted["payload"]["secret"] == "top-secret-value"

    # Break exactly one thing: replace the role's inline policy with the logs-only baseline,
    # dropping the secretsmanager grant. The poll bounds IAM's own policy-removal propagation --
    # never trust a single invoke right after the change.
    role_name = fn["role_name"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(_LOGS_ONLY_POLICY),
    )
    denied = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {}),
        lambda r: r["payload"]["ok"] is False,
        timeout_s=60,
        interval_s=3,
        description="the removed grant is enforced (IAM policy-removal propagation)",
    )
    assert denied["payload"]["ok"] is False
    assert (
        "AccessDenied" in denied["payload"]["error"]
        or "AccessDenied" in denied["payload"]["message"]
    )
    principal = f"arn:aws:sts::{secret['ARN'].split(':')[4]}:assumed-role/{role_name}/{fn['name']}"
    expected_message = (
        "An error occurred (AccessDeniedException) when calling the GetSecretValue operation: "
        f"User: {principal} is not authorized to perform: secretsmanager:GetSecretValue on resource: "
        f"{secret['ARN']} because no identity-based policy allows the secretsmanager:GetSecretValue action"
    )
    assert denied["payload"]["message"] == expected_message, (
        f"expected {expected_message!r}, got {denied['payload']['message']!r}"
    )

    # Restore: put the original grant back and demand the identical call succeeds again, so the
    # denial above was caused by the missing grant and nothing else.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    *_LOGS_ONLY_POLICY["Statement"],
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue"],
                        "Resource": secret["ARN"],
                    },
                ],
            }
        ),
    )
    restored = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {}),
        lambda r: r["payload"]["ok"] is True,
        timeout_s=60,
        interval_s=3,
        description="restoring the grant returns the identical call to success (grant propagation)",
    )
    assert restored["payload"]["ok"] is True
    assert restored["payload"]["secret"] == "top-secret-value"


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
    # No fixed propagation sleep here: _create_function_with_retry already retries
    # CreateFunction through the "cannot be assumed" window on its own bounded deadline, and every
    # caller that depends on an IAM *permission* (not just the trust policy) taking effect polls
    # its own downstream call for that.
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
            # too.
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
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
    fn["role_name"] = role["name"]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
