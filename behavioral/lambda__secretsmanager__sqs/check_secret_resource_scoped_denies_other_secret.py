"""secret-resource-scoped-denies-other-secret."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secret-resource-scoped-denies-other-secret"

GROUP = "overly-permissive"

SERVICES = ["lambda", "secretsmanager", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """IAM policy scoped to secret A must not allow GetSecretValue on secret B."""
    sm = ctx.client("secretsmanager")
    name_a = ctx.unique_name("secret-a-")
    name_b = ctx.unique_name("secret-b-")
    secret_a = sm.create_secret(Name=name_a, SecretString="secret-a-value")
    secret_b = sm.create_secret(Name=name_b, SecretString="secret-b-value")
    ctx.on_cleanup(
        lambda: ctx.client("secretsmanager").delete_secret(
            SecretId=secret_a["ARN"], ForceDeleteWithoutRecovery=True
        )
    )
    ctx.on_cleanup(
        lambda: ctx.client("secretsmanager").delete_secret(
            SecretId=secret_b["ARN"], ForceDeleteWithoutRecovery=True
        )
    )
    code = """
import boto3, os
sm = boto3.client("secretsmanager")
def handler(event, context):
    out = {}
    try:
        resp = sm.get_secret_value(SecretId=os.environ["OWN_SECRET_ARN"])
        out["own_ok"] = True
        out["own_secret"] = resp["SecretString"]
    except Exception as e:
        out["own_ok"] = False
        out["own_code"] = getattr(e, "response", {}).get("Error", {}).get("Code")
        out["own_message"] = str(e)
    try:
        resp = sm.get_secret_value(SecretId=os.environ["OTHER_SECRET_ARN"])
        out["other_ok"] = True
        out["other_secret"] = resp["SecretString"]
    except Exception as e:
        out["other_ok"] = False
        out["other_code"] = getattr(e, "response", {}).get("Error", {}).get("Code")
        out["other_message"] = str(e)
    return out
"""
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {"Action": ["secretsmanager:GetSecretValue"], "Resource": secret_a["ARN"]}
        ],
        env={"OWN_SECRET_ARN": secret_a["ARN"], "OTHER_SECRET_ARN": secret_b["ARN"]},
    )
    # The inline policy can take a few seconds longer to become effective for an actual
    # secretsmanager call than the trust policy takes to let Lambda assume the role (already
    # retried in _create_function_with_retry); poll the positive control instead of guessing a
    # fixed wait, so a slow-but-correct target isn't scored as denying everything.
    result = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {}),
        lambda r: r.get("payload", {}).get("own_ok") is True,
        timeout_s=60.0,
        interval_s=5.0,
        description="policy scoped to secret A grants GetSecretValue on secret A itself",
    )
    payload = result["payload"]
    assert payload["own_ok"] is True and payload["own_secret"] == "secret-a-value", (
        f"positive control failed: policy scoped to secret A must grant GetSecretValue on "
        f"secret A itself, got {payload}"
    )
    assert payload["other_ok"] is False, (
        f"policy scoped to secret A must not grant access to secret B, got {payload}"
    )
    assert (
        "AccessDenied" in (payload.get("other_code") or "")
        or "AccessDenied" in (payload.get("other_message") or "")
    ), f"expected AccessDenied denying secret B, got {payload}"
    role_arn = ctx.client("lambda").get_function_configuration(FunctionName=fn["name"])["Role"]
    principal = (
        f"arn:aws:sts::{secret_b['ARN'].split(':')[4]}:assumed-role/{role_arn.rsplit('/', 1)[1]}/{fn['name']}"
    )
    expected_message = (
        "An error occurred (AccessDeniedException) when calling the GetSecretValue operation: "
        f"User: {principal} is not authorized to perform: secretsmanager:GetSecretValue on resource: "
        f"{secret_b['ARN']} because no identity-based policy allows the secretsmanager:GetSecretValue action"
    )
    assert payload["other_message"] == expected_message, (
        f"expected {expected_message!r}, got {payload['other_message']!r}"
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
