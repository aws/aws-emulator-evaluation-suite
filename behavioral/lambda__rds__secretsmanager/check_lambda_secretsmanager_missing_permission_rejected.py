"""lambda-secretsmanager-missing-permission-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-secretsmanager-missing-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER_SRC = """
import json
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=event["secret_id"])
        return {"ok": True, "value": resp["SecretString"]}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without secretsmanager:GetSecretValue the Lambda gets AccessDeniedException and no secret
    value; granting that one permission to the same role returns the real value."""
    secrets = ctx.client("secretsmanager")
    ctx.client("lambda")

    secret_value = "sim2real-topsecret-value"
    secret_name = ctx.unique_name("sim2real-lambda-secret-")
    secret_arn = secrets.create_secret(
        Name=secret_name, SecretString=secret_value, Tags=[{"Key": "sim2real", "Value": "true"}]
    )["ARN"]
    ctx.on_cleanup(lambda: secrets.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_arn, role_name = _create_lambda_role(ctx)
    func_name = _create_function(ctx, role_arn)

    payload = json.dumps({"secret_id": secret_arn}).encode()

    # --- negative: role has no secretsmanager:GetSecretValue permission at all ---
    result = _invoke(ctx, func_name, payload)
    assert result["ok"] is False, f"expected the secret fetch to be denied, got {result!r}"
    assert result["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException with no secretsmanager permissions, got {result!r}"
    )
    assert "value" not in result, "secret value must not be present when access was denied"

    # --- fix the one blocking condition: grant read access on this exact secret ---
    iam = ctx.client("iam")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="secrets-read", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="secrets-read"))

    # --- positive control: same function, same secret, only the permission changed ---
    fixed_result = _poll_until_ok(ctx, func_name, payload, timeout_s=90)
    assert fixed_result["ok"] is True, f"expected the fetch to succeed once permission was granted, got {fixed_result!r}"
    assert fixed_result["value"] == secret_value, (
        f"expected the exact secret value back, got {fixed_result['value']!r}"
    )


def _create_lambda_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-secret-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
    )
    return role["Arn"], role_name


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", src)
    return buf.getvalue()


def _create_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    func_name = ctx.unique_name("sim2real-lambda-secret-fn-")
    deadline = time.monotonic() + 60
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip_bytes(_HANDLER_SRC)},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise AssertionError(f"CreateFunction never accepted the new role: {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    lam.get_waiter("function_active").wait(FunctionName=func_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return func_name


def _invoke(ctx, func_name: str, payload: bytes) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=func_name, Payload=payload)
    body = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"lambda invocation raised unexpectedly: {body!r}"
    return body


def _poll_until_ok(ctx, func_name: str, payload: bytes, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = _invoke(ctx, func_name, payload)
        if last.get("ok") is True:
            return last
        time.sleep(5)
    raise AssertionError(f"secret fetch never succeeded within {timeout_s}s after granting permission, last={last!r}")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
