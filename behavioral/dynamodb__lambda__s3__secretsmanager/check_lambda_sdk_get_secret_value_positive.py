"""lambda-sdk-get-secret-value-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-get-secret-value-positive"
GROUP = "sdk-call"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_HANDLER_CODE = """
import boto3, json, os

def handler(event, context):
    client = boto3.client("secretsmanager")
    resp = client.get_secret_value(SecretId=os.environ["SECRET_ARN"])
    return {"secret_string": resp.get("SecretString")}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A Lambda whose role grants secretsmanager:GetSecretValue retrieves the exact
    secret value at runtime via boto3, proving the SDK call crosses the boundary."""
    secret_value = "s3cr3t-value-" + ctx.unique_name("")
    secret_arn = _create_secret(ctx, secret_value)
    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE, env={"SECRET_ARN": secret_arn})

    resp, body = _invoke(ctx, fn_name)
    assert resp.get("FunctionError") is None, f"unexpected FunctionError: {body}"
    assert body["secret_string"] == secret_value, (
        f"expected secret value {secret_value!r}, lambda read {body['secret_string']!r} via boto3"
    )


def _create_role(ctx: Any, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    if statements:
        policy_name = ctx.unique_name("sim2real-lambda-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(
    ctx: Any, role_arn: str, handler_code: str, env: dict | None = None, timeout: int = 30
) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", handler_code)
    zip_bytes = buf.getvalue()

    last_err: Exception | None = None
    deadline = time.monotonic() + 90
    created = False
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real": "true"},
            )
            created = True
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if not created:
        raise AssertionError(f"function creation never succeeded (role propagation): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return name


def _wait_function_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _invoke(ctx: Any, name: str, payload: dict | None = None) -> tuple[dict, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    return resp, body


def _create_secret(ctx: Any, secret_string: str, kms_key_id: str | None = None) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-secret-")
    kwargs: dict[str, Any] = {
        "Name": name,
        "SecretString": secret_string,
        "Tags": [{"Key": "sim2real", "Value": "true"}],
    }
    if kms_key_id:
        kwargs["KmsKeyId"] = kms_key_id
    resp = sm.create_secret(**kwargs)
    arn = resp["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


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
