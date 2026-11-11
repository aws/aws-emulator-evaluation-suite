"""lambda-secretsmanager-kms-decrypt-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-secretsmanager-kms-decrypt-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_HANDLER_CODE = """
import boto3, json, os
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=os.environ["SECRET_ARN"])
        return {"ok": True, "secret_string": resp.get("SecretString")}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A function whose role has secretsmanager:GetSecretValue but no kms:Decrypt on the secret's key gets
    AccessDeniedException and no plaintext; after kms:Decrypt on that key is added to the same role, the same
    call returns the stored value.
    """
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description="sim2real behavioral check CMK",
        Tags=[{"TagKey": "sim2real", "TagValue": "lambda-secretsmanager-kms-decrypt-permission-negative"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    secret_value = "kms-protected-secret-" + ctx.unique_name("")
    secret_arn = _create_secret(ctx, secret_value, kms_key_id=key_id)

    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE, env={"SECRET_ARN": secret_arn})

    _, body_denied = _invoke(ctx, fn_name)
    assert body_denied["ok"] is False, f"expected the CMK-encrypted secret read to be denied, got {body_denied!r}"
    assert body_denied["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for a role with GetSecretValue but no kms:Decrypt, "
        f"got {body_denied['error_code']!r}"
    )
    assert "secret_string" not in body_denied, f"a denied read must not leak plaintext: {body_denied!r}"

    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    kms_policy_name = ctx.unique_name("sim2real-kms-decrypt-")
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=kms_policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=kms_policy_name))

    body_allowed = _poll_until_success(ctx, fn_name, timeout_s=60.0)
    assert body_allowed["ok"] is True, (
        f"expected the identical call to succeed once kms:Decrypt was granted for {key_arn}, "
        f"got {body_allowed!r}"
    )
    assert body_allowed["secret_string"] == secret_value, (
        f"expected the recovered plaintext to match what was stored, "
        f"got {body_allowed.get('secret_string')!r} != {secret_value!r}"
    )


def _poll_until_success(ctx: Any, fn_name: str, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_body: dict = {}
    while time.monotonic() < deadline:
        _, body = _invoke(ctx, fn_name)
        last_body = body
        if body.get("ok") is True:
            return body
        time.sleep(3)
    raise AssertionError(f"secret never became retrievable after granting kms:Decrypt: {last_body}")


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
        Tags=[{"Key": "sim2real", "Value": "lambda-secretsmanager-kms-decrypt-permission-negative"}],
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
                Tags={"sim2real": "lambda-secretsmanager-kms-decrypt-permission-negative"},
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
        "Tags": [{"Key": "sim2real", "Value": "lambda-secretsmanager-kms-decrypt-permission-negative"}],
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
