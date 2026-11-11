"""lambda-secretsmanager-binary-secret-format."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-binary-secret-format"
GROUP = "data-format"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_LAMBDA_CODE = """
import boto3, base64, os

sm = boto3.client('secretsmanager')

def _describe(secret_id):
    resp = sm.get_secret_value(SecretId=secret_id)
    if resp.get('SecretBinary') is not None:
        return {'type': 'binary', 'value_b64': base64.b64encode(resp['SecretBinary']).decode('ascii')}
    return {'type': 'string', 'value': resp['SecretString']}

def handler(event, context):
    return {
        'string_result': _describe(event['string_secret_id']),
        'binary_result': _describe(event['binary_secret_id']),
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda correctly distinguishes SecretString vs SecretBinary payloads from GetSecretValue."""
    string_value = "plain-string-secret-value-42"
    binary_value = bytes([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]) + b"binary-payload"

    string_arn, string_id = _create_secret(ctx, string_secret=string_value)
    binary_arn, binary_id = _create_secret(ctx, binary_secret=binary_value)

    statements = [
        {
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": [string_arn, binary_arn],
        },
    ]
    _role_name, role_arn = _create_lambda_role(ctx, statements)
    fname = _create_function(ctx, role_arn, _LAMBDA_CODE)

    _, body = _invoke(
        ctx, fname, {"string_secret_id": string_id, "binary_secret_id": binary_id}
    )

    string_result = body["string_result"]
    binary_result = body["binary_result"]
    assert string_result["type"] == "string", (
        f"expected the SecretString secret to read back as type 'string', got {string_result!r}"
    )
    assert string_result["value"] == string_value, (
        f"expected string secret value {string_value!r}, got {string_result!r}"
    )
    assert binary_result["type"] == "binary", (
        f"expected the SecretBinary secret to read back as type 'binary', got {binary_result!r}"
    )
    decoded = base64.b64decode(binary_result["value_b64"])
    assert decoded == binary_value, (
        f"expected binary secret bytes {binary_value!r}, got {decoded!r}"
    )


def _zip_code(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_secret(
    ctx, string_secret: str | None = None, binary_secret: bytes | None = None
) -> tuple[str, str]:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-lam-secret-")
    kwargs: dict[str, Any] = {
        "Name": name,
        "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
    }
    if string_secret is not None:
        kwargs["SecretString"] = string_secret
    if binary_secret is not None:
        kwargs["SecretBinary"] = binary_secret
    resp = sm.create_secret(**kwargs)
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    )
    return resp["ARN"], name


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_name, role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(
    ctx,
    role_arn: str,
    code: str,
    handler: str = "index.handler",
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> str:
    lam = ctx.client("lambda")
    fname = ctx.unique_name("sim2real-lam-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fname,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": _zip_code(code)},
        Timeout=timeout,
        MemorySize=128,
        Publish=True,
        Tags={"sim2real-check": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    last_exc = None
    for _ in range(12):
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_exc = e
                time.sleep(3)
                continue
            raise
    else:
        raise last_exc  # type: ignore[misc]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fname))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fname)["State"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=90,
        interval_s=3,
    )
    return fname


def _invoke(ctx, fname: str, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fname,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    raw = resp["Payload"].read()
    body = json.loads(raw) if raw else {}
    assert "FunctionError" not in resp, (resp.get("FunctionError"), body)
    return resp, body


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
