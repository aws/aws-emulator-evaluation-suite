"""lambda-secretsmanager-describe-secret-without-getvalue-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-secretsmanager-describe-secret-without-getvalue-negative"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_LAMBDA_CODE = """
import boto3
from botocore.exceptions import ClientError

sm = boto3.client('secretsmanager')

def handler(event, context):
    secret_id = event['secret_id']
    result = {
        'describe_ok': False, 'describe_name': None, 'describe_error': None,
        'get_ok': False, 'get_value': None, 'get_error': None,
    }
    try:
        d = sm.describe_secret(SecretId=secret_id)
        result['describe_ok'] = True
        result['describe_name'] = d['Name']
    except ClientError as e:
        result['describe_error'] = e.response['Error']['Code']
    try:
        g = sm.get_secret_value(SecretId=secret_id)
        result['get_ok'] = True
        result['get_value'] = g.get('SecretString')
    except ClientError as e:
        result['get_error'] = e.response['Error']['Code']
    return result
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role granted only secretsmanager:DescribeSecret can read metadata but is
    denied GetSecretValue; adding the permission unblocks the same call."""
    secret_value = "value-only-visible-with-getvalue-permission"
    secret_arn, secret_id = _create_secret(ctx, secret_value)

    statements = [
        {"Effect": "Allow", "Action": "secretsmanager:DescribeSecret", "Resource": secret_arn},
    ]
    role_name, role_arn = _create_lambda_role(ctx, statements)
    fname = _create_function(ctx, role_arn, _LAMBDA_CODE)

    _, denied_body = _invoke(ctx, fname, {"secret_id": secret_id})
    assert denied_body["describe_ok"] is True, denied_body
    assert denied_body["describe_name"] == secret_id, denied_body
    assert denied_body["get_ok"] is False, denied_body
    assert denied_body["get_error"] == "AccessDeniedException", denied_body
    assert denied_body["get_value"] is None, denied_body

    # Positive control: grant GetSecretValue on the same secret, same role, same call.
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="getvalue-fix",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": secret_arn,
                    }
                ],
            }
        ),
    )

    allowed_body = _poll_until(
        lambda: _invoke(ctx, fname, {"secret_id": secret_id})[1],
        lambda b: b["get_ok"] is True,
        timeout_s=60,
        interval_s=3,
    )
    assert allowed_body["get_value"] == secret_value, allowed_body
    assert allowed_body["describe_ok"] is True, allowed_body


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


def _create_secret(ctx, secret_value: str) -> tuple[str, str]:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-lam-secret-")
    resp = sm.create_secret(
        Name=name,
        SecretString=secret_value,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    last_exc = None
    for _ in range(15):
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
