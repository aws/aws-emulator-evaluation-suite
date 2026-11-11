"""lambda-fetches-secret-then-puts-s3-object-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-fetches-secret-then-puts-s3-object-positive"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_LAMBDA_CODE = """
import boto3, os, json

sm = boto3.client('secretsmanager')
s3 = boto3.client('s3')

BUCKET = os.environ['BUCKET_NAME']
SECRET_ID = os.environ['SECRET_ID']

def handler(event, context):
    resp = sm.get_secret_value(SecretId=SECRET_ID)
    config = json.loads(resp['SecretString'])
    key = config['key_prefix'] + '/output.txt'
    body = b'hello-from-lambda-secret-config'
    s3.put_object(Bucket=BUCKET, Key=key, Body=body)
    return {'key': key}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda fetches a naming-config secret and uses it to build the S3 key it writes."""
    key_prefix = ctx.unique_name("secret-cfg-")
    bucket = _create_bucket(ctx)
    secret_arn, secret_id = _create_secret(ctx, json.dumps({"key_prefix": key_prefix}))
    bucket_arn = f"arn:aws:s3:::{bucket}"
    statements = [
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"{bucket_arn}/*"},
    ]
    _role_name, role_arn = _create_lambda_role(ctx, statements)
    fname = _create_function(
        ctx,
        role_arn,
        _LAMBDA_CODE,
        env={"BUCKET_NAME": bucket, "SECRET_ID": secret_id},
    )

    expected_key = f"{key_prefix}/output.txt"
    _, body = _invoke(ctx, fname, {})
    assert body.get("key") == expected_key, (expected_key, body)

    s3 = ctx.client("s3")
    obj = s3.get_object(Bucket=bucket, Key=expected_key)
    content = obj["Body"].read()
    assert content == b"hello-from-lambda-secret-config", content


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


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-lam-s3-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_secret(ctx, secret_string: str) -> tuple[str, str]:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-lam-secret-")
    resp = sm.create_secret(
        Name=name,
        SecretString=secret_string,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
