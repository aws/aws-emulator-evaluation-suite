"""s3-notification-lambda-decrypts-object-with-secret-writes-dynamodb."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-lambda-decrypts-object-with-secret-writes-dynamodb"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_LAMBDA_CODE = """
import boto3, os, urllib.parse

s3 = boto3.client('s3')
sm = boto3.client('secretsmanager')
ddb = boto3.client('dynamodb')

SECRET_ID = os.environ['SECRET_ID']
TABLE_NAME = os.environ['TABLE_NAME']

def handler(event, context):
    processed = 0
    for record in event.get('Records', []):
        bucket = record['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(record['s3']['object']['key'])
        obj = s3.get_object(Bucket=bucket, Key=key)
        data = obj['Body'].read()
        secret_resp = sm.get_secret_value(SecretId=SECRET_ID)
        xor_key = secret_resp['SecretString']
        plain = bytes(b ^ ord(xor_key[i % len(xor_key)]) for i, b in enumerate(data))
        ddb.put_item(
            TableName=TABLE_NAME,
            Item={
                'object_key': {'S': key},
                'decrypted_content': {'S': plain.decode('utf-8', errors='replace')},
                'size': {'N': str(len(data))},
            },
        )
        processed += 1
    return {'processed': processed}
"""


def _xor_bytes(plaintext: bytes, key: str) -> bytes:
    return bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(plaintext))


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 ObjectCreated notification invokes Lambda, which fetches a decryption key
    from Secrets Manager, decrypts the object body, and writes metadata to DynamoDB."""
    xor_key = "my-xor-secret-key"
    plaintext = "hello-secret-payload-for-s3-notification"

    bucket = _create_bucket(ctx)
    table = _create_table(ctx)
    secret_arn, secret_id = _create_secret(ctx, xor_key)

    bucket_arn = f"arn:aws:s3:::{bucket}"
    table_arn = _table_arn(ctx, table)
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{bucket_arn}/*"},
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
        {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn},
    ]
    _role_name, role_arn = _create_lambda_role(ctx, statements)
    fname, function_arn = _create_function(
        ctx, role_arn, _LAMBDA_CODE, env={"SECRET_ID": secret_id, "TABLE_NAME": table}
    )
    _wire_s3_notification(ctx, bucket, fname, function_arn)

    key = "incoming/testfile.bin"
    encrypted = _xor_bytes(plaintext.encode("utf-8"), xor_key)
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=encrypted)

    ddb = ctx.client("dynamodb")
    item = _poll_until(
        lambda: ddb.get_item(TableName=table, Key={"object_key": {"S": key}}).get("Item"),
        lambda i: i is not None,
        timeout_s=90,
        interval_s=3,
    )
    assert item["decrypted_content"]["S"] == plaintext, (
        f"expected decrypted_content {plaintext!r}, got {item['decrypted_content']['S']!r}: {item}"
    )
    assert item["size"]["N"] == str(len(encrypted)), (
        f"expected size {len(encrypted)}, got {item['size']['N']!r}: {item}"
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


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-lam-s3-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
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


def _create_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-lam-table-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "object_key", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "object_key", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    return table


def _table_arn(ctx, table: str) -> str:
    ddb = ctx.client("dynamodb")
    return ddb.describe_table(TableName=table)["Table"]["TableArn"]


def _create_secret(ctx, secret_value: str) -> tuple[str, str]:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-lam-secret-")
    resp = sm.create_secret(
        Name=name,
        SecretString=secret_value,
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
) -> tuple[str, str]:
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
    for _ in range(15):
        try:
            create_resp = lam.create_function(**kwargs)
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
    return fname, create_resp["FunctionArn"]


def _wire_s3_notification(ctx, bucket: str, fname: str, function_arn: str) -> None:
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    lam.add_permission(
        FunctionName=fname,
        StatementId="AllowS3Invoke",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=f"arn:aws:s3:::{bucket}",
    )
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [
                {"LambdaFunctionArn": function_arn, "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
