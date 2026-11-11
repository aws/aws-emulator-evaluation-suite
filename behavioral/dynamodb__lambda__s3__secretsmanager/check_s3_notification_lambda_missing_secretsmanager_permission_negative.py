"""s3-notification-lambda-missing-secretsmanager-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-notification-lambda-missing-secretsmanager-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_LAMBDA_CODE = """
import boto3, json, os, urllib.parse
from botocore.exceptions import ClientError

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
        try:
            secret_resp = sm.get_secret_value(SecretId=SECRET_ID)
        except ClientError as e:
            # Independent side-channel: an async S3->Lambda invocation has no caller-visible
            # response, so the specific denial code is surfaced via an S3 marker object rather
            # than inferred from the absence of the DynamoDB write.
            marker = {'code': e.response['Error']['Code'], 'message': e.response['Error'].get('Message')}
            s3.put_object(Bucket=bucket, Key='errors/' + key + '.err', Body=json.dumps(marker).encode())
            continue
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


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """The decrypt-and-store pipeline halts before the DynamoDB write when the Lambda
    role lacks secretsmanager:GetSecretValue; granting the permission unblocks it."""
    xor_key = "my-xor-secret-key"
    plaintext_a = "object-a-should-never-be-decrypted"
    plaintext_b = "object-b-should-be-decrypted-fine"

    bucket = _create_bucket(ctx)
    table = _create_table(ctx)
    secret_arn, secret_id = _create_secret(ctx, xor_key)

    bucket_arn = f"arn:aws:s3:::{bucket}"
    table_arn = _table_arn(ctx, table)
    # Deliberately missing: secretsmanager:GetSecretValue. s3:PutObject is granted so the
    # function can write its own error marker (the specific-denial side channel) even while
    # secretsmanager access is denied.
    statements = [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": f"{bucket_arn}/*"},
        {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn},
    ]
    role_name, role_arn = _create_lambda_role(ctx, statements)
    fname, function_arn = _create_function(
        ctx, role_arn, _LAMBDA_CODE, env={"SECRET_ID": secret_id, "TABLE_NAME": table}
    )
    # Disable Lambda's automatic async-invoke retries: S3 notifications invoke Lambda
    # asynchronously, and a failed invocation is retried (with a delay of a minute or
    # more) by default. Without disabling retries, granting the missing permission
    # later in this check could let a *retry* of the object-a invocation succeed,
    # which would falsely look like the pipeline "worked" for object-a. Disabling
    # retries makes the negative assertion deterministic: object-a's one and only
    # invocation attempt happens while the permission is still missing.
    ctx.client("lambda").put_function_event_invoke_config(
        FunctionName=fname, MaximumRetryAttempts=0
    )
    _wire_s3_notification(ctx, bucket, fname, function_arn)

    ddb = ctx.client("dynamodb")

    key_a = "incoming/object-a.bin"
    encrypted_a = _xor_bytes(plaintext_a.encode("utf-8"), xor_key)
    s3_client = ctx.client("s3")
    s3_client.put_object(Bucket=bucket, Key=key_a, Body=encrypted_a)

    # The specific refusal, on an independent side channel: the invocation is async (an S3
    # event), so there is no caller-visible response to inspect directly. The function catches
    # the ClientError itself and writes the code to a marker object, which we read back.
    marker_key_a = f"errors/{key_a}.err"
    marker_body = _poll_until(
        lambda: _try_get_object(ctx, bucket, marker_key_a),
        lambda b: b is not None,
        timeout_s=30,
        interval_s=2,
    )
    marker = json.loads(marker_body)
    assert marker["code"] == "AccessDeniedException", (
        f"expected an AccessDeniedException marker for the missing secretsmanager permission, "
        f"got {marker!r}"
    )
    _, partition, _, _, account, _ = function_arn.split(":", 5)
    expected_message = (
        f"User: arn:{partition}:sts::{account}:assumed-role/{role_name}/{fname} is not authorized "
        f"to perform: secretsmanager:GetSecretValue on resource: {secret_id} because no "
        "identity-based policy allows the secretsmanager:GetSecretValue action"
    )
    assert marker["message"] == expected_message, (
        f"GetSecretValue denial message: {marker['message']!r}, expected {expected_message!r}"
    )

    # Repeatedly confirm absence over a generous window: the pipeline must never reach
    # the DynamoDB write because GetSecretValue is denied every time it is attempted.
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline:
        item = ddb.get_item(TableName=table, Key={"object_key": {"S": key_a}}).get("Item")
        assert item is None, f"item written despite missing secretsmanager permission: {item}"
        time.sleep(4)

    # Positive control: grant the missing permission, then a new upload completes the pipeline.
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="secrets-fix",
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

    key_b = "incoming/object-b.bin"
    encrypted_b = _xor_bytes(plaintext_b.encode("utf-8"), xor_key)

    # IAM policy grants are not instantly consistent, and we disabled Lambda's async
    # retries above (to keep the object-a negative assertion deterministic), so a
    # single upload could race the freshly-granted secretsmanager permission and be
    # denied before it propagates. Re-issue the upload (each is a fresh S3 event ->
    # fresh Lambda invocation attempt) until the permission has propagated and the
    # pipeline completes.
    item_b = None
    attempts_deadline = time.monotonic() + 90.0
    next_upload = 0.0
    while time.monotonic() < attempts_deadline:
        now = time.monotonic()
        if now >= next_upload:
            s3_client.put_object(Bucket=bucket, Key=key_b, Body=encrypted_b)
            next_upload = now + 15.0
        item_b = ddb.get_item(TableName=table, Key={"object_key": {"S": key_b}}).get("Item")
        if item_b is not None:
            break
        time.sleep(3)
    assert item_b is not None, "object-b was never written even after granting the permission"
    assert item_b["decrypted_content"]["S"] == plaintext_b, item_b

    # Re-confirm object A was still never written, even after the permission fix.
    item_a_final = ddb.get_item(TableName=table, Key={"object_key": {"S": key_a}}).get("Item")
    assert item_a_final is None, item_a_final


def _xor_bytes(plaintext: bytes, key: str) -> bytes:
    return bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(plaintext))


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


def _try_get_object(ctx, bucket: str, key: str) -> bytes | None:
    s3 = ctx.client("s3")
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return None
        raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-lam-s3-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 rejects an explicit LocationConstraint; every other region requires one.
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
    # Only the incoming/ inputs trigger the function, so its own errors/ markers in the same
    # bucket do not invoke it again (no recursive S3 -> Lambda loop).
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [
                {
                    "LambdaFunctionArn": function_arn,
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "incoming/"}]}},
                }
            ]
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
