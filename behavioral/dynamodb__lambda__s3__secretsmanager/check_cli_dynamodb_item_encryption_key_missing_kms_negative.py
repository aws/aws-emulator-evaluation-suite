"""cli-dynamodb-item-encryption-key-missing-kms-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-dynamodb-item-encryption-key-missing-kms-negative"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role reads the secret and writes DynamoDB but lacks kms:Decrypt on the secret's key gets
    AccessDeniedException and writes no item; after kms:Decrypt is granted on the same key, the same call
    writes the item with the secret-derived enc_key.
    """
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-cmk-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    secret_name = ctx.unique_name("sim2real-enc-secret-")
    enc_key_value = "enc-key-" + ctx.unique_name("")
    secret_arn = sm.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"encryption_key": enc_key_value}),
        KmsKeyId=key_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    table_name = ctx.unique_name("sim2real-enc-table-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ctx, table_name)

    item_pk = ctx.unique_name("item-")

    # Role can read the secret's ciphertext blob and write DynamoDB, but has no
    # kms:Decrypt grant on the CMK, so GetSecretValue cannot complete.
    role_arn = _create_lambda_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secret_arn},
            {
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                "Resource": f"arn:aws:dynamodb:{ctx.region}:*:table/{table_name}",
            },
        ],
    )

    handler_code = (
        "import boto3, os, json\n"
        "from botocore.exceptions import ClientError\n"
        "def handler(event, context):\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    ddb = boto3.client('dynamodb')\n"
        "    try:\n"
        "        val = sm.get_secret_value(SecretId=os.environ['SECRET_ID'])['SecretString']\n"
        "        cfg = json.loads(val)\n"
        "        ddb.put_item(TableName=os.environ['TABLE_NAME'], Item={\n"
        "            'pk': {'S': event['pk']},\n"
        "            'enc_key': {'S': cfg['encryption_key']},\n"
        "        })\n"
        "        return {'ok': True}\n"
        "    except ClientError as e:\n"
        "        return {'ok': False, 'code': e.response['Error']['Code']}\n"
    )
    fn_name = _create_function(
        ctx, role_arn, handler_code, env_vars={"SECRET_ID": secret_arn, "TABLE_NAME": table_name}
    )

    _, body = _invoke(ctx, fn_name, {"pk": item_pk})
    assert body["ok"] is False, f"expected the write to be blocked without kms:Decrypt, got {body}"
    assert body["code"] == "AccessDeniedException", body

    item = ddb.get_item(TableName=table_name, Key={"pk": {"S": item_pk}}).get("Item")
    assert item is None, f"item should not exist without kms:Decrypt, got {item}"

    # Positive control: grant kms:Decrypt on the same key and retry the identical call.
    policy_name = f"{fn_name}-kms-grant"
    iam_role_name = role_arn.split("/")[-1]
    iam.put_role_policy(
        RoleName=iam_role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kms:Decrypt",
                        "Resource": f"arn:aws:kms:{ctx.region}:*:key/{key_id}",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=iam_role_name, PolicyName=policy_name))

    # Bounded retry, not a flat sleep: IAM policy propagation has no fixed latency, so the
    # 40 s deadline below is what waits for it.
    deadline = time.monotonic() + 40.0
    body_after = None
    while time.monotonic() < deadline:
        _, body_after = _invoke(ctx, fn_name, {"pk": item_pk})
        if body_after.get("ok") is True:
            break
        time.sleep(3)
    assert body_after is not None and body_after["ok"] is True, body_after

    item_after = ddb.get_item(TableName=table_name, Key={"pk": {"S": item_pk}}).get("Item")
    assert item_after is not None and item_after["enc_key"]["S"] == enc_key_value, (
        f"expected item {item_pk!r} with enc_key={enc_key_value!r} after granting kms:Decrypt, got {item_after}"
    )


def _wait_table_active(ctx, table_name, timeout_s=60.0):
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _make_zip(handler_code: str, filename="index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements, role_name=None):
    iam = ctx.client("iam")
    role_name = role_name or ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if policy_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # No flat sleep here: role-assumption propagation is absorbed by _create_function's
    # bounded retry on InvalidParameterValueException below, not by waiting up front.
    return role_arn


def _create_function(ctx, role_arn, handler_code, handler="index.handler", env_vars=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(handler_code)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=False,
        Tags={"sim2real": CHECK},
    )
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    last_err = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return name


def _wait_for_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _invoke(ctx, name, payload=None):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, Payload=json.dumps(payload or {}).encode(), InvocationType="RequestResponse"
    )
    body = json.loads(resp["Payload"].read())
    return resp, body


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
