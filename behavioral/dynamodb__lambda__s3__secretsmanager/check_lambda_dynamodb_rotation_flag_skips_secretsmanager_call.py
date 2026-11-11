"""lambda-dynamodb-rotation-flag-skips-secretsmanager-call."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-dynamodb-rotation-flag-skips-secretsmanager-call"
GROUP = "shared-state"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]

_LAMBDA_CODE = """
import boto3, os

ddb = boto3.client('dynamodb')
sm = boto3.client('secretsmanager')

TABLE = os.environ['TABLE_NAME']
SECRET_ID = os.environ['SECRET_ID']

def handler(event, context):
    resp = ddb.get_item(TableName=TABLE, Key={'id': {'S': 'rotation-flag'}})
    item = resp.get('Item')
    flag = bool(item) and item.get('rotation_complete', {}).get('BOOL', False)
    if flag:
        return {'skipped': True}

    # record that we are about to make the (redundant, first-time-only) call
    ddb.update_item(
        TableName=TABLE,
        Key={'id': {'S': 'call-count'}},
        UpdateExpression='ADD #c :inc',
        ExpressionAttributeNames={'#c': 'count'},
        ExpressionAttributeValues={':inc': {'N': '1'}},
    )
    sm.get_secret_value(SecretId=SECRET_ID)
    ddb.put_item(
        TableName=TABLE,
        Item={'id': {'S': 'rotation-flag'}, 'rotation_complete': {'BOOL': True}},
    )
    return {'skipped': False}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda checks a rotation-complete flag in DynamoDB and skips the redundant
    Secrets Manager call once the flag is already set, observed via a call counter."""
    table = _create_table(ctx)
    secret_arn, secret_id = _create_secret(ctx, "top-secret-rotation-value")

    table_arn = _table_arn(ctx, table)
    statements = [
        {
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
            "Resource": table_arn,
        },
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
    ]
    _role_name, role_arn = _create_lambda_role(ctx, statements)
    fname = _create_function(
        ctx, role_arn, _LAMBDA_CODE, env={"TABLE_NAME": table, "SECRET_ID": secret_id}
    )

    ddb = ctx.client("dynamodb")

    _, body1 = _invoke(ctx, fname, {})
    assert body1["skipped"] is False, body1
    count_item = ddb.get_item(TableName=table, Key={"id": {"S": "call-count"}})["Item"]
    assert count_item["count"]["N"] == "1", count_item
    flag_item = ddb.get_item(TableName=table, Key={"id": {"S": "rotation-flag"}})["Item"]
    assert flag_item["rotation_complete"]["BOOL"] is True, flag_item

    _, body2 = _invoke(ctx, fname, {})
    assert body2["skipped"] is True, body2
    count_item_after = ddb.get_item(TableName=table, Key={"id": {"S": "call-count"}})["Item"]
    assert count_item_after["count"]["N"] == "1", count_item_after  # unchanged: no redundant call


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


def _create_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-lam-table-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
