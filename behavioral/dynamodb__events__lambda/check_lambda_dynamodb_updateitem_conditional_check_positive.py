"""lambda-dynamodb-updateitem-conditional-check-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-dynamodb-updateitem-conditional-check-positive"
GROUP = "data-format"
SERVICES = ["dynamodb", "events", "lambda"]

_HANDLER_SRC = """
import os
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb")
    pk = event["pk"]
    expected_version = event["expected_version"]
    try:
        ddb.update_item(
            TableName=table,
            Key={"pk": {"S": pk}},
            UpdateExpression="SET #s = :s, version = version + :one",
            ConditionExpression="version = :v",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": {"S": "DONE"},
                ":v": {"N": str(expected_version)},
                ":one": {"N": "1"},
            },
        )
        return {"ok": True}
    except ClientError as e:
        return {"ok": False, "code": e.response["Error"]["Code"]}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda's UpdateItem with a ConditionExpression against DynamoDB succeeds only when the
    condition matches, and a stale condition leaves the item unmodified."""
    dynamodb = ctx.client("dynamodb")
    table_name, table_arn = _create_table(
        ctx,
        [{"AttributeName": "pk", "KeyType": "HASH"}],
        [{"AttributeName": "pk", "AttributeType": "S"}],
    )
    role_arn = _create_role(
        ctx, [{"Effect": "Allow", "Action": ["dynamodb:UpdateItem"], "Resource": table_arn}]
    )
    fn_name, _ = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table_name})

    pk = ctx.unique_name("item-")
    dynamodb.put_item(
        TableName=table_name,
        Item={"pk": {"S": pk}, "status": {"S": "PENDING"}, "version": {"N": "1"}},
    )

    body1 = _invoke(ctx, fn_name, {"pk": pk, "expected_version": 1})
    assert body1["ok"] is True, (
        f"conditional update with the current version should succeed, got {body1!r}"
    )

    updated = dynamodb.get_item(TableName=table_name, Key={"pk": {"S": pk}})["Item"]
    assert updated["status"]["S"] == "DONE", (
        f"status after the guarded update is {updated['status']['S']!r}, expected 'DONE'"
    )
    assert updated["version"]["N"] == "2", (
        f"version after the guarded update is {updated['version']['N']!r}, expected '2'"
    )

    # Same expected_version is now stale (real version advanced to 2); condition must fail.
    body2 = _invoke(ctx, fn_name, {"pk": pk, "expected_version": 1})
    assert body2["ok"] is False, (
        f"conditional update with a stale version should be rejected, got {body2!r}"
    )
    assert body2["code"] == "ConditionalCheckFailedException", (
        f"stale-version update failed with {body2.get('code')!r}, expected "
        "'ConditionalCheckFailedException'"
    )

    unchanged = dynamodb.get_item(TableName=table_name, Key={"pk": {"S": pk}})["Item"]
    assert unchanged["status"]["S"] == "DONE", (
        f"a rejected conditional update mutated status to {unchanged['status']['S']!r}"
    )
    assert unchanged["version"]["N"] == "2", (
        f"a rejected conditional update mutated version to {unchanged['version']['N']!r}"
    )

    # Restore: the identical call, now carrying the current version, must succeed — this is what
    # proves the two rejections above came from the condition and not from a broken call.
    body3 = _invoke(ctx, fn_name, {"pk": pk, "expected_version": 2})
    assert body3["ok"] is True, (
        f"conditional update with the now-current version should succeed, got {body3!r}"
    )

    restored = dynamodb.get_item(TableName=table_name, Key={"pk": {"S": pk}})["Item"]
    assert restored["status"]["S"] == "DONE", (
        f"status after the restore update is {restored['status']['S']!r}, expected 'DONE'"
    )
    assert restored["version"]["N"] == "3", (
        f"version after the restore update is {restored['version']['N']!r}, expected '3'"
    )


def _lambda_zip(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _create_role(ctx, policy_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
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
    policy_name = ctx.unique_name("sim2real-behav-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(ctx, role_arn, src, env=None, timeout_s=90.0):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _lambda_zip(src)
    deadline = time.monotonic() + timeout_s
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": env or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
            continue
    if resp is None:
        raise AssertionError(f"could not create function (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return name, resp["FunctionArn"]


def _wait_active(ctx, name):
    lam = ctx.client("lambda")

    def probe():
        return lam.get_function(FunctionName=name)["Configuration"]["State"]

    state = _poll_until(probe, lambda s: s in ("Active", "Failed"), timeout_s=90.0, interval_s=3.0)
    if state != "Active":
        raise AssertionError(f"function did not become Active: {state}")


def _invoke(ctx, name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, InvocationType="RequestResponse", Payload=json.dumps(payload).encode()
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation error: {body}")
    return body


def _create_table(ctx, key_schema, attr_defs):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-tbl-")
    resp = ddb.create_table(
        TableName=name,
        KeySchema=key_schema,
        AttributeDefinitions=attr_defs,
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
