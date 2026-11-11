"""lambda-dynamodb-batchwriteitem-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-dynamodb-batchwriteitem-positive"
GROUP = "sdk-call"
SERVICES = ["dynamodb", "events", "lambda"]

_HANDLER_SRC = """
import os
import boto3

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb")
    ids = event["ids"]
    request_items = {
        table: [
            {"PutRequest": {"Item": {"pk": {"S": i}, "batch": {"BOOL": True}}}}
            for i in ids
        ]
    }
    resp = ddb.batch_write_item(RequestItems=request_items)
    unprocessed = resp.get("UnprocessedItems", {})
    while unprocessed:
        resp = ddb.batch_write_item(RequestItems=unprocessed)
        unprocessed = resp.get("UnprocessedItems", {})
    return {"count": len(ids)}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda BatchWriteItem call writes multiple items observable in DynamoDB."""
    dynamodb = ctx.client("dynamodb")
    table_name, table_arn = _create_table(
        ctx,
        [{"AttributeName": "pk", "KeyType": "HASH"}],
        [{"AttributeName": "pk", "AttributeType": "S"}],
    )
    role_arn = _create_role(
        ctx, [{"Effect": "Allow", "Action": ["dynamodb:BatchWriteItem"], "Resource": table_arn}]
    )
    fn_name, _ = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table_name})

    ids = [ctx.unique_name(f"batch-{i}-") for i in range(5)]
    body = _invoke(ctx, fn_name, {"ids": ids})
    assert body["count"] == len(ids), f"lambda reported writing {body['count']} items, expected {len(ids)}"

    resp = dynamodb.batch_get_item(RequestItems={table_name: {"Keys": [{"pk": {"S": i}} for i in ids]}})
    returned = {item["pk"]["S"]: item for item in resp["Responses"][table_name]}
    assert set(returned.keys()) == set(ids), (
        f"table has keys {sorted(returned.keys())}, expected exactly {sorted(ids)}"
    )
    for item in returned.values():
        assert item["batch"]["BOOL"] is True, f"item {item['pk']['S']!r} has batch={item.get('batch')}, expected BOOL true"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
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
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
