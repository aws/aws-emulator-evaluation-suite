"""lambda-dynamodb-query-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-dynamodb-query-missing-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]

_HANDLER_SRC = """
import os
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb")
    action = event["action"]
    pk = event["pk"]
    if action == "get":
        try:
            resp = ddb.get_item(TableName=table, Key={"pk": {"S": pk}, "sk": {"S": event["sk"]}})
            return {"ok": True, "item_present": "Item" in resp}
        except ClientError as e:
            return {"ok": False, "code": e.response["Error"]["Code"]}
    elif action == "query":
        try:
            resp = ddb.query(
                TableName=table,
                KeyConditionExpression="pk = :pk",
                ExpressionAttributeValues={":pk": {"S": pk}},
            )
            return {"ok": True, "count": resp.get("Count", 0)}
        except ClientError as e:
            return {"ok": False, "code": e.response["Error"]["Code"]}
    return {"ok": False, "code": "UnknownAction"}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role that lacks dynamodb:Query cannot query the table -- the call fails with
    AccessDeniedException and leaks no item data, while the same role's permitted GetItem call
    (positive control) still succeeds."""
    dynamodb = ctx.client("dynamodb")
    table_name, table_arn = _create_table(
        ctx,
        [
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        [
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
    )
    # Deliberately omit dynamodb:Query from the role's policy.
    role_arn, role_name, policy_name = _create_role(
        ctx, [{"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": table_arn}]
    )
    fn_name, _ = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table_name})

    pk = ctx.unique_name("query-pk-")
    dynamodb.put_item(TableName=table_name, Item={"pk": {"S": pk}, "sk": {"S": "a"}})
    dynamodb.put_item(TableName=table_name, Item={"pk": {"S": pk}, "sk": {"S": "b"}})

    # Positive control: the permitted action succeeds on this same role/function.
    get_body = _invoke(ctx, fn_name, {"action": "get", "pk": pk, "sk": "a"})
    assert get_body["ok"] is True, f"permitted GetItem must succeed on this role; got {get_body!r}"
    assert get_body["item_present"] is True, (
        f"the seeded item must be visible to the permitted GetItem; got {get_body!r}"
    )

    # Negative: the unpermitted action is denied and no item data is returned/leaked.
    query_body = _invoke(ctx, fn_name, {"action": "query", "pk": pk})
    assert query_body["ok"] is False, f"expected denial for an unpermitted Query; got {query_body!r}"
    assert query_body["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for a role lacking dynamodb:Query; got {query_body!r}"
    )
    assert "count" not in query_body, f"a denied Query must leak no item count; got {query_body!r}"

    # Restore: grant the missing permission on the same role and re-issue the identical call --
    # it must now succeed, proving the earlier denial was the policy's doing, not broken wiring.
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["dynamodb:GetItem", "dynamodb:Query"],
                        "Resource": table_arn,
                    }
                ],
            }
        ),
    )
    restored_body = _poll_until(
        lambda: _invoke(ctx, fn_name, {"action": "query", "pk": pk}),
        lambda body: body.get("ok") is True,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert restored_body["ok"] is True, (
        f"granting dynamodb:Query on the same role must let the identical query call succeed "
        f"once IAM policy propagation completes; got {restored_body!r}"
    )
    assert restored_body["count"] == 2, (
        f"the restored query must see both items written under pk={pk!r}; "
        f"got count={restored_body.get('count')!r}"
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-behav-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn, role_name, policy_name


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
