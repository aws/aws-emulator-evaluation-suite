"""lambda-dynamodb-deleteitem-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-dynamodb-deleteitem-missing-permission-negative"
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
            resp = ddb.get_item(TableName=table, Key={"pk": {"S": pk}})
            return {"ok": True, "item_present": "Item" in resp}
        except ClientError as e:
            return {"ok": False, "code": e.response["Error"]["Code"]}
    elif action == "delete":
        try:
            ddb.delete_item(TableName=table, Key={"pk": {"S": pk}})
            return {"ok": True}
        except ClientError as e:
            return {"ok": False, "code": e.response["Error"]["Code"]}
    return {"ok": False, "code": "UnknownAction"}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role lacks dynamodb:DeleteItem gets AccessDeniedException and the item stays while its
    permitted GetItem succeeds; after DeleteItem is granted on the same role, the same delete removes the item.
    """
    dynamodb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    table_name, table_arn = _create_table(
        ctx,
        [{"AttributeName": "pk", "KeyType": "HASH"}],
        [{"AttributeName": "pk", "AttributeType": "S"}],
    )
    # Deliberately omit dynamodb:DeleteItem from the role's policy.
    role_arn, role_name = _create_role(
        ctx, [{"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": table_arn}]
    )
    fn_name, _ = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table_name})

    pk = ctx.unique_name("to-delete-")
    dynamodb.put_item(TableName=table_name, Item={"pk": {"S": pk}, "marker": {"S": "seed"}})

    # Positive control: the permitted action succeeds on this same role/function.
    get_body = _invoke(ctx, fn_name, {"action": "get", "pk": pk})
    assert get_body["ok"] is True, f"expected the permitted GetItem call to succeed, got {get_body!r}"
    assert get_body["item_present"] is True, (
        f"expected the seeded item to be visible via GetItem, got {get_body!r}"
    )

    # Negative: the unpermitted action is denied.
    del_body = _invoke(ctx, fn_name, {"action": "delete", "pk": pk})
    assert del_body["ok"] is False, (
        f"expected the unpermitted DeleteItem call to be denied, got {del_body!r}"
    )
    assert del_body["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for the unpermitted DeleteItem, got {del_body!r}"
    )

    # Effect absent: the item was not deleted.
    still_there = dynamodb.get_item(TableName=table_name, Key={"pk": {"S": pk}})
    assert "Item" in still_there, "expected the item to still exist after the denied delete"
    assert still_there["Item"]["marker"]["S"] == "seed", (
        f"expected the untouched seed marker, got {still_there['Item']!r}"
    )

    # Restore: grant dynamodb:DeleteItem on the SAME role and require the IDENTICAL call to then
    # succeed. IAM policy attachment propagates asynchronously, so poll rather than a single retry.
    restore_policy_name = ctx.unique_name("sim2real-behav-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["dynamodb:DeleteItem"], "Resource": table_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=restore_policy_name))

    restored = _poll_until(
        lambda: _invoke(ctx, fn_name, {"action": "delete", "pk": pk}),
        lambda body: body["ok"] is True,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert restored["ok"] is True, (
        f"expected the identical delete call to succeed once dynamodb:DeleteItem is granted on the "
        f"same role, got {restored!r}"
    )

    after_restore = dynamodb.get_item(TableName=table_name, Key={"pk": {"S": pk}})
    assert "Item" not in after_restore, (
        f"expected the item to be gone once the restored DeleteItem call succeeded, got {after_restore!r}"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    return role_arn, role_name


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
                Tags={"sim2real:managed": "true"},
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
