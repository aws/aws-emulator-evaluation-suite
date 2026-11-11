"""eventbridge-triggered-lambda-reads-dynamodb-item-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "eventbridge-triggered-lambda-reads-dynamodb-item-positive"
GROUP = "sdk-call"
SERVICES = ["dynamodb", "events", "lambda"]

_HANDLER_SRC = """
import os
import boto3

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb")
    detail = event.get("detail", {})
    src_id = detail["src_id"]
    dst_id = detail["dst_id"]
    resp = ddb.get_item(TableName=table, Key={"pk": {"S": src_id}})
    item = resp.get("Item", {})
    val = item.get("value", {}).get("S", "MISSING")
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": dst_id}, "value": {"S": val}, "read_ok": {"BOOL": True}},
    )
    return {"status": "ok"}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda invoked by an EventBridge event reads an existing DynamoDB item via boto3 GetItem."""
    dynamodb = ctx.client("dynamodb")
    table_name, table_arn = _create_table(
        ctx,
        [{"AttributeName": "pk", "KeyType": "HASH"}],
        [{"AttributeName": "pk", "AttributeType": "S"}],
    )
    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem"], "Resource": table_arn}],
    )
    fn_name, fn_arn = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table_name})
    pattern = {"source": ["sim2real.behav.read"], "detail-type": ["ItemRead"]}
    _create_rule_with_lambda_target(ctx, pattern, fn_name, fn_arn)

    src_id = ctx.unique_name("seed-")
    dst_id = ctx.unique_name("result-")
    seed_value = "seed-value-xyz"
    dynamodb.put_item(TableName=table_name, Item={"pk": {"S": src_id}, "value": {"S": seed_value}})

    _put_event(ctx, "sim2real.behav.read", "ItemRead", {"src_id": src_id, "dst_id": dst_id})

    def probe():
        resp = dynamodb.get_item(TableName=table_name, Key={"pk": {"S": dst_id}})
        return resp.get("Item")

    item = _poll_until(probe, lambda i: i is not None, timeout_s=60.0, interval_s=3.0)
    assert item["value"]["S"] == seed_value, (
        f"expected propagated value {seed_value!r}, got {item['value']['S']!r}"
    )
    assert item["read_ok"]["BOOL"] is True, (
        f"expected read_ok True (Lambda's GetItem must have succeeded), got {item['read_ok']['BOOL']!r}"
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


def _create_rule_with_lambda_target(ctx, event_pattern, function_name, function_arn):
    events_c = ctx.client("events")
    lam = ctx.client("lambda")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    resp = events_c.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    rule_arn = resp["RuleArn"]
    ctx.on_cleanup(lambda: events_c.delete_rule(Name=rule_name))
    statement_id = ctx.unique_name("sim2real-behav-perm-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=function_name, StatementId=statement_id))
    events_c.put_targets(Rule=rule_name, Targets=[{"Id": "target-1", "Arn": function_arn}])
    ctx.on_cleanup(lambda: events_c.remove_targets(Rule=rule_name, Ids=["target-1"]))
    return rule_arn


def _put_event(ctx, source, detail_type, detail):
    events_c = ctx.client("events")
    resp = events_c.put_events(
        Entries=[{"Source": source, "DetailType": detail_type, "Detail": json.dumps(detail)}]
    )
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_events failed: {resp}")


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
