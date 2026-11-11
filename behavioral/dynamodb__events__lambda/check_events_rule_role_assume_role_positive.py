"""events-rule-role-assume-role-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-rule-role-assume-role-positive"
GROUP = "iam-trust"
SERVICES = ["dynamodb", "events", "lambda"]

_HANDLER_DDB = """
import json
import os
import boto3

def handler(event, context):
    table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
    marker = event.get("detail", {}).get("marker", "unknown")
    table.put_item(Item={"pk": marker, "payload": json.dumps(event)})
    return {"status": "ok"}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda target granted invoke by an AddPermission statement (events.amazonaws.com, SourceArn = the rule's
    ARN) receives a matching event and writes its exact marker to DynamoDB.
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    events = ctx.client("events")

    table_name = ctx.unique_name("sim2real-evt-role-ddb-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)

    role_name = ctx.unique_name("sim2real-evt-role-lambda-role-")
    role_arn = _create_role(ctx, iam, role_name, "lambda.amazonaws.com")
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="write-ddb",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}],
            }
        ),
    )

    func_name = ctx.unique_name("sim2real-evt-role-fn-")
    resp = _create_function_with_retry(
        lam,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_lambda_code(_HANDLER_DDB)},
        Environment={"Variables": {"TABLE_NAME": table_name}},
        Timeout=15,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_fn_active(lam, func_name)
    func_arn = resp["FunctionArn"]

    rule_name = ctx.unique_name("sim2real-evt-role-rule-")
    pattern = {"source": ["sim2real.rulerole"], "detail-type": ["rule-role-positive"]}
    put_rule_resp = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = put_rule_resp["RuleArn"]

    stmt_id = ctx.unique_name("sim2real-stmt-")
    lam.add_permission(
        FunctionName=func_name,
        StatementId=stmt_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    policy = json.loads(lam.get_policy(FunctionName=func_name)["Policy"])
    stmt = next((s for s in policy["Statement"] if s["Sid"] == stmt_id), None)
    assert stmt is not None, f"statement {stmt_id} missing from policy: {policy}"
    assert stmt["Principal"]["Service"] == "events.amazonaws.com", stmt
    assert stmt["Condition"]["ArnLike"]["AWS:SourceArn"] == rule_arn, stmt

    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": func_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))

    marker = ctx.unique_name("marker-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.rulerole",
                "DetailType": "rule-role-positive",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )

    item = _poll_until(
        lambda: ddb.get_item(TableName=table_name, Key={"pk": {"S": marker}}).get("Item"),
        lambda i: i is not None,
        timeout_s=60.0,
        interval_s=2.0,
    )
    payload = json.loads(item["payload"]["S"])
    assert payload["detail"]["marker"] == marker, payload


def _trust_policy(principal_service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": principal_service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_role(ctx, iam, role_name: str, principal_service: str) -> str:
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_trust_policy(principal_service))
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        try:
            for pol in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            for pol in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _zip_lambda_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()


def _create_function_with_retry(lam, *, timeout_s: float = 90.0, interval_s: float = 3.0, **kwargs: Any):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever calling create_function"
    raise last_exc


def _wait_fn_active(lam, func_name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if lam.get_function(FunctionName=func_name)["Configuration"]["State"] == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active")


def _wait_table_active(ddb, table_name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if ddb.describe_table(TableName=table_name)["Table"]["TableStatus"] == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
