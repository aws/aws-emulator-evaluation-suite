"""eventbridge-rule-lambda-missing-invoke-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-lambda-missing-invoke-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """On one rule, the target whose function grants events.amazonaws.com no invoke permission is never invoked
    while its sibling with the grant writes the event's marker; once granted the same permission, the first
    target writes the marker of the next event.
    """
    table_allowed = _create_ddb_table(ctx)
    table_denied = _create_ddb_table(ctx)
    role_arn = _create_lambda_role(ctx)

    fn_allowed = ctx.unique_name("sim2real-fn-allow-")
    arn_allowed = _create_lambda_function(ctx, fn_allowed, role_arn, table_allowed)
    fn_denied = ctx.unique_name("sim2real-fn-deny-")
    arn_denied = _create_lambda_function(ctx, fn_denied, role_arn, table_denied)

    rule_name = ctx.unique_name("sim2real-rule-")
    events = ctx.client("events")
    pattern = {"source": ["sim2real.test"], "detail-type": ["TestEvent"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    # Only fn_allowed gets an events.amazonaws.com invoke grant; fn_denied never does.
    _add_event_invoke_permission(ctx, fn_allowed, rule_arn, "sim2real-stmt")

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "target-allowed", "Arn": arn_allowed},
            {"Id": "target-denied", "Arn": arn_denied},
        ],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(
            Rule=rule_name, Ids=["target-allowed", "target-denied"]
        )
    )

    marker = ctx.unique_name("marker-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "TestEvent",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )

    ddb = ctx.client("dynamodb")
    item = _poll_until(
        lambda: ddb.get_item(
            TableName=table_allowed, Key={"id": {"S": marker}}, ConsistentRead=True
        ).get("Item"),
        lambda i: i is not None,
        timeout_s=90.0,
        interval_s=2.0,
        description="permitted target invoked (positive control)",
    )
    got_marker = json.loads(item["payload"]["S"])["detail"]["marker"]
    assert got_marker == marker, f"expected marker {marker!r} in positive-control item, got {got_marker!r}"

    _confirm_absent(
        lambda: ddb.get_item(
            TableName=table_denied, Key={"id": {"S": marker}}, ConsistentRead=True
        ).get("Item"),
        hold_s=20.0,
        interval_s=4.0,
        description="target lacking an invoke-permission grant was invoked anyway",
    )

    # Restore: grant fn_denied the same invoke permission fn_allowed always had, then demand
    # that the identical rule/target wiring, with the grant, actually delivers.
    _add_event_invoke_permission(ctx, fn_denied, rule_arn, "sim2real-stmt-restored")
    marker2 = ctx.unique_name("marker2-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "TestEvent",
                "Detail": json.dumps({"marker": marker2}),
            }
        ]
    )
    restored_item = _poll_until(
        lambda: ddb.get_item(
            TableName=table_denied, Key={"id": {"S": marker2}}, ConsistentRead=True
        ).get("Item"),
        lambda i: i is not None,
        timeout_s=90.0,
        interval_s=2.0,
        description="previously-denied target invoked after the invoke-permission grant was added",
    )
    restored_marker = json.loads(restored_item["payload"]["S"])["detail"]["marker"]
    assert restored_marker == marker2, (
        f"expected marker {marker2!r} in restored-target item, got {restored_marker!r}"
    )


_LAMBDA_CODE = '''
import json
import os
import boto3

TABLE_NAME = os.environ["TABLE_NAME"]

def handler(event, context):
    client = boto3.client("dynamodb")
    marker = None
    if isinstance(event, dict):
        marker = event.get("marker")
        if marker is None:
            detail = event.get("detail")
            if isinstance(detail, dict):
                marker = detail.get("marker")
    if marker is None:
        marker = "no-marker"
    client.put_item(
        TableName=TABLE_NAME,
        Item={
            "id": {"S": str(marker)},
            "payload": {"S": json.dumps(event)},
        },
    )
    return {"stored": str(marker)}
'''


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _confirm_absent(probe, *, hold_s=15.0, interval_s=3.0, description="effect"):
    """Poll continuously for hold_s seconds and assert the probe stays falsy
    throughout the whole window (not a single check at the end)."""
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        result = probe()
        if result:
            raise AssertionError(f"{description} unexpectedly became present: {result!r}")
        time.sleep(interval_s)


def _make_lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-ddb-write",
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-ddb-write")
    )
    return role_arn


def _create_lambda_function(ctx, function_name: str, role_arn: str, table_name: str) -> str:
    lam = ctx.client("lambda")
    zip_bytes = _make_lambda_zip(_LAMBDA_CODE)
    last_err = None
    deadline = time.monotonic() + 90.0
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"TABLE_NAME": table_name}},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=function_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {function_name} Active",
    )
    return resp["FunctionArn"]


def _create_ddb_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-tbl-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=2.0,
        description=f"table {table_name} ACTIVE",
    )
    return table_name


def _add_event_invoke_permission(ctx, function_name: str, rule_arn: str, statement_id: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(FunctionName=function_name, StatementId=statement_id)
    )


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
