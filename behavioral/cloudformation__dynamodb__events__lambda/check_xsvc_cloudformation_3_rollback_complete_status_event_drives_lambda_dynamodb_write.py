"""xsvc-cloudformation-3-rollback-complete-status-event-drives-lambda-dynamodb-write."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudformation-3-rollback-complete-status-event-drives-lambda-dynamodb-write"
GROUP = "deploy-eventing"
SERVICES = ["cloudformation", "dynamodb", "events", "lambda"]

STACK_TIMEOUT_S = 240.0
DELIVERY_TIMEOUT_S = 300.0

# The parameter's value must be all digits; "abc" is accepted by CreateStack and refused by SSM
# when the resource is created, so the stack fails on the server side and rolls back.
_TEMPLATE = json.dumps(
    {
        "Parameters": {"V": {"Type": "String"}},
        "Resources": {
            "P": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Type": "String", "Value": {"Ref": "V"}, "AllowedPattern": "^[0-9]+$"},
            }
        },
    }
)

_HANDLER = '''
import os
import boto3

_ddb = boto3.client("dynamodb")


def handler(event, context):
    detail = event.get("detail") or {}
    status = detail.get("status-details") or {}
    _ddb.put_item(
        TableName=os.environ["TABLE"],
        Item={
            "pk": {"S": detail["stack-id"]},
            "status": {"S": status.get("status") or "-"},
            "reason": {"S": status.get("status-reason") or "-"},
            "event_id": {"S": event["id"]},
            "detail_type": {"S": event["detail-type"]},
            "source": {"S": event["source"]},
        },
    )
    return {"written": detail["stack-id"]}
'''


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:eventing",
    "concern:e2e",
    "plane:control",
)
def run(ctx) -> None:
    """A stack that rolls back emits a ROLLBACK_COMPLETE Stack Status Change event; a rule on that
    status invokes a Lambda that writes the event into DynamoDB, read back at the far end. A sibling
    stack that reaches CREATE_COMPLETE under the same rule must write nothing.
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    ident = ctx.client("sts").get_caller_identity()
    partition = ident["Arn"].split(":")[1]

    prefix = ctx.unique_name("sim2real-xsvc-cfn3-rb-")
    chain = _build_chain(ctx, ddb, events, lam, ident["Account"], partition, prefix, ["ROLLBACK_COMPLETE"])
    table = chain["table"]

    stack_tags = [{"Key": "sim2real-check", "Value": CHECK}]
    ok_id = cfn.create_stack(
        StackName=f"{prefix}-ok", TemplateBody=_TEMPLATE, Parameters=_v("123"), Tags=stack_tags
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=ok_id))
    status = _poll_status(cfn, ok_id, why="CREATE_COMPLETE stack")
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"

    bad_id = cfn.create_stack(
        StackName=f"{prefix}-bad", TemplateBody=_TEMPLATE, Parameters=_v("abc"), Tags=stack_tags
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=bad_id))
    status = _poll_status(cfn, bad_id, why="rolling-back stack")
    assert status == "ROLLBACK_COMPLETE", f"subject stack: expected ROLLBACK_COMPLETE, got {status!r}"

    started = time.monotonic()
    item = _wait_item(ddb, table, bad_id, why="the ROLLBACK_COMPLETE stack's write")
    latency_s = time.monotonic() - started
    assert item["status"]["S"] == "ROLLBACK_COMPLETE", f"written status: got {item['status']['S']!r}"
    assert item["detail_type"]["S"] == "CloudFormation Stack Status Change", (
        f"written detail-type: got {item['detail_type']['S']!r}"
    )
    assert item["source"]["S"] == "aws.cloudformation", f"written source: got {item['source']['S']!r}"
    assert item["event_id"]["S"] and item["event_id"]["S"] != "-", f"written event id: got {item['event_id']!r}"

    # The ROLLBACK_COMPLETE write is the barrier: the control stack's CREATE_COMPLETE event was
    # emitted before the subject was even created, on the same bus, under the same rule.
    _settle(seconds=max(2.0 * latency_s, 20.0))
    stray = ddb.get_item(TableName=table, Key={"pk": {"S": ok_id}}, ConsistentRead=True).get("Item")
    assert stray is None, (
        f"a CREATE_COMPLETE stack must not match a ROLLBACK_COMPLETE rule; it wrote {stray!r}"
    )
    keys = _all_keys(ddb, table)
    assert keys == {bad_id}, f"the table must hold exactly the rolled-back stack's row; got {sorted(keys)!r}"


def _v(value: str) -> list[dict]:
    return [{"ParameterKey": "V", "ParameterValue": value}]


def _zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _pattern(account: str, region: str, partition: str, prefix: str, statuses: list[str]) -> str:
    return json.dumps(
        {
            "source": ["aws.cloudformation"],
            "detail-type": ["CloudFormation Stack Status Change"],
            "detail": {
                "stack-id": [{"prefix": f"arn:{partition}:cloudformation:{region}:{account}:stack/{prefix}-"}],
                "status-details": {"status": statuses},
            },
        }
    )


def _build_chain(ctx, ddb, events, lam, account, partition, prefix, statuses) -> dict:
    """Table <- Lambda (PutItem only, no log permissions so no log group) <- rule on the default bus."""
    iam = ctx.client("iam")
    table = ctx.unique_name("sim2real-xsvc-cfn3-tbl-")
    table_arn = ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    role = ctx.unique_name("sim2real-xsvc-cfn3-role-")
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.put_role_policy(
        RoleName=role,
        PolicyName="put-item",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName="put-item"))

    fn = ctx.unique_name("sim2real-xsvc-cfn3-fn-")
    fn_arn = None
    deadline = time.monotonic() + 90.0
    while fn_arn is None:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip(_HANDLER)},
                Timeout=30,
                Environment={"Variables": {"TABLE": table}},
                Tags={"sim2real-check": CHECK},
            )["FunctionArn"]
        except ClientError as exc:
            # IAM propagation: the new role is not yet assumable by Lambda.
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    # First use of the role's permission: a synchronous warm-up write, retried until the inline
    # policy is effective, so the asynchronous EventBridge invoke cannot hit IAM propagation.
    warm_key = f"warm-{fn}"
    warm_event = {
        "id": "warm-up",
        "detail-type": "warm-up",
        "source": "sim2real",
        "detail": {"stack-id": warm_key, "status-details": {"status": "WARM"}},
    }
    deadline = time.monotonic() + 120.0
    while True:
        out = lam.invoke(FunctionName=fn, Payload=json.dumps(warm_event).encode())
        body = out["Payload"].read().decode()
        if "FunctionError" not in out:
            break
        assert "AccessDenied" in body and time.monotonic() < deadline, f"warm-up invoke failed: {body[:400]!r}"
        time.sleep(5.0)
    ddb.delete_item(TableName=table, Key={"pk": {"S": warm_key}})

    rule = ctx.unique_name("sim2real-xsvc-cfn3-rule-")
    rule_arn = events.put_rule(
        Name=rule,
        EventPattern=_pattern(account, ctx.region, partition, prefix, statuses),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule))
    lam.add_permission(
        FunctionName=fn,
        StatementId="events-invoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(Rule=rule, Targets=[{"Id": "fn", "Arn": fn_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["fn"]))
    return {"table": table, "rule": rule, "fn": fn}


def _poll_status(cfn, stack_id: str, *, why: str) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not last.endswith("_IN_PROGRESS"):
            return last
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_id!r} still {last!r} after {STACK_TIMEOUT_S}s [{why}]")


def _wait_item(ddb, table: str, key: str, *, why: str, timeout_s: float = DELIVERY_TIMEOUT_S) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        item = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
        if item is not None:
            return item
        time.sleep(3.0)
    raise AssertionError(f"no item for {key!r} in {table!r} within {timeout_s}s [{why}]")


def _settle(*, seconds: float) -> None:
    """Hold after the differential barrier has already been observed (never a stand-in for it)."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        time.sleep(min(2.0, max(0.0, end - time.monotonic())))


def _all_keys(ddb, table: str) -> set[str]:
    keys: set[str] = set()
    for page in ddb.get_paginator("scan").paginate(TableName=table, ConsistentRead=True):
        keys.update(item["pk"]["S"] for item in page["Items"])
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
