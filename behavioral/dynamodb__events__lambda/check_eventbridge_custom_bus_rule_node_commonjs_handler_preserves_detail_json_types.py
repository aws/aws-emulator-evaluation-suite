"""eventbridge-custom-bus-rule-node-commonjs-handler-preserves-detail-json-types."""
from __future__ import annotations

import json
import re
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-custom-bus-rule-node-commonjs-handler-preserves-detail-json-types"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "events", "lambda"]

_TAGS = {"sim2real:managed": "true"}

_HANDLER_JS = r"""
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");
const ddb = new DynamoDBClient({});
const TABLE = process.env.REC_TABLE;

exports.handler = async (event) => {
  await ddb.send(new PutItemCommand({
    TableName: TABLE,
    Item: {
      pk: { S: event.id },
      raw: { S: JSON.stringify(event) },
    },
  }));
};
"""


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _scan_all(ddb, table: str) -> list[dict]:
    items: list[dict] = []
    kwargs: dict = {"TableName": table}
    while True:
        page = ddb.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule on a custom event bus invokes a Node.js CommonJS handler whose
    event.detail preserves the published JSON's exact types -- numbers, booleans, null, nested
    arrays and unicode text survive the Node.js runtime's own JSON round trip unchanged.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-event-bus.html
    """
    ddb = ctx.client("dynamodb")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    rec_table = ctx.unique_name("sim2real-ebcbus-rec-")
    ddb.create_table(
        TableName=rec_table, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=rec_table),
                             "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=rec_table,
                                        WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    rec_arn = ddb.describe_table(TableName=rec_table)["Table"]["TableArn"]

    bus_name = ctx.unique_name("sim2real-ebcbus-bus-")
    events.create_event_bus(Name=bus_name, Tags=[
        {"Key": k, "Value": v} for k, v in _TAGS.items()])
    ctx.on_cleanup(_teardown(lambda: events.delete_event_bus(Name=bus_name),
                             "ResourceNotFoundException"))

    role_name = ctx.unique_name("sim2real-ebcbus-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                                Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    basic = f"arn:{role_arn.split(':')[1]}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic),
                             "NoSuchEntity"))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": rec_arn},
        ]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"),
                             "NoSuchEntity"))

    fn_name = ctx.unique_name("sim2real-ebcbus-fn-")
    group = f"/aws/lambda/{fn_name}"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.js", _HANDLER_JS)
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while True:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn_name, Runtime="nodejs24.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": zip_buf.getvalue()},
                Timeout=10, MemorySize=256,
                Environment={"Variables": {"REC_TABLE": rec_table}},
                Tags=_TAGS,
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or \
                    "assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            if _budget_spent(ctx):
                raise TimeoutError(
                    "CreateFunction role propagation: the run budget ended first; not graded"
                ) from exc
            time.sleep(3)

    def _reap_log_group() -> None:
        logs = ctx.client("logs")
        deadline2 = time.monotonic() + _budget_s(ctx, 45)
        absent = 0
        while absent < 3:
            groups = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if any(g["logGroupName"] == group for g in groups):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < 3:
                if time.monotonic() >= deadline2:
                    if _budget_spent(ctx):
                        raise TimeoutError(
                            "reaping log group: the run budget ended first; not graded"
                        )
                    raise AssertionError("lambda log group never settled absent")
                time.sleep(2)

    ctx.on_cleanup(_reap_log_group)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    rule_name = ctx.unique_name("sim2real-ebcbus-rule-")
    rule_arn = events.put_rule(
        Name=rule_name, EventBusName=bus_name,
        EventPattern=json.dumps({"source": ["check.ebcbus"], "detail-type": ["TypePreserve"]}),
    )["RuleArn"]
    ctx.on_cleanup(_teardown(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name),
                             "ResourceNotFoundException"))
    lam.add_permission(FunctionName=fn_name, StatementId="events-invoke",
                       Action="lambda:InvokeFunction", Principal="events.amazonaws.com",
                       SourceArn=rule_arn)
    events.put_targets(Rule=rule_name, EventBusName=bus_name,
                       Targets=[{"Id": "lambda-target", "Arn": fn_arn}])
    ctx.on_cleanup(_teardown(
        lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["lambda-target"]),
        "ResourceNotFoundException"))

    tag = ctx.unique_name("sim2real-ebcbus-tag")
    detail = {
        "txt": tag, "num": 42, "flt": 3.5, "flag": True, "nil": None,
        "nested": {"arr": [1, 2, 3], "s": "héllo-ü"},
    }

    def publish_and_probe():
        # EventBridge drops anything published before the rule/target is live, so re-publish
        # on every poll rather than once.
        events.put_events(Entries=[{
            "EventBusName": bus_name, "Source": "check.ebcbus", "DetailType": "TypePreserve",
            "Detail": json.dumps(detail),
        }])
        items = _scan_all(ddb, rec_table)
        return items[0] if items else None

    deadline = time.monotonic() + _budget_s(ctx, 180)
    item = None
    while True:
        item = publish_and_probe()
        if item is not None:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("event delivery to the Lambda target: the run budget ended first; not graded")
            raise AssertionError("event never arrived at the Lambda target")
        time.sleep(2)

    received = json.loads(item["raw"]["S"])
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                        received["id"]), f"event id is not a UUID: {received['id']!r}"
    assert received["source"] == "check.ebcbus", f"source was {received['source']!r}"
    assert received["detail-type"] == "TypePreserve", f"detail-type was {received['detail-type']!r}"
    assert received["detail"] == detail, (
        f"detail round-tripped through the Node.js handler as {received['detail']!r}, "
        f"expected the published {detail!r} with every type unchanged"
    )
    assert isinstance(received["detail"]["num"], int) and received["detail"]["num"] == 42, (
        f"detail.num must survive as the number 42, got {received['detail']['num']!r}"
    )
    assert received["detail"]["flag"] is True, (
        f"detail.flag must survive as the boolean true, got {received['detail']['flag']!r}"
    )
    assert received["detail"]["nil"] is None, (
        f"detail.nil must survive as null, got {received['detail']['nil']!r}"
    )
    assert received["detail"]["nested"]["arr"] == [1, 2, 3], (
        f"detail.nested.arr must keep its element order and numeric type, got "
        f"{received['detail']['nested']['arr']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
