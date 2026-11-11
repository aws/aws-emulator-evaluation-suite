"""eventbridge-rule-sqs-lambda-nested-detail-survives-to-dynamodb."""
from __future__ import annotations

import json
import io
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-sqs-lambda-nested-detail-survives-to-dynamodb"

GROUP = "event-propagation"

SERVICES = ["dynamodb", "events", "lambda", "sqs"]

_HANDLER = """
import json, os, boto3

_ddb = boto3.client("dynamodb")


def handler(event, context):
    for record in event["Records"]:
        env = json.loads(record["body"])
        _ddb.put_item(TableName=os.environ["TABLE"], Item={
            "pk": {"S": env["detail"]["marker"]},
            "detail_json": {"S": json.dumps(env["detail"])},
        })
    return {"ok": True}
"""

_ROLE_PROPAGATION_S = 90.0
_DELIVERY_S = 120.0
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def _run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return _run


def _create_role(ctx, statements: list) -> dict:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=name, Path="/sim2real/", AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _delete() -> None:
        for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pname)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_tolerant(_delete, "NoSuchEntity"))
    statements = statements + [{
        "Effect": "Allow", "Resource": "*",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
    }]
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return {"name": name, "arn": arn}


def _create_function(ctx, role_arn: str, env: dict) -> str:
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER)
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=30, MemorySize=128,
                Environment={"Variables": env}, Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            # A just-created role is not yet assumable by Lambda.
            if _err(exc)[0] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(
        _tolerant(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{name}"),
                  "ResourceNotFoundException")
    )
    ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            return name
        assert state != "Failed", f"function {name} reached State Failed"
        assert time.monotonic() < deadline, f"function {name} still {state!r}"
        time.sleep(2)


def _wait_esm_enabled(lam, uuid: str) -> None:
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        state = lam.get_event_source_mapping(UUID=uuid)["State"]
        if state == "Enabled":
            return
        assert state in ("Creating", "Enabling", "Updating"), f"mapping {uuid} reached {state!r}"
        assert time.monotonic() < deadline, f"mapping {uuid} still {state!r}"
        time.sleep(2)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A nested typed detail payload put on a custom bus arrives unchanged on the SQS queue and in
    the item the queue's Lambda consumer writes to DynamoDB."""
    sqs = ctx.client("sqs")
    ddb = ctx.client("dynamodb")
    events = ctx.client("events")
    lam = ctx.client("lambda")

    table = ctx.unique_name("sim2real-xsvc-tbl-")
    table_arn = ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(_tolerant(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    queue = ctx.unique_name("sim2real-xsvc-q-")
    queue_url = sqs.create_queue(
        QueueName=queue, Attributes={"VisibilityTimeout": "30"}, tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(
        _tolerant(lambda: sqs.delete_queue(QueueUrl=queue_url),
                  "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
    )
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    bus = ctx.unique_name("sim2real-xsvc-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(_tolerant(lambda: events.delete_event_bus(Name=bus), "ResourceNotFoundException"))

    source = ctx.unique_name("sim2real.nested-detail.")
    detail_type = "sim2real.nested-detail.test"
    rule = ctx.unique_name("sim2real-xsvc-rule-")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": [source]}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["RuleArn"]
    ctx.on_cleanup(
        _tolerant(lambda: events.delete_rule(Name=rule, EventBusName=bus), "ResourceNotFoundException")
    )
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    })})
    events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(
        _tolerant(
            lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["q"]),
            "ResourceNotFoundException",
        )
    )

    marker = ctx.unique_name("evt-")
    nested_detail = {
        "marker": marker,
        "total": 42.75,
        "expedited": True,
        "giftNote": None,
        "customer": {"name": "sim2real-tester", "tier": "gold"},
        "items": [
            {"sku": "WIDGET-1", "qty": 3},
            {"sku": "WIDGET-2", "qty": 1},
        ],
    }

    # Emit, re-emitting on a dropped first attempt (a just-created rule can drop its first event);
    # EventBridge never retries that on its own, so a bounded re-emit is the correct recovery.
    deadline = time.monotonic() + _DELIVERY_S
    raw_body = None
    while raw_body is None:
        resp = events.put_events(Entries=[{
            "EventBusName": bus, "Source": source, "DetailType": detail_type,
            "Detail": json.dumps(nested_detail),
        }])
        assert resp.get("FailedEntryCount") == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
        poll_until = min(deadline, time.monotonic() + 10)
        while time.monotonic() < poll_until:
            got = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2,
                VisibilityTimeout=0,
            )
            msgs = got.get("Messages", [])
            if msgs:
                raw_body = json.loads(msgs[0]["Body"])
                break
        assert time.monotonic() < deadline or raw_body is not None, (
            f"no message arrived on the queue within {_DELIVERY_S:.0f}s of re-emitting"
        )

    # Hop 1 (EventBridge -> SQS): the message sitting on the queue, read before any consumer
    # exists, carries the exact nested detail we sent.
    assert raw_body["detail"] == nested_detail, (
        f"the SQS message body's detail {raw_body['detail']!r} does not match the nested "
        f"payload sent {nested_detail!r}"
    )
    assert raw_body["source"] == source and raw_body["detail-type"] == detail_type, (
        f"the SQS message body envelope fields were source={raw_body.get('source')!r} "
        f"detail-type={raw_body.get('detail-type')!r}, expected source={source!r} "
        f"detail-type={detail_type!r}"
    )

    # Hop 2 (SQS -> Lambda): a role, a function and an event-source mapping consume the same
    # message (it is still on the queue — VisibilityTimeout=0 above put it straight back) and
    # persist what the function parsed out of it.
    role = _create_role(ctx, [
        {"Effect": "Allow", "Resource": queue_arn,
         "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]},
        {"Effect": "Allow", "Resource": table_arn, "Action": ["dynamodb:PutItem"]},
    ])
    fn = _create_function(ctx, role["arn"], {"TABLE": table})
    esm = lam.create_event_source_mapping(
        EventSourceArn=queue_arn, FunctionName=fn, BatchSize=1, Enabled=True
    )["UUID"]
    ctx.on_cleanup(
        _tolerant(lambda: lam.delete_event_source_mapping(UUID=esm), "ResourceNotFoundException")
    )
    _wait_esm_enabled(lam, esm)

    deadline = time.monotonic() + _DELIVERY_S
    item = None
    while time.monotonic() < deadline:
        resp = ddb.get_item(TableName=table, Key={"pk": {"S": marker}}, ConsistentRead=True)
        if "Item" in resp:
            item = resp["Item"]
            break
        time.sleep(1)
    assert item is not None, f"no DynamoDB write for marker {marker!r} within {_DELIVERY_S:.0f}s"

    persisted_detail = json.loads(item["detail_json"]["S"])
    assert persisted_detail == nested_detail, (
        f"the function's DynamoDB write holds detail {persisted_detail!r}, expected the nested "
        f"payload {nested_detail!r} unchanged across the SQS->Lambda hop"
    )

    deadline = time.monotonic() + _DELIVERY_S
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        if attrs.get("ApproximateNumberOfMessages") == "0" and (
            attrs.get("ApproximateNumberOfMessagesNotVisible") == "0"
        ):
            break
        assert time.monotonic() < deadline, f"the queue never drained: {attrs!r}"
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
