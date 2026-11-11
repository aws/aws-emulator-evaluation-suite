"""topic-rule-dynamodbv2-action-writes-item-from-published-message."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "topic-rule-dynamodbv2-action-writes-item-from-published-message"
GROUP = "rule-invocation"
SERVICES = ["iot", "dynamodb"]

_DELIVERY_DEADLINE_S = 180.0


def _retry_client_error(fn, *, what: str, attempts: int = 10, interval_s: float = 5.0):
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as err:
            last = err
            time.sleep(interval_s)
    raise AssertionError(f"{what}: {last!r}")


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A topic rule's dynamoDBv2 action writes a DynamoDB item with exactly one column per top-level
    attribute of the published MQTT message, keyed by the table's hash key.
    """
    iot = ctx.client("iot")
    data = ctx.client("iot-data")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    scenario = "iot-rule-dynamodbv2-action"

    table_name = ctx.unique_name("sim2real-iotddb-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    role_name = ctx.unique_name("sim2real-iotddbrole-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "iot.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                        "Condition": {"StringEquals": {"aws:SourceAccount": account}},
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline = "sim2real-put-item"
    table_arn = f"arn:aws:dynamodb:{ctx.region}:{account}:table/{table_name}"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline))

    topic = ctx.unique_name("sim2real/iotddb/")
    rule_name = ctx.unique_name("sim2real_iot_ddb_").replace("-", "_")
    _retry_client_error(
        lambda: iot.create_topic_rule(
            ruleName=rule_name,
            topicRulePayload={
                "sql": f"SELECT * FROM '{topic}'",
                "awsIotSqlVersion": "2016-03-23",
                "ruleDisabled": False,
                "description": "sim2real dynamodbv2 action",
                "actions": [{"dynamoDBv2": {"roleArn": role_arn, "putItem": {"tableName": table_name}}}],
            },
            tags=f"sim2real={scenario}",
        ),
        what="CreateTopicRule never accepted the freshly created dynamodbv2 role",
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    marker_id = ctx.unique_name("sim2real-item-")
    payload = {"id": marker_id, "temp": 42, "status": "ok"}
    body = json.dumps(payload).encode()

    deadline = time.monotonic() + _DELIVERY_DEADLINE_S
    item = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        data.publish(topic=topic, qos=1, payload=body)
        inner = time.monotonic() + 15
        while time.monotonic() < inner:
            got = ddb.get_item(TableName=table_name, Key={"id": {"S": marker_id}}, ConsistentRead=True)
            if "Item" in got:
                item = got["Item"]
                break
            time.sleep(2)
        if item is not None:
            break
    if item is None:
        raise AssertionError(
            f"no DynamoDB item with id={marker_id!r} appeared in {table_name!r} after {attempts} "
            f"publishes over {_DELIVERY_DEADLINE_S}s"
        )

    assert item["id"]["S"] == marker_id, f"item id was {item.get('id')!r}, expected S={marker_id!r}"
    assert item["temp"]["N"] == "42", f"item temp was {item.get('temp')!r}, expected N='42'"
    assert item["status"]["S"] == "ok", f"item status was {item.get('status')!r}, expected S='ok'"
    assert set(item) == {"id", "temp", "status"}, (
        f"item carries unexpected columns {sorted(set(item) - {'id', 'temp', 'status'})!r}; the "
        "dynamoDBv2 action must write exactly the message's top-level attributes, nothing else"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
