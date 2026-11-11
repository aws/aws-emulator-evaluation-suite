"""topic-rule-dynamodbv2-action-missing-put-item-permission-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "topic-rule-dynamodbv2-action-missing-put-item-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["iot", "dynamodb"]


def _capped(ctx, budget_s: float) -> float:
    """The wait bound, capped by the run's remaining time so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, left)


def _retry_client_error(ctx, fn, *, what: str, timeout_s: float = 50.0, interval_s: float = 2.0):
    """Retry while the fresh role propagates to IoT; raises at the deadline."""
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    while True:
        try:
            return fn()
        except ClientError as err:
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what}: {err!r}") from err
            time.sleep(interval_s)


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A dynamoDBv2 rule action whose role lacks dynamodb:PutItem never writes the item, while a
    sibling rule with a PutItem grant on the same table does, proving the setup itself works.
    """
    iot = ctx.client("iot")
    data = ctx.client("iot-data")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    scenario = "iot-rule-dynamodbv2-permission-boundary"
    table_name = ctx.unique_name("sim2real-iotddbperm-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = f"arn:aws:dynamodb:{ctx.region}:{account}:table/{table_name}"

    def _create_role(name_hint: str, grant_put_item: bool) -> str:
        role_name = ctx.unique_name(f"sim2real-{name_hint}-")
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
        if grant_put_item:
            inline = "sim2real-put-item"
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=inline,
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}],
                    }
                ),
            )
            ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline))
        return role_arn

    good_role_arn = _create_role("iotddbgoodrole", grant_put_item=True)
    bad_role_arn = _create_role("iotddbbadrole", grant_put_item=False)

    def _create_rule(name_hint: str, topic: str, role_arn: str) -> None:
        rule_name = ctx.unique_name(f"sim2real_{name_hint}_").replace("-", "_")
        _retry_client_error(
            ctx,
            lambda: iot.create_topic_rule(
                ruleName=rule_name,
                topicRulePayload={
                    "sql": f"SELECT * FROM '{topic}'",
                    "awsIotSqlVersion": "2016-03-23",
                    "ruleDisabled": False,
                    "description": "sim2real dynamodbv2 permission boundary",
                    "actions": [{"dynamoDBv2": {"roleArn": role_arn, "putItem": {"tableName": table_name}}}],
                },
                tags=f"sim2real={scenario}",
            ),
            what=f"CreateTopicRule never accepted the role for {name_hint}",
        )
        ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    topic_good = ctx.unique_name("sim2real/iotddbgood/")
    topic_bad = ctx.unique_name("sim2real/iotddbbad/")
    _create_rule("iotddbgood", topic_good, good_role_arn)
    _create_rule("iotddbbad", topic_bad, bad_role_arn)

    marker_good = str(uuid.uuid4())
    marker_bad = str(uuid.uuid4())

    def _publish_until_written(marker: str, also_bad: bool) -> bool:
        deadline = time.monotonic() + _capped(ctx, 180.0)
        while time.monotonic() < deadline:
            data.publish(topic=topic_good, qos=1, payload=json.dumps({"id": marker}).encode())
            if also_bad:
                data.publish(topic=topic_bad, qos=1, payload=json.dumps({"id": marker_bad}).encode())
            time.sleep(2)
            got = ddb.get_item(TableName=table_name, Key={"id": {"S": marker}}, ConsistentRead=True)
            if "Item" in got:
                return True
        return False

    found_good = _publish_until_written(marker_good, also_bad=True)

    assert found_good, (
        f"positive control: no item for marker_good={marker_good!r} appeared after repeated "
        "publishes — the correctly-permissioned sibling rule must deliver, or this check cannot "
        "distinguish 'enforced' from 'broken'"
    )

    # Absence by contrast: publish the bad marker once more, then a second good marker after it;
    # once the later good marker is written, the bad marker must still be absent.
    data.publish(topic=topic_bad, qos=1, payload=json.dumps({"id": marker_bad}).encode())
    marker_after = str(uuid.uuid4())
    assert _publish_until_written(marker_after, also_bad=False), (
        f"positive control: the good rule stopped delivering (no item for {marker_after!r}), so "
        "the bad marker's absence below would prove nothing"
    )
    got_bad = ddb.get_item(TableName=table_name, Key={"id": {"S": marker_bad}}, ConsistentRead=True)
    assert "Item" not in got_bad, (
        f"a dynamoDBv2 action whose role grants no dynamodb:PutItem on this table still wrote "
        f"item id={marker_bad!r}: {got_bad.get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
