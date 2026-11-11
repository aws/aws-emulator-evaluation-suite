"""topic-rule-kinesis-action-puts-record-from-published-message."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "topic-rule-kinesis-action-puts-record-from-published-message"
GROUP = "rule-invocation"
SERVICES = ["iot", "kinesis"]

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


def _read_all_records(kinesis, stream_name: str, shard_id: str) -> list[bytes]:
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    out: list[bytes] = []
    while iterator:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
        out.extend(r["Data"] for r in resp["Records"])
        iterator = resp.get("NextShardIterator")
        if not resp["Records"]:
            break
    return out


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
    """A topic rule's kinesis action puts a record onto the stream whose data decodes to exactly
    the published MQTT message.
    """
    iot = ctx.client("iot")
    data = ctx.client("iot-data")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    scenario = "iot-rule-kinesis-action"

    stream_name = ctx.unique_name("sim2real-iotkin-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    kinesis.get_waiter("stream_exists").wait(StreamName=stream_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    kinesis.add_tags_to_stream(StreamName=stream_name, Tags={"sim2real": scenario})
    stream_arn = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["StreamARN"]
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]["ShardId"]

    role_name = ctx.unique_name("sim2real-iotkinrole-")
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
    inline = "sim2real-put-record"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": stream_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline))

    topic = ctx.unique_name("sim2real/iotkin/")
    rule_name = ctx.unique_name("sim2real_iot_kin_").replace("-", "_")
    _retry_client_error(
        lambda: iot.create_topic_rule(
            ruleName=rule_name,
            topicRulePayload={
                "sql": f"SELECT * FROM '{topic}'",
                "awsIotSqlVersion": "2016-03-23",
                "ruleDisabled": False,
                "description": "sim2real kinesis action",
                "actions": [
                    {"kinesis": {"roleArn": role_arn, "streamName": stream_name, "partitionKey": "sim2real-partition"}}
                ],
            },
            tags=f"sim2real={scenario}",
        ),
        what="CreateTopicRule never accepted the freshly created kinesis role",
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    marker = ctx.unique_name("sim2real-marker-")
    payload = {"marker": marker, "temp": 42}
    body = json.dumps(payload).encode()

    deadline = time.monotonic() + _DELIVERY_DEADLINE_S
    found = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        data.publish(topic=topic, qos=1, payload=body)
        time.sleep(5)
        for raw in _read_all_records(kinesis, stream_name, shard_id):
            try:
                decoded = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if decoded.get("marker") == marker:
                found = decoded
                break
        if found is not None:
            break
    if found is None:
        raise AssertionError(
            f"no Kinesis record carrying marker={marker!r} appeared on stream {stream_name!r} "
            f"after {attempts} publishes over {_DELIVERY_DEADLINE_S}s"
        )

    assert found == payload, (
        f"the delivered record decoded to {found!r}, expected the exact published message {payload!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
