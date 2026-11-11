"""topic-rule-kinesis-action-missing-put-record-permission-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "topic-rule-kinesis-action-missing-put-record-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["iot", "kinesis"]


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


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A kinesis rule action whose role lacks kinesis:PutRecord never puts the record, while a
    sibling rule with a PutRecord grant on the same stream does, proving the setup itself works.
    """
    iot = ctx.client("iot")
    data = ctx.client("iot-data")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    scenario = "iot-rule-kinesis-permission-boundary"
    stream_name = ctx.unique_name("sim2real-iotkinperm-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    kinesis.get_waiter("stream_exists").wait(StreamName=stream_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    kinesis.add_tags_to_stream(StreamName=stream_name, Tags={"sim2real": scenario})
    stream_arn = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["StreamARN"]
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]["ShardId"]

    def _create_role(name_hint: str, grant_put_record: bool) -> str:
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
        if grant_put_record:
            inline = "sim2real-put-record"
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=inline,
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": stream_arn}],
                    }
                ),
            )
            ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline))
        return role_arn

    good_role_arn = _create_role("iotkingoodrole", grant_put_record=True)
    bad_role_arn = _create_role("iotkinbadrole", grant_put_record=False)

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
                    "description": "sim2real kinesis permission boundary",
                    "actions": [
                        {"kinesis": {"roleArn": role_arn, "streamName": stream_name, "partitionKey": "sim2real-partition"}}
                    ],
                },
                tags=f"sim2real={scenario}",
            ),
            what=f"CreateTopicRule never accepted the role for {name_hint}",
        )
        ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    topic_good = ctx.unique_name("sim2real/iotkingood/")
    topic_bad = ctx.unique_name("sim2real/iotkinbad/")
    _create_rule("iotkingood", topic_good, good_role_arn)
    _create_rule("iotkinbad", topic_bad, bad_role_arn)

    marker_good = str(uuid.uuid4())
    marker_bad = str(uuid.uuid4())

    def _decoded_records() -> list[dict]:
        out = []
        for raw in _read_all_records(kinesis, stream_name, shard_id):
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return out

    def _publish_until_delivered(marker: str, also_bad: bool, reserve_s: float) -> bool:
        # reserve_s keeps run time back for what follows, so a slow delivery fails here
        deadline = time.monotonic() + max(1.0, _capped(ctx, 180.0) - reserve_s)
        while time.monotonic() < deadline:
            data.publish(topic=topic_good, qos=1, payload=json.dumps({"marker": marker}).encode())
            if also_bad:
                data.publish(topic=topic_bad, qos=1, payload=json.dumps({"marker": marker_bad}).encode())
            time.sleep(2)
            if any(d.get("marker") == marker for d in _decoded_records()):
                return True
        return False

    found_good = _publish_until_delivered(marker_good, also_bad=True, reserve_s=30.0)

    assert found_good, (
        f"positive control: no record for marker_good={marker_good!r} appeared after repeated "
        "publishes — the correctly-permissioned sibling rule must deliver, or this check cannot "
        "distinguish 'enforced' from 'broken'"
    )

    # Absence by contrast: publish the bad marker once more, then a second good marker after it;
    # once the later good marker is on the stream, the bad marker must still be absent.
    data.publish(topic=topic_bad, qos=1, payload=json.dumps({"marker": marker_bad}).encode())
    marker_after = str(uuid.uuid4())
    assert _publish_until_delivered(marker_after, also_bad=False, reserve_s=10.0), (
        f"positive control: the good rule stopped delivering (no record for {marker_after!r}), so "
        "the bad marker's absence below would prove nothing"
    )
    decoded_records = _decoded_records()
    bad_seen = any(d.get("marker") == marker_bad for d in decoded_records)
    assert not bad_seen, (
        f"a kinesis action whose role grants no kinesis:PutRecord on this stream still delivered a "
        f"record for marker_bad={marker_bad!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
