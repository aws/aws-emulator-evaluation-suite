"""kinesis-partition-key-path-renders-numbers-and-objects-as-json-and-an-absent-field-as-empty-object."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "kinesis-partition-key-path-renders-numbers-and-objects-as-json-and-an-absent-field-as-empty-object"
GROUP = "kinesis-target"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 180.0

# One target per PartitionKeyPath shape, all on one rule and one stream.
_PATHS = {
    "number": "$.detail.n",
    "object": "$.detail.o",
    "absent": "$.detail.absent",
}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Kinesis PartitionKeyPath keys each record by the selected value's compact JSON (`7`,
    `{"a":1,"b":[2]}`) and by `{}` when the path selects nothing; each record is the full envelope.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_KinesisParameters.html
    """
    events = ctx.client("events")
    kinesis = ctx.client("kinesis")
    stream_arn, stream = _create_stream(ctx, kinesis)
    role_arn = _events_role(ctx, stream_arn)
    dlq_url, dlq_arn = _create_dlq(ctx)

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.kinesis.")
    rule = _create_rule(ctx, events, bus, {"source": [source]})
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": label, "Arn": stream_arn, "RoleArn": role_arn,
         "KinesisParameters": {"PartitionKeyPath": path},
         "DeadLetterConfig": {"Arn": dlq_arn},
         "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}
        for label, path in _PATHS.items()
    ])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    detail = {"n": 7, "o": {"a": 1, "b": [2]}, "m": ctx.unique_name("m-")}
    want = {"7": "number", '{"a":1,"b":[2]}': "object", "{}": "absent"}
    records: list[dict] = []
    sent: set[str] = set()
    reader = _ShardReader(kinesis, stream)

    def _done() -> str | None:
        for eid in sent:
            keys = {r["PartitionKey"] for r in records if json.loads(r["Data"]).get("id") == eid}
            if keys >= set(want):
                return eid
        return None

    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline and _done() is None:
        if time.monotonic() >= next_put:
            # A just-created rule or role can drop events until delivery is live; re-publish.
            resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source,
                                               "DetailType": "keyed", "Detail": json.dumps(detail)}])
            assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
            sent.add(resp["Entries"][0]["EventId"])
            next_put = time.monotonic() + 20.0
        records += reader.read()
        time.sleep(2)
    event_id = _done()
    assert event_id is not None, (
        f"no event reached the stream under all three keys within {_DELIVERY_TIMEOUT_S}s; "
        f"keys seen: {sorted({r['PartitionKey'] for r in records})!r}"
    )
    mine = [r for r in records if json.loads(r["Data"]).get("id") == event_id]
    keys = sorted(r["PartitionKey"] for r in mine)
    assert set(keys) == set(want), (
        f"the event's records carry partition keys {keys!r}; expected exactly {sorted(want)!r}"
    )
    for rec in mine:
        env = json.loads(rec["Data"])
        assert (env["source"], env["detail-type"], env["detail"]) == (source, "keyed", detail), (
            f"the record under key {rec['PartitionKey']!r} ({want[rec['PartitionKey']]} path) is "
            f"not the published envelope: {env!r}"
        )

    dead = _drain_for(ctx, dlq_url, 10.0)
    assert [d for d in dead if d.get("id") == event_id] == [], (
        f"a path that selects nothing must not fail delivery; the DLQ received "
        f"{len(dead)} message(s) for the event"
    )


class _ShardReader:
    """Reads every shard from TRIM_HORIZON, keeping one iterator per shard."""

    def __init__(self, kinesis, stream: str) -> None:
        self._k = kinesis
        self._its = {
            s["ShardId"]: kinesis.get_shard_iterator(
                StreamName=stream, ShardId=s["ShardId"], ShardIteratorType="TRIM_HORIZON"
            )["ShardIterator"]
            for s in kinesis.list_shards(StreamName=stream)["Shards"]
        }

    def read(self) -> list[dict]:
        out = []
        for shard, it in list(self._its.items()):
            resp = self._k.get_records(ShardIterator=it, Limit=100)
            out += resp["Records"]
            self._its[shard] = resp["NextShardIterator"]
        return out


def _create_stream(ctx, kinesis) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-ks-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    kinesis.get_waiter("stream_exists").wait(StreamName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return arn, name


def _events_role(ctx, stream_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="put", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
            "Resource": stream_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="put"))
    return arn


def _create_dlq(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}}}]})})
    return url, arn


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> str:
    name = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(Name=name, EventBusName=bus, EventPattern=json.dumps(pattern))

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return name


def _drain_for(ctx, url: str, seconds: float) -> list[dict]:
    sqs = ctx.client("sqs")
    out: list[dict] = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=5).get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
