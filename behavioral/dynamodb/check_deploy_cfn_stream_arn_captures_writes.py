"""deploy-cfn-stream-arn-captures-writes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-cfn-stream-arn-captures-writes"
GROUP = "deploy"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed table with StreamSpecification produces a consumable stream
    that captures subsequent PutItem/UpdateItem mutations."""
    table_name = ctx.unique_name("sim2real-ddb-stream-")
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: {table_name}
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST
      StreamSpecification:
        StreamViewType: NEW_AND_OLD_IMAGES
Outputs:
  TableName:
    Value: !Ref Table
  StreamArn:
    Value: !GetAtt Table.StreamArn
""".strip()

    _deploy_cfn(ctx, template)

    ddb = ctx.client("dynamodb")
    desc = ddb.describe_table(TableName=table_name)["Table"]
    stream_arn = desc.get("LatestStreamArn")
    assert stream_arn, "CFN-deployed table with StreamSpecification must expose LatestStreamArn"
    assert desc["StreamSpecification"]["StreamViewType"] == "NEW_AND_OLD_IMAGES"

    streams = ctx.client("dynamodbstreams")
    stream_desc = streams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
    assert stream_desc["StreamStatus"] in ("ENABLED", "ENABLING")
    shard_ids = [s["ShardId"] for s in stream_desc["Shards"]]
    assert shard_ids, f"expected at least one shard on a freshly enabled stream, saw {stream_desc['Shards']!r}"
    # A fresh PAY_PER_REQUEST table's stream can start with several shards, and DynamoDB
    # Streams routes a given partition key to exactly one of them by key hash -- not
    # necessarily Shards[0]. Reading a single shard makes the check pass or fail by luck
    # of which shard the test key hashed to, so every shard is opened and drained.
    iterators = [
        streams.get_shard_iterator(
            StreamArn=stream_arn, ShardId=sid, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        for sid in shard_ids
    ]

    pk = "stream-item-1"
    ddb.put_item(TableName=table_name, Item={"pk": {"S": pk}, "val": {"S": "v1"}})
    ddb.update_item(
        TableName=table_name,
        Key={"pk": {"S": pk}},
        UpdateExpression="SET val = :v",
        ExpressionAttributeValues={":v": {"S": "v2"}},
    )

    records = _collect_stream_records(streams, iterators, timeout_s=90.0, interval_s=2.0)

    inserts = [
        r for r in records
        if r["eventName"] == "INSERT" and r["dynamodb"]["Keys"]["pk"]["S"] == pk
    ]
    modifies = [
        r for r in records
        if r["eventName"] == "MODIFY" and r["dynamodb"]["Keys"]["pk"]["S"] == pk
    ]
    assert inserts, f"expected an INSERT stream record for {pk}, saw {len(records)} records total"
    assert modifies, f"expected a MODIFY stream record for {pk}, saw {len(records)} records total"
    assert inserts[0]["dynamodb"]["NewImage"]["val"] == {"S": "v1"}
    assert modifies[0]["dynamodb"]["OldImage"]["val"] == {"S": "v1"}
    assert modifies[0]["dynamodb"]["NewImage"]["val"] == {"S": "v2"}


def _collect_stream_records(streams_client, iterators: list, *, timeout_s: float, interval_s: float) -> list:
    out: list = []
    cursors = list(iterators)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and any(cursors):
        for i, cursor in enumerate(cursors):
            if cursor is None:
                continue
            resp = streams_client.get_records(ShardIterator=cursor, Limit=100)
            out.extend(resp.get("Records", []))
            cursors[i] = resp.get("NextShardIterator")
        event_names = {r["eventName"] for r in out}
        if {"INSERT", "MODIFY"}.issubset(event_names):
            break
        time.sleep(interval_s)
    return out


def _deploy_cfn(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ddb-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return {"stack_name": stack_name, "outputs": {o["OutputKey"]: o["OutputValue"] for o in outputs}}


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
