"""deploy-cfn-stream-put-get-records-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-cfn-stream-put-get-records-round-trip"
GROUP = "server-side"
SERVICES = ["kinesis"]

_TEMPLATE = """\
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Sim2RealStream:
    Type: AWS::Kinesis::Stream
    Properties:
      ShardCount: 1
      RetentionPeriodHours: 24
Outputs:
  StreamName:
    Value: !Ref Sim2RealStream
  StreamArn:
    Value: !GetAtt Sim2RealStream.Arn
"""


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stream deployed via an AWS::Kinesis::Stream CloudFormation template actually accepts
    PutRecord and returns it byte-for-byte via GetRecords -- not merely reaching
    CREATE_COMPLETE with no working data plane behind it."""
    outputs = _deploy_cfn(ctx, _TEMPLATE)
    stream_name = outputs["StreamName"]
    stream_arn = outputs["StreamArn"]

    kinesis = ctx.client("kinesis")
    summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
    assert summary["StreamStatus"] == "ACTIVE", (
        f"expected stream ACTIVE after stack CREATE_COMPLETE, got {summary['StreamStatus']!r}"
    )
    assert summary["StreamARN"] == stream_arn, (
        f"expected describe_stream_summary ARN to match the CFN GetAtt output {stream_arn!r}, "
        f"got {summary['StreamARN']!r}"
    )

    shard_id = kinesis.list_shards(StreamName=stream_name)["Shards"][0]["ShardId"]
    shard_iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    payload = f"cfn-deployed-round-trip-{ctx.unique_name('')}".encode()
    put = kinesis.put_record(StreamName=stream_name, Data=payload, PartitionKey="cfn-round-trip")

    records = _poll_for_records(ctx, shard_iterator, expected=1)
    assert records[0]["Data"] == payload, "record returned by a CFN-deployed stream was altered"
    assert records[0]["SequenceNumber"] == put["SequenceNumber"], (
        f"expected GetRecords sequence number to match PutRecord's {put['SequenceNumber']!r}, "
        f"got {records[0]['SequenceNumber']!r}"
    )


def _deploy_cfn(ctx, template_body):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-kinesis-cfn-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack_and_verify(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _delete_stack_and_verify(cfn, stack_name):
    from botocore.exceptions import ClientError

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    try:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as err:
        if "does not exist" in str(err):
            return
        raise
    assert status == "DELETE_COMPLETE", f"expected stack torn down as DELETE_COMPLETE, got {status!r}"


def _poll_for_records(ctx, shard_iterator, expected, timeout_s=60.0):
    kinesis = ctx.client("kinesis")
    records: list = []
    iterator = shard_iterator
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(records) < expected:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
        records.extend(resp["Records"])
        iterator = resp["NextShardIterator"]
        if len(records) < expected:
            time.sleep(2.0)
    if len(records) < expected:
        raise AssertionError(f"expected {expected} records, got {len(records)} within {timeout_s}s")
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
