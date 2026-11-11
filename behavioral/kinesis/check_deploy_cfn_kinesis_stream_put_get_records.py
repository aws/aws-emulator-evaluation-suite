"""deploy-cfn-kinesis-stream-put-get-records."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-kinesis-stream-put-get-records"
GROUP = "deploy"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Kinesis::Stream reaches ACTIVE and serves data: GetRecords
    returns the PutRecord payload and sequence number. After stack deletion the stream is gone."""
    stream_name = ctx.unique_name("sim2real-behav-cfnstream-")
    template = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  StreamName:
    Type: String
Resources:
  Stream:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: !Ref StreamName
      ShardCount: 1
      RetentionPeriodHours: 24
Outputs:
  StreamName:
    Value: !Ref Stream
  StreamArn:
    Value: !GetAtt Stream.Arn
"""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cfnstack-")
    outputs = _deploy_cfn(
        ctx,
        cfn,
        stack_name,
        template,
        [{"ParameterKey": "StreamName", "ParameterValue": stream_name}],
    )
    stream_arn = outputs["StreamArn"]
    assert outputs["StreamName"] == stream_name, (
        f"expected StreamName output {stream_name!r}, got {outputs['StreamName']!r}"
    )

    kinesis = ctx.client("kinesis")
    summary = _wait_stream_active(kinesis, stream_arn)
    assert summary["StreamStatus"] == "ACTIVE", f"expected ACTIVE, got {summary['StreamStatus']!r}"

    payload = b"sim2real-cfn-stream-payload"
    put = kinesis.put_record(StreamARN=stream_arn, Data=payload, PartitionKey="pk-1")
    shard_id = put["ShardId"]

    iterator = kinesis.get_shard_iterator(
        StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records = _poll_for_records(kinesis, stream_arn, iterator, expected_count=1)
    assert len(records) == 1, f"expected 1 record, got {len(records)}"
    assert bytes(records[0]["Data"]) == payload, (
        f"expected payload {payload!r}, got {bytes(records[0]['Data'])!r}"
    )
    assert records[0]["SequenceNumber"] == put["SequenceNumber"], (
        f"expected SequenceNumber {put['SequenceNumber']!r}, got {records[0]['SequenceNumber']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    _wait_stack_deleted(cfn, stack_name)
    try:
        kinesis.describe_stream_summary(StreamARN=stream_arn)
        raise AssertionError(f"stream {stream_arn} is still describable after its stack was deleted")
    except kinesis.exceptions.ResourceNotFoundException as exc:
        want = f"Stream {stream_name} under account {ctx.account} not found."
        assert exc.response["Error"]["Message"] == want, (
            f"expected message {want!r}, got {exc.response['Error']['Message']!r}"
        )


def _deploy_cfn(
    ctx, cfn, stack_name: str, template_body: str, parameters: list[dict[str, str]]
) -> dict[str, str]:
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    deadline = time.monotonic() + 600
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} failed to create: {status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} never reached CREATE_COMPLETE, last status={status}")


def _wait_stack_deleted(cfn, stack_name: str, timeout_s: float = 600.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        status = desc["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status.endswith("FAILED"):
            raise AssertionError(f"stack {stack_name} failed to delete: {status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} never reached DELETE_COMPLETE, last status={status}")


def _wait_stream_active(kinesis, stream_arn: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {stream_arn} never became ACTIVE, last={summary}")


def _poll_for_records(kinesis, stream_arn, shard_iterator, expected_count, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    out: list[dict[str, Any]] = []
    iterator = shard_iterator
    while time.monotonic() < deadline and len(out) < expected_count and iterator is not None:
        resp = kinesis.get_records(StreamARN=stream_arn, ShardIterator=iterator, Limit=100)
        out.extend(resp["Records"])
        iterator = resp.get("NextShardIterator")
        if not resp["Records"]:
            time.sleep(1)
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} records, got {len(out)}")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
