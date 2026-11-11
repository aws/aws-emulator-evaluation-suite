"""deploy-cfn-stream-encryption-enforced."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-stream-encryption-enforced"
GROUP = "deploy"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed stream with StreamEncryption configured actually
    serves records as KMS-encrypted end-to-end: PutRecord and GetRecords both
    report EncryptionType=KMS, not just DescribeStreamSummary metadata."""
    stream_name = ctx.unique_name("sim2real-behav-cfnenc-")
    template = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  StreamName:
    Type: String
  KeyId:
    Type: String
Resources:
  Stream:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: !Ref StreamName
      ShardCount: 1
      StreamEncryption:
        EncryptionType: KMS
        KeyId: !Ref KeyId
      Tags:
        - Key: sim2real-behav-check
          Value: cfn-stream-encryption-enforced
Outputs:
  StreamName:
    Value: !Ref Stream
  StreamArn:
    Value: !GetAtt Stream.Arn
"""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=stream_name,
        Tags=[{"TagKey": "sim2real-behav-check", "TagValue": "cfn-stream-encryption-enforced"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    outputs, stack_name = _deploy_cfn(
        ctx,
        template,
        [
            {"ParameterKey": "StreamName", "ParameterValue": stream_name},
            {"ParameterKey": "KeyId", "ParameterValue": key_id},
        ],
    )
    stream_arn = outputs["StreamArn"]

    kinesis = ctx.client("kinesis")
    summary = _wait_stream_active(ctx, kinesis, stream_arn)
    assert summary["StreamStatus"] == "ACTIVE"
    assert summary["EncryptionType"] == "KMS"

    payload = b"sim2real-cfn-encrypted-payload"
    put = kinesis.put_record(StreamARN=stream_arn, Data=payload, PartitionKey="pk-enc")
    assert put["EncryptionType"] == "KMS"

    iterator = kinesis.get_shard_iterator(
        StreamARN=stream_arn, ShardId=put["ShardId"], ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records = _poll_for_records(kinesis, stream_arn, iterator, expected_count=1)
    assert len(records) == 1
    assert records[0]["EncryptionType"] == "KMS"
    assert bytes(records[0]["Data"]) == payload

    # The cleanup callback already deletes this stack; prove the deletion actually
    # tears the KMS-encrypted stream down rather than leaving it live behind a
    # DELETE_COMPLETE stack.
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    code, message = _error(lambda: kinesis.describe_stream_summary(StreamARN=stream_arn))
    assert code == "ResourceNotFoundException", (
        f"expected the encrypted stream {stream_arn} to disappear after stack deletion, "
        f"got code={code!r}"
    )
    expected_message = f"Stream {stream_name} under account {ctx.account} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _deploy_cfn(ctx, template_body: str, parameters: list[dict[str, str]]) -> tuple[dict[str, str], str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cfnstack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body, Parameters=parameters)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    deadline = time.monotonic() + 600
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}, stack_name
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} failed to create: {status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} never reached CREATE_COMPLETE, last status={status}")


def _wait_stream_active(ctx, kinesis, stream_arn: str, timeout_s: float = 180.0) -> dict[str, Any]:
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
