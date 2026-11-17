"""deploy-cfn-kinesis-stream-encryption-disabled-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-kinesis-stream-encryption-disabled-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "kinesis"]

_NOT_FOUND = "ResourceNotFoundException"
_STACK_CAP_S = 600.0
_ENCRYPT_CAP_S = 120.0
_POLL_S = 2.0


def _template(name: str, *, encrypted: bool) -> str:
    properties = {"Name": name, "ShardCount": 1}
    if encrypted:
        properties["StreamEncryption"] = {"EncryptionType": "KMS", "KeyId": "alias/aws/kinesis"}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Stream": {"Type": "AWS::Kinesis::Stream", "Properties": properties}},
            "Outputs": {"StreamArn": {"Value": {"Fn::GetAtt": ["Stream", "Arn"]}}},
        }
    )


def _settle(cfn, stack_id: str, deadline: float) -> dict:
    """Poll DescribeStacks by id until the status stops ending in _IN_PROGRESS."""
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r}")
        time.sleep(_POLL_S)


def _require(cfn, stack_id: str, want: str) -> dict:
    stack = _settle(cfn, stack_id, time.monotonic() + _STACK_CAP_S)
    if stack["StackStatus"] != want:
        raise AssertionError(f"stack {stack_id} ended {stack['StackStatus']!r}, expected {want!r}")
    return stack


def _refused(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, call returned {result!r} instead")


def _encryption_terminal(kinesis, name: str, want_type: str) -> dict:
    """Poll DescribeStreamSummary until it reports an ACTIVE stream of the wanted encryption type."""
    deadline = time.monotonic() + _ENCRYPT_CAP_S
    while True:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE" and summary["EncryptionType"] == want_type:
            return summary
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stream {name} did not settle on EncryptionType={want_type!r}, last read {summary!r}"
            )
        time.sleep(_POLL_S)


def _round_trip(kinesis, name: str, payload: bytes) -> str:
    """PutRecord then read it back from the stream's one shard; returns the record's EncryptionType.

    Both responses omit the field rather than spell out NONE, so a missing key means unencrypted.
    """
    put = kinesis.put_record(StreamName=name, Data=payload, PartitionKey="probe")
    put_type = put.get("EncryptionType", "NONE")
    (shard,) = kinesis.list_shards(StreamName=name)["Shards"]
    iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard["ShardId"], ShardIteratorType="AT_SEQUENCE_NUMBER",
        StartingSequenceNumber=put["SequenceNumber"],
    )["ShardIterator"]
    deadline = time.monotonic() + _ENCRYPT_CAP_S
    while True:
        page = kinesis.get_records(ShardIterator=iterator, Limit=10)
        hits = [r for r in page["Records"] if bytes(r["Data"]) == payload]
        if hits:
            got = hits[0].get("EncryptionType", "NONE")
            assert got == put_type, (
                f"GetRecords reported EncryptionType {got!r}, PutRecord said {put_type!r}"
            )
            return put_type
        if time.monotonic() >= deadline:
            raise AssertionError(f"record never came back from {name} within the poll budget")
        iterator = page["NextShardIterator"]
        time.sleep(1.0)


@tags(
    "axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation",
    "dp:api", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """Removing StreamEncryption from a stream's template disables KMS encryption in place.

    The stream keeps its physical id and stays usable; adding the property back re-enables it,
    and deleting the stack leaves no trace of either state.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-kinesis-stream-streamencryption.html
    """
    cfn = ctx.client("cloudformation")
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-cfnkinenc-")
    stack = ctx.unique_name("sim2real-cfnkinenc-stack-")
    created: dict = {}

    ctx.on_cleanup(lambda: _delete(cfn, created))
    created["id"] = cfn.create_stack(
        StackName=stack, TemplateBody=_template(name, encrypted=True),
        Tags=[{"Key": "sim2real", "Value": stack}],
    )["StackId"]
    _require(cfn, created["id"], "CREATE_COMPLETE")
    summary = _encryption_terminal(kinesis, name, "KMS")
    assert summary["KeyId"] == "alias/aws/kinesis", (
        f"DescribeStreamSummary should echo the KeyId as templated, got {summary['KeyId']!r}"
    )
    assert _round_trip(kinesis, name, b"sim2real-encrypted-payload") == "KMS", (
        "a record written while StreamEncryption is set should report EncryptionType KMS"
    )

    # ---- in-place: dropping the property disables encryption without replacing the stream
    cfn.update_stack(StackName=created["id"], TemplateBody=_template(name, encrypted=False))
    _require(cfn, created["id"], "UPDATE_COMPLETE")
    resources = cfn.describe_stack_resources(StackName=created["id"])["StackResources"]
    (stream_resource,) = [r for r in resources if r["LogicalResourceId"] == "Stream"]
    assert stream_resource["PhysicalResourceId"] == name, (
        f"disabling encryption replaced the stream, physical id became "
        f"{stream_resource['PhysicalResourceId']!r}"
    )
    disabled = _encryption_terminal(kinesis, name, "NONE")
    assert disabled.get("KeyId") is None, f"KeyId survived disabling encryption: {disabled!r}"
    assert _round_trip(kinesis, name, b"sim2real-plaintext-payload") == "NONE", (
        "a record written after StreamEncryption is removed should report EncryptionType NONE"
    )

    # ---- delete: the stream is gone, encrypted or not
    cfn.delete_stack(StackName=created["id"])
    _require(cfn, created["id"], "DELETE_COMPLETE")
    got = _refused(lambda: kinesis.describe_stream_summary(StreamName=name))
    want = (_NOT_FOUND, f"Stream {name} under account {ctx.account} not found.")
    assert got == want, f"DescribeStreamSummary after delete answered {got!r}, expected {want!r}"


def _delete(cfn, created: dict) -> None:
    stack_id = created.get("id")
    if stack_id is None:
        return
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in exc.response["Error"].get("Message", ""):
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(cfn, stack_id, time.monotonic() + _STACK_CAP_S)
    cfn.delete_stack(StackName=stack_id)
    final = _settle(cfn, stack_id, time.monotonic() + _STACK_CAP_S)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(f"teardown of {stack_id} ended {final['StackStatus']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
