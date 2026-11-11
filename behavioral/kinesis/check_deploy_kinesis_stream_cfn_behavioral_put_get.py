"""deploy-kinesis-stream-cfn-behavioral-put-get."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kinesis-stream-cfn-behavioral-put-get"
GROUP = "deploy"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Kinesis stream deployed via a CloudFormation template accepts PutRecord and serves
    it back via GetShardIterator/GetRecords -- live behavior beyond CREATE_COMPLETE status --
    and deleting the stack actually removes the stream, not just the stack record."""
    cfn = ctx.client("cloudformation")
    kinesis = ctx.client("kinesis")
    stack_name = ctx.unique_name("sim2real-cfn-")
    stream_name = ctx.unique_name("sim2real-cfn-stream-")

    template = {
        "Resources": {
            "Stream": {
                "Type": "AWS::Kinesis::Stream",
                "Properties": {
                    "Name": stream_name,
                    "ShardCount": 1,
                    "RetentionPeriodHours": 24,
                    "Tags": [{"Key": "sim2real-behav-check", "Value": CHECK}],
                },
            }
        },
        "Outputs": {"StreamNameOut": {"Value": {"Ref": "Stream"}}},
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {stack['StackStatus']!r}"
    )
    outputs = stack["Outputs"]
    deployed_stream_name = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "StreamNameOut")
    assert deployed_stream_name == stream_name, (
        f"expected stack output {stream_name!r}, got {deployed_stream_name!r}"
    )

    _wait_stream_active(ctx, kinesis, deployed_stream_name)
    shard_id = kinesis.list_shards(StreamName=deployed_stream_name)["Shards"][0]["ShardId"]

    payload = b"cfn-deployed-stream-payload"
    kinesis.put_record(StreamName=deployed_stream_name, Data=payload, PartitionKey="cfn-pk")

    records = _wait_for_records(ctx, kinesis, deployed_stream_name, shard_id, expected=1)
    assert len(records) == 1, f"expected exactly 1 record, got {len(records)}"
    assert records[0]["Data"] == payload, (
        f"expected payload {payload!r}, got {records[0]['Data']!r}"
    )

    _delete_stack(ctx, cfn, stack_name)
    _assert_stream_gone(kinesis, deployed_stream_name, ctx.account)


def _wait_stream_active(ctx, kinesis, stream_name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_for_records(ctx, kinesis, stream_name, shard_id, expected, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        records = kinesis.get_records(ShardIterator=iterator, Limit=100)["Records"]
        if len(records) >= expected:
            return records
        time.sleep(2)
    raise AssertionError(f"expected {expected} record(s), never observed within {timeout_s}s")


def _delete_stack(ctx, cfn, stack_name):
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


def _assert_stream_gone(kinesis, stream_name, account):
    try:
        kinesis.describe_stream_summary(StreamName=stream_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for {stream_name} after stack delete, got {code}"
        )
        expected_message = f"Stream {stream_name} under account {account} not found."
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
        return
    raise AssertionError(f"stream {stream_name} still describable after its CFN stack was deleted")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
