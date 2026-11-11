"""deploy-subscription-filter-cfn-then-forwards-to-destination."""
from __future__ import annotations

import gzip
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-subscription-filter-cfn-then-forwards-to-destination"
GROUP = "deploy"
SERVICES = ["logs"]

_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "CREATE_FAILED",
}

_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-behav-logs-sf"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Logs::SubscriptionFilter wired to a Kinesis destination
    actually forwards matching log events to the stream after deployment, decoded end-to-end."""
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")

    group_name = ctx.unique_name("sim2real-behav-logs-sf-group-")
    stream_name = ctx.unique_name("sim2real-behav-logs-sf-stream-")
    filter_name = ctx.unique_name("sim2real-behav-logs-sf-filter-")
    dest_stream_name = ctx.unique_name("sim2real-behav-logs-sf-dest-")
    stack_name = ctx.unique_name("sim2real-behav-logs-sf-stack-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": group_name, "RetentionInDays": 1},
            },
            "LogStream": {
                "Type": "AWS::Logs::LogStream",
                "Properties": {
                    "LogGroupName": {"Ref": "LogGroup"},
                    "LogStreamName": stream_name,
                },
            },
            "DestStream": {
                "Type": "AWS::Kinesis::Stream",
                "Properties": {"Name": dest_stream_name, "ShardCount": 1},
            },
            "CWLRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "logs.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringLike": {
                                        "aws:SourceArn": {
                                            "Fn::Sub": "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:*"
                                        }
                                    }
                                },
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "CWLtoKinesis",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "kinesis:PutRecord",
                                        "Resource": {"Fn::GetAtt": ["DestStream", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "SubFilter": {
                "Type": "AWS::Logs::SubscriptionFilter",
                "Properties": {
                    "LogGroupName": {"Ref": "LogGroup"},
                    "FilterName": filter_name,
                    "FilterPattern": "ERROR",
                    "DestinationArn": {"Fn::GetAtt": ["DestStream", "Arn"]},
                    "RoleArn": {"Fn::GetAtt": ["CWLRole", "Arn"]},
                },
            },
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[
            {"Key": _MANAGED_TAG_KEY, "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _TAG_PREFIX},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    status = _wait_stack_terminal(cfn, stack_name, timeout_s=300, interval_s=2)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE, got {status}"

    described = logs.describe_subscription_filters(
        logGroupName=group_name, filterNamePrefix=filter_name
    )
    sub_filters = described["subscriptionFilters"]
    assert len(sub_filters) == 1, (
        f"expected exactly one subscription filter named {filter_name!r}, got {sub_filters!r}"
    )
    assert sub_filters[0]["filterPattern"] == "ERROR", (
        f"expected filterPattern 'ERROR', got {sub_filters[0]['filterPattern']!r}"
    )
    assert dest_stream_name in sub_filters[0]["destinationArn"], (
        f"expected destinationArn to reference stream {dest_stream_name!r}, "
        f"got {sub_filters[0]['destinationArn']!r}"
    )

    shard_id = kinesis.describe_stream(StreamName=dest_stream_name)["StreamDescription"]["Shards"][
        0
    ]["ShardId"]
    shard_iterator = kinesis.get_shard_iterator(
        StreamName=dest_stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    marker = ctx.unique_name("sf-marker-")
    found_record = None
    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else max(1.0, min(180.0, left - 5.0)))
    while time.monotonic() < deadline:
        now_ms = int(time.time() * 1000)
        logs.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[
                {"timestamp": now_ms, "message": "INFO: unrelated noise"},
                {"timestamp": now_ms + 1, "message": f"ERROR: {marker}"},
            ],
        )
        resp = kinesis.get_records(ShardIterator=shard_iterator, Limit=100)
        shard_iterator = resp["NextShardIterator"]
        for record in resp["Records"]:
            payload = json.loads(gzip.decompress(record["Data"]))
            for ev in payload.get("logEvents", []):
                if marker in ev.get("message", ""):
                    found_record = payload
                    break
            if found_record:
                break
        if found_record:
            break
        time.sleep(2)

    if found_record is None:
        raise AssertionError(
            f"no Kinesis record carrying marker {marker!r} arrived within the polling budget; "
            "the CFN-deployed subscription filter did not forward matching log events"
        )
    assert found_record["logGroup"] == group_name, (
        f"expected forwarded record logGroup {group_name!r}, got {found_record['logGroup']!r}"
    )
    assert found_record["messageType"] == "DATA_MESSAGE", (
        f"expected messageType 'DATA_MESSAGE', got {found_record['messageType']!r}"
    )
    assert filter_name in found_record["subscriptionFilters"], (
        f"expected forwarded record to name filter {filter_name!r}, "
        f"got subscriptionFilters={found_record['subscriptionFilters']!r}"
    )


# ===== helpers =====
def _wait_stack_terminal(cfn: Any, stack_name: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state, last seen {status}")


def _delete_stack(cfn: Any, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
