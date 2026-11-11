"""deploy-cfn-stack-deletion-removes-delivery-stream."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-deletion-removes-delivery-stream"
GROUP = "deploy"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a CloudFormation stack that owns a delivery stream removes the
    underlying resource; a subsequent DescribeDeliveryStream returns ResourceNotFound."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    stack_name = ctx.unique_name("sim2real-behav-fh-stack2-")
    bucket_name = ctx.unique_name("sim2real-behav-fh-bkt2-").lower()
    stream_name = ctx.unique_name("sim2real-behav-fh-ds2-")
    tag_value = ctx.unique_name("team-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_delivery_stream_template(tag_value)),
        Parameters=[
            {"ParameterKey": "BucketNameParam", "ParameterValue": bucket_name},
            {"ParameterKey": "StreamNameParam", "ParameterValue": stream_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )
    # Safety-net cleanup in case an assertion fails before the explicit teardown below runs.
    ctx.on_cleanup(lambda: _teardown_stack_if_present(cfn, s3, stack_name, bucket_name))

    status = _wait_for_stack_terminal(cfn, stack_name, timeout_s=600)
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in {status}"

    active_desc = _wait_stream_settled(ctx, firehose, stream_name)
    assert active_desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected ACTIVE after CREATE_COMPLETE, got {active_desc['DeliveryStreamStatus']}"
    )

    # No records were sent, so the destination bucket is empty and the stack can
    # delete cleanly without any manual emptying step.
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_deleted(cfn, stack_name, timeout_s=600)

    code, msg = _wait_stream_gone(ctx, firehose, stream_name)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after stack deletion, got {code!r}"
    )
    expected_msg = f"Firehose under account {ctx.account} not found."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _delivery_stream_template(tag_value: str) -> dict[str, Any]:
    owner_tag = [{"Key": "sim2real-owner", "Value": tag_value}]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "BucketNameParam": {"Type": "String"},
            "StreamNameParam": {"Type": "String"},
        },
        "Resources": {
            "DeliveryBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": {"Ref": "BucketNameParam"}, "Tags": owner_tag},
            },
            "FirehoseRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "firehose.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "firehose-s3-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "s3:AbortMultipartUpload",
                                            "s3:GetBucketLocation",
                                            "s3:GetObject",
                                            "s3:ListBucket",
                                            "s3:ListBucketMultipartUploads",
                                            "s3:PutObject",
                                        ],
                                        "Resource": [
                                            {"Fn::GetAtt": ["DeliveryBucket", "Arn"]},
                                            {
                                                "Fn::Join": [
                                                    "",
                                                    [{"Fn::GetAtt": ["DeliveryBucket", "Arn"]}, "/*"],
                                                ]
                                            },
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": owner_tag,
                },
            },
            "DeliveryStream": {
                "Type": "AWS::KinesisFirehose::DeliveryStream",
                "DependsOn": "FirehoseRole",
                "Properties": {
                    "DeliveryStreamName": {"Ref": "StreamNameParam"},
                    "DeliveryStreamType": "DirectPut",
                    "ExtendedS3DestinationConfiguration": {
                        "BucketARN": {"Fn::GetAtt": ["DeliveryBucket", "Arn"]},
                        "RoleARN": {"Fn::GetAtt": ["FirehoseRole", "Arn"]},
                        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                    },
                    "Tags": owner_tag,
                },
            },
        },
        "Outputs": {
            "DeliveryStreamNameOut": {"Value": {"Ref": "DeliveryStream"}},
            "BucketNameOut": {"Value": {"Ref": "DeliveryBucket"}},
        },
    }


def _wait_for_stack_terminal(cfn, stack_name: str, timeout_s: float = 600, interval_s: float = 10) -> str:
    terminal = {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "ROLLBACK_COMPLETE",
        "CREATE_FAILED",
        "UPDATE_ROLLBACK_COMPLETE",
    }
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within {timeout_s}s")


def _wait_for_stack_deleted(cfn, stack_name: str, timeout_s: float = 600, interval_s: float = 10) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            if "does not exist" in str(e):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _teardown_stack_if_present(cfn, s3, stack_name: str, bucket_name: str) -> None:
    try:
        cfn.describe_stacks(StackName=stack_name)
    except ClientError as e:
        if "does not exist" in str(e):
            return
        raise
    try:
        _empty_bucket(s3, bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
    _wait_for_stack_deleted(cfn, stack_name, timeout_s=600)


def _wait_stream_settled(ctx, firehose, name: str) -> dict:
    """Read the stream until it leaves CREATING; a stack can report complete first."""
    left = ctx.time_left()
    deadline = time.monotonic() + max(
        1.0, min(180.0, (180.0 if left is None else left) - 5.0)
    )
    while True:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        settled = desc["DeliveryStreamStatus"] != "CREATING"
        if settled:
            return desc
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before stream {name} settled; not graded")
            raise AssertionError(f"stream {name} did not settle within its deadline: {desc!r}")
        time.sleep(1)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stream_gone(ctx, firehose, name: str, timeout_s: float = 180.0):
    """Read the stream until DescribeDeliveryStream refuses it; return (Error.Code, Error.Message).

    A stream still DELETING when its stack reports DELETE_COMPLETE keeps the wait going.
    """
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            desc = firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        status = desc["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        assert status == "DELETING", (
            f"stream {name} reads {status!r} after its stack was deleted; expected DELETING or gone"
        )
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while stream {name} was DELETING; not graded")
            raise AssertionError(f"stream {name} still DELETING {timeout_s:.0f}s after its stack was deleted")
        time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
