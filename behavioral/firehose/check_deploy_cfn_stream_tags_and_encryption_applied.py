"""deploy-cfn-stream-tags-and-encryption-applied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stream-tags-and-encryption-applied"
GROUP = "deploy"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags and encryption declared in a CFN template are exactly reflected by
    ListTagsForDeliveryStream and DescribeDeliveryStream after deploy; deleting the stack
    removes the stream."""
    cfn = ctx.client("cloudformation")
    firehose = ctx.client("firehose")

    stack_name = ctx.unique_name("sim2real-behav-fhstack-")
    stream_name = ctx.unique_name("sim2real-behav-fhstream-")
    tag_key = "sim2real-owner"
    tag_value = ctx.unique_name("team-")

    template = _build_tagged_encrypted_template()
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[
            {"ParameterKey": "StreamName", "ParameterValue": stream_name},
            {"ParameterKey": "TagKeyParam", "ParameterValue": tag_key},
            {"ParameterKey": "TagValueParam", "ParameterValue": tag_value},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )
    # Safety net only; the in-body teardown assertion below grades deletion.
    ctx.on_cleanup(lambda: _teardown_stack_if_present(ctx, stack_name))
    outputs = _wait_for_stack_complete(ctx, stack_name)
    bucket_name = outputs["BucketName"]

    tags_resp = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)
    tag_map = {t["Key"]: t["Value"] for t in tags_resp["Tags"]}
    assert tag_map.get(tag_key) == tag_value, f"expected tag {tag_key}={tag_value}, got {tag_map}"

    desc = _wait_stream_settled(ctx, firehose, stream_name)
    enc = desc["DeliveryStreamEncryptionConfiguration"]
    assert enc["Status"] == "ENABLED", f"expected encryption ENABLED, got {enc}"
    assert enc["KeyType"] == "AWS_OWNED_CMK"

    _empty_bucket(ctx, bucket_name)
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_deleted(ctx, stack_name)

    code, msg = _wait_stream_gone(ctx, firehose, stream_name)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after stack deletion, got {code}"
    )
    expected_msg = f"Firehose under account {ctx.account} not found."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _build_tagged_encrypted_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "StreamName": {"Type": "String"},
            "TagKeyParam": {"Type": "String"},
            "TagValueParam": {"Type": "String"},
        },
        "Resources": {
            "FirehoseBucket": {"Type": "AWS::S3::Bucket"},
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
                                            {"Fn::GetAtt": ["FirehoseBucket", "Arn"]},
                                            {
                                                "Fn::Join": [
                                                    "",
                                                    [{"Fn::GetAtt": ["FirehoseBucket", "Arn"]}, "/*"],
                                                ]
                                            },
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "DeliveryStream": {
                "Type": "AWS::KinesisFirehose::DeliveryStream",
                "Properties": {
                    "DeliveryStreamName": {"Ref": "StreamName"},
                    "DeliveryStreamType": "DirectPut",
                    "DeliveryStreamEncryptionConfigurationInput": {"KeyType": "AWS_OWNED_CMK"},
                    "ExtendedS3DestinationConfiguration": {
                        "BucketARN": {"Fn::GetAtt": ["FirehoseBucket", "Arn"]},
                        "RoleARN": {"Fn::GetAtt": ["FirehoseRole", "Arn"]},
                        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                    },
                    "Tags": [{"Key": {"Ref": "TagKeyParam"}, "Value": {"Ref": "TagValueParam"}}],
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "FirehoseBucket"}},
            "StreamName": {"Value": {"Ref": "DeliveryStream"}},
        },
    }


def _wait_for_stack_complete(ctx, stack_name: str, timeout_s: float = 300.0) -> dict:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        if status.endswith("FAILED") or status in ("ROLLBACK_COMPLETE",):
            raise AssertionError(f"stack {stack_name} entered {status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE in {timeout_s}s")


def _wait_for_stack_deleted(ctx, stack_name: str, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
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
            raise AssertionError(f"stack {stack_name} deletion failed: {status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE in {timeout_s}s")


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})


def _teardown_stack_if_present(ctx, stack_name: str) -> None:
    """Best-effort stack deletion for a failure before run()'s own teardown assertion."""
    cfn = ctx.client("cloudformation")
    try:
        resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    except ClientError as e:
        if "does not exist" in str(e):
            return
        raise
    for resource in resources:
        if resource["ResourceType"] == "AWS::S3::Bucket" and resource.get("PhysicalResourceId"):
            _empty_bucket(ctx, resource["PhysicalResourceId"])
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_deleted(ctx, stack_name)


def _wait_stream_settled(ctx, firehose, name: str) -> dict:
    """Read the stream until it leaves CREATING and its encryption leaves ENABLING.

    A stack can report complete first on a fast target.
    """
    left = ctx.time_left()
    deadline = time.monotonic() + max(
        1.0, min(180.0, (180.0 if left is None else left) - 5.0)
    )
    while True:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        settled = desc["DeliveryStreamStatus"] != "CREATING" and desc.get(
            "DeliveryStreamEncryptionConfiguration", {}
        ).get("Status") != "ENABLING"
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
