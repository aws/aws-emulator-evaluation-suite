"""deploy-cfn-delivery-stream-behaves-after-create."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-delivery-stream-behaves-after-create"
GROUP = "deploy"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Firehose delivery stream deployed via a CloudFormation template accepts
    PutRecord and actually delivers the record to its configured S3 destination."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    stack_name = ctx.unique_name("sim2real-behav-fh-stack-")
    bucket_name = ctx.unique_name("sim2real-behav-fh-bkt-").lower()
    stream_name = ctx.unique_name("sim2real-behav-fh-ds-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_delivery_stream_template()),
        Parameters=[
            {"ParameterKey": "BucketNameParam", "ParameterValue": bucket_name},
            {"ParameterKey": "StreamNameParam", "ParameterValue": stream_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(cfn, s3, stack_name, bucket_name))

    status = _wait_for_stack_terminal(cfn, stack_name, timeout_s=600)
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in {status}"

    _wait_stream_active(firehose, stream_name, timeout_s=180)

    marker = ctx.unique_name("marker-")
    payload = f"firehose-behav-record::{marker}\n".encode("utf-8")
    put_resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})
    assert "RecordId" in put_resp, f"expected RecordId in PutRecord response, got {put_resp}"

    # Buffering hint is 60s minimum, so give the destination a generous bounded
    # poll window before concluding the record never landed.
    remaining = _wait_for_objects_containing(s3, bucket_name, {marker}, timeout_s=240, interval_s=15)
    assert not remaining, f"record marker {marker} never landed in s3://{bucket_name}"


def _delivery_stream_template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "BucketNameParam": {"Type": "String"},
            "StreamNameParam": {"Type": "String"},
        },
        "Resources": {
            "DeliveryBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": {"Ref": "BucketNameParam"}},
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


def _teardown_stack(cfn, s3, stack_name: str, bucket_name: str) -> None:
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


def _wait_stream_active(firehose, name: str, timeout_s: float = 180, interval_s: float = 5) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status.endswith("_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
        time.sleep(interval_s)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


def _wait_for_objects_containing(
    s3, bucket: str, markers: set[str], timeout_s: float = 240, interval_s: float = 15
) -> set[str]:
    remaining = set(markers)
    seen_keys: set[str] = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and remaining:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            key = obj["Key"]
            if key in seen_keys:
                continue
            seen_keys.add(key)
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            text = body.decode("utf-8", errors="ignore")
            for m in list(remaining):
                if m in text:
                    remaining.discard(m)
        if remaining:
            time.sleep(interval_s)
    return remaining


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
