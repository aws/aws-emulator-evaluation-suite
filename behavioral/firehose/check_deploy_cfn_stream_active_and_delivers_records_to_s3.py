"""deploy-cfn-stream-active-and-delivers-records-to-s3."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-stream-active-and-delivers-records-to-s3"
GROUP = "deploy"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CFN-deployed Firehose stream with an S3 destination is not just CREATE_COMPLETE
    but is actually able to deliver a PutRecord payload into the target S3 bucket."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    stack_name = ctx.unique_name("sim2real-behav-fhstack-")
    stream_name = ctx.unique_name("sim2real-behav-fhstream-")

    template = _build_s3_stream_template()
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": "StreamName", "ParameterValue": stream_name}],
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))

    outputs = _wait_for_stack_complete(ctx, stack_name)
    bucket_name = outputs["BucketName"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    _wait_stream_active(ctx, stream_name, timeout_s=180.0)

    marker = ctx.unique_name("marker-")
    payload = json.dumps({"marker": marker, "value": 42}).encode("utf-8")
    put_resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})
    assert isinstance(put_resp.get("RecordId"), str) and put_resp["RecordId"], (
        f"put_record on {stream_name} returned no RecordId: {put_resp}"
    )

    found = _poll_until(
        lambda: _find_object_containing(ctx, bucket_name, marker),
        lambda key: key is not None,
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert found is not None, f"marker {marker!r} never appeared in bucket {bucket_name}"
    body = s3.get_object(Bucket=bucket_name, Key=found)["Body"].read()
    assert marker.encode("utf-8") in body


def _build_s3_stream_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"StreamName": {"Type": "String"}},
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
                    "ExtendedS3DestinationConfiguration": {
                        "BucketARN": {"Fn::GetAtt": ["FirehoseBucket", "Arn"]},
                        "RoleARN": {"Fn::GetAtt": ["FirehoseRole", "Arn"]},
                        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                    },
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


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 180.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status.endswith("_FAILED"):
            raise AssertionError(f"delivery stream {stream_name} entered {status}")
        time.sleep(5)
    raise AssertionError(
        f"delivery stream {stream_name} did not become ACTIVE within {timeout_s}s "
        f"(last status {status})"
    )


def _delete_stack_and_wait(ctx, stack_name: str, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return
        if desc["StackStatus"] == "DELETE_COMPLETE":
            return
        if desc["StackStatus"].endswith("FAILED"):
            raise AssertionError(f"stack {stack_name} deletion failed: {desc['StackStatus']}")
        time.sleep(5)


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _find_object_containing(ctx, bucket_name: str, marker: str) -> str | None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket_name)
    for obj in resp.get("Contents", []):
        key = obj["Key"]
        try:
            body = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
        except Exception:
            continue
        if marker.encode("utf-8") in body:
            return key
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
