"""deploy-cfn-firehose-stream-becomes-active."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-cfn-firehose-stream-becomes-active"
GROUP = "deploy"
SERVICES = ["firehose"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  BucketName:
    Type: String
  RoleName:
    Type: String
  StreamName:
    Type: String
  Prefix:
    Type: String
Resources:
  DeliveryBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  FirehoseRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: firehose.amazonaws.com
            Action: "sts:AssumeRole"
      Policies:
        - PolicyName: FirehoseS3Access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - "s3:AbortMultipartUpload"
                  - "s3:GetBucketLocation"
                  - "s3:GetObject"
                  - "s3:ListBucket"
                  - "s3:ListBucketMultipartUploads"
                  - "s3:PutObject"
                Resource:
                  - !GetAtt DeliveryBucket.Arn
                  - !Sub "${DeliveryBucket.Arn}/*"
  DeliveryStream:
    Type: AWS::KinesisFirehose::DeliveryStream
    DependsOn:
      - FirehoseRole
    Properties:
      DeliveryStreamName: !Ref StreamName
      DeliveryStreamType: DirectPut
      S3DestinationConfiguration:
        BucketARN: !GetAtt DeliveryBucket.Arn
        RoleARN: !GetAtt FirehoseRole.Arn
        Prefix: !Ref Prefix
        CompressionFormat: UNCOMPRESSED
        BufferingHints:
          IntervalInSeconds: 60
          SizeInMBs: 1
Outputs:
  StreamNameOut:
    Value: !Ref DeliveryStream
  StreamArnOut:
    Value: !GetAtt DeliveryStream.Arn
  BucketNameOut:
    Value: !Ref DeliveryBucket
"""


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "dp:api",
    "plane:control",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """A CFN stack with AWS::KinesisFirehose::DeliveryStream reaches CREATE_COMPLETE, the
    underlying stream is DescribeDeliveryStream-able in ACTIVE status, and a PutRecord
    payload actually lands in the S3 bucket the template wired as the stream's destination."""
    bucket_name = ctx.unique_name("sim2real-behav-fh-").lower()
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    stream_name = ctx.unique_name("sim2real-behav-fh-stream-")

    stack_name, outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        {
            "BucketName": bucket_name,
            "RoleName": role_name,
            "StreamName": stream_name,
            "Prefix": "data/",
        },
    )

    cfn = ctx.client("cloudformation")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected stack {stack_name} in CREATE_COMPLETE, got {stack['StackStatus']}"
    )

    firehose = ctx.client("firehose")
    desc = _wait_stream_settled(ctx, firehose, stream_name)
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected delivery stream {stream_name} ACTIVE, got {desc['DeliveryStreamStatus']}"
    )
    assert desc["DeliveryStreamName"] == stream_name, (
        f"expected DeliveryStreamName {stream_name!r}, got {desc['DeliveryStreamName']!r}"
    )
    assert outputs["StreamNameOut"] == stream_name, (
        f"stack output StreamNameOut {outputs['StreamNameOut']!r} != {stream_name!r}"
    )

    marker = ctx.unique_name("marker-")
    payload = f"deploy-cfn-becomes-active-record::{marker}\n".encode("utf-8")
    put_resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})
    assert put_resp.get("RecordId"), f"put_record returned no RecordId: {put_resp!r}"

    s3 = ctx.client("s3")
    # BufferingHints.IntervalInSeconds is 60 in the template; give the S3 destination a
    # bounded window well beyond that before concluding the record never landed.
    found_key = _poll_until(
        lambda: _find_object_containing(s3, bucket_name, marker),
        lambda key: key is not None,
        timeout_s=240.0,
        interval_s=15.0,
    )
    assert found_key is not None, f"marker {marker!r} never appeared in bucket {bucket_name}"
    body = s3.get_object(Bucket=bucket_name, Key=found_key)["Body"].read()
    assert marker.encode("utf-8") in body, f"object {found_key} did not contain marker {marker!r}"


def _deploy_cfn(ctx, template_body: str, parameters: dict) -> tuple:
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-behav-fh-stack-")
    bucket_name = parameters["BucketName"]

    def _cleanup():
        _empty_bucket(s3, bucket_name)
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    outputs = {}
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    for o in desc.get("Outputs", []):
        outputs[o["OutputKey"]] = o["OutputValue"]
    return stack_name, outputs


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _find_object_containing(s3, bucket: str, marker: str) -> str | None:
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        key = obj["Key"]
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
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
        if settled or time.monotonic() >= deadline:
            return desc
        time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
