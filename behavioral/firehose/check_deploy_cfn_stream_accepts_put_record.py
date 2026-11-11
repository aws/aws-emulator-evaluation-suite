"""deploy-cfn-stream-accepts-put-record."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-cfn-stream-accepts-put-record"
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
  BucketNameOut:
    Value: !Ref DeliveryBucket
"""


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A delivery stream deployed by CloudFormation is ACTIVE, PutRecord returns a RecordId and Encrypted, the stack
    output names the bucket, and the record lands in that S3 bucket."""
    bucket_name = ctx.unique_name("sim2real-behav-fh-").lower()
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    stream_name = ctx.unique_name("sim2real-behav-fh-stream-")

    _, outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        {
            "BucketName": bucket_name,
            "RoleName": role_name,
            "StreamName": stream_name,
            "Prefix": "data/",
        },
    )
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    desc = _wait_stream_settled(ctx, firehose, stream_name)
    assert desc["DeliveryStreamStatus"] == "ACTIVE", f"expected ACTIVE, got {desc['DeliveryStreamStatus']}"

    marker = ctx.unique_name("put-record-marker-")
    payload = f"deploy-cfn-put-record-payload::{marker}\n".encode("utf-8")
    resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})
    assert isinstance(resp.get("RecordId"), str) and len(resp["RecordId"]) > 0, (
        f"expected a non-empty string RecordId, got {resp.get('RecordId')!r}"
    )
    assert "Encrypted" in resp, f"expected an Encrypted field on the PutRecord response, got {resp.keys()}"
    assert outputs["BucketNameOut"] == bucket_name, (
        f"expected stack output BucketNameOut == {bucket_name!r}, got {outputs.get('BucketNameOut')!r}"
    )

    # The template buffers for 60 s; poll well beyond that so the verdict rests on the record arriving in S3,
    # not on PutRecord's response alone.
    landed_key = _poll_until(
        probe=lambda: _find_object_containing(s3, bucket_name, marker),
        predicate=lambda key: key is not None,
        timeout_s=240,
        interval_s=10,
    )
    assert landed_key is not None, f"record marker {marker!r} never landed in s3://{bucket_name}"
    body = s3.get_object(Bucket=bucket_name, Key=landed_key)["Body"].read()
    assert marker.encode("utf-8") in body, (
        f"expected marker {marker!r} in delivered object {landed_key!r}, got {body[:200]!r}"
    )


def _deploy_cfn(ctx, template_body: str, parameters: dict) -> tuple:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-fh-stack-")

    def _cleanup():
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


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _find_object_containing(s3, bucket_name: str, marker: str) -> str | None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            body = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
            if marker.encode("utf-8") in body:
                return key
    return None


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
