"""deploy-cfn-stream-s3-destination-config-applied."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-cfn-stream-s3-destination-config-applied"
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
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """The S3 destination properties declared in the CFN template (bucket, role, prefix) are
    actually enforced server-side: a record put through the stream lands in the templated
    bucket, under the templated prefix, with content matching what was sent."""
    bucket_name = ctx.unique_name("sim2real-behav-fh-").lower()
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    stream_name = ctx.unique_name("sim2real-behav-fh-stream-")
    templated_prefix = "cfn-destination-check/"

    _deploy_cfn(
        ctx,
        _TEMPLATE,
        {
            "BucketName": bucket_name,
            "RoleName": role_name,
            "StreamName": stream_name,
            "Prefix": templated_prefix,
        },
    )
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    firehose = ctx.client("firehose")
    status = _wait_stream_settled(ctx, firehose, stream_name)["DeliveryStreamStatus"]
    assert status == "ACTIVE", f"expected delivery stream {stream_name} ACTIVE, got {status}"
    marker = ctx.unique_name("marker-")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": f"{marker}\n".encode()})

    key, body = _wait_for_object(ctx, bucket_name, timeout_s=240.0)
    assert key.startswith(templated_prefix), (
        f"expected the delivered object to be keyed under the templated prefix "
        f"{templated_prefix!r} (from S3DestinationConfiguration.Prefix), got {key!r}"
    )
    assert marker.encode() in body, (
        f"expected marker {marker!r} in the body of {key!r}, got {body[:200]!r}"
    )

    # confirm nothing landed outside the templated prefix (e.g. at bucket root)
    root_objects = [
        o["Key"]
        for o in ctx.client("s3").list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if not o["Key"].startswith(templated_prefix)
    ]
    assert root_objects == [], f"expected no objects outside {templated_prefix!r}, found {root_objects!r}"


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
        Tags=[{"Key": "sim2real-check", "Value": stack_name}],
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


def _wait_for_object(ctx, bucket: str, timeout_s: float = 240.0):
    # No Prefix= filter here: filtering server-side would make key.startswith(prefix) true by
    # construction and hide a target that ignores the configured Prefix.
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket)
        contents = resp.get("Contents", [])
        if contents:
            key = contents[0]["Key"]
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            return key, body
        time.sleep(2)
    raise AssertionError(f"no object landed in {bucket!r} within {timeout_s}s")


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
