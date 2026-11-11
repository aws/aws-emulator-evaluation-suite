"""deploy-cfn-stream-delivers-to-s3."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-stream-delivers-to-s3"
GROUP = "state-machine"
SERVICES = ["firehose"]

_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  BucketName:
    Type: String
  StreamName:
    Type: String
Resources:
  FirehoseRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: firehose.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: FirehoseS3Access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:AbortMultipartUpload
                  - s3:GetBucketLocation
                  - s3:GetObject
                  - s3:ListBucket
                  - s3:ListBucketMultipartUploads
                  - s3:PutObject
                Resource:
                  - !Sub "arn:aws:s3:::${BucketName}"
                  - !Sub "arn:aws:s3:::${BucketName}/*"
  DeliveryBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  DeliveryStream:
    Type: AWS::KinesisFirehose::DeliveryStream
    Properties:
      DeliveryStreamName: !Ref StreamName
      DeliveryStreamType: DirectPut
      S3DestinationConfiguration:
        BucketARN: !GetAtt DeliveryBucket.Arn
        RoleARN: !GetAtt FirehoseRole.Arn
        BufferingHints:
          IntervalInSeconds: 60
          SizeInMBs: 1
Outputs:
  StreamName:
    Value: !Ref DeliveryStream
  BucketName:
    Value: !Ref DeliveryBucket
"""


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CFN-deployed AWS::KinesisFirehose::DeliveryStream accepts PutRecord and
    actually delivers bytes to the S3 bucket configured in the template."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    stack_name = ctx.unique_name("sim2real-fh-cfn-")
    bucket_name = ctx.unique_name("sim2real-fh-cfn-").lower()
    stream_name = ctx.unique_name("sim2real-fh-cfn-")

    def _teardown() -> None:
        _empty_bucket(s3, bucket_name)
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "BucketName", "ParameterValue": bucket_name},
            {"ParameterKey": "StreamName", "ParameterValue": stream_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )

    ctx.on_cleanup(_teardown)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    deployed_stream = outputs["StreamName"]
    deployed_bucket = outputs["BucketName"]
    assert deployed_bucket == bucket_name, (
        f"expected stack output BucketName {bucket_name!r}, got {deployed_bucket!r}"
    )

    _wait_stream_active(firehose, deployed_stream, timeout_s=180)

    marker = ctx.unique_name("cfn-marker-")
    payload = f"{marker}-payload\n".encode("utf-8")
    put_resp = firehose.put_record(
        DeliveryStreamName=deployed_stream, Record={"Data": payload}
    )
    assert "RecordId" in put_resp and put_resp["RecordId"], (
        f"PutRecord did not return a RecordId: {put_resp}"
    )

    # S3 destination buffering interval minimum is 60s; poll well beyond that.
    objects = _poll_until(
        probe=lambda: _list_matching_objects(s3, deployed_bucket, marker),
        predicate=lambda found: len(found) >= 1,
        timeout_s=240,
        interval_s=10,
    )
    assert len(objects) >= 1, "no object matching the record marker landed in S3"
    body = s3.get_object(Bucket=deployed_bucket, Key=objects[0])["Body"].read()
    assert marker.encode("utf-8") in body, (
        f"delivered object {objects[0]!r} does not contain marker {marker!r}: {body!r}"
    )


# ===== helpers =====


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _wait_stream_active(firehose_client, name: str, timeout_s: float = 180) -> None:
    def _status() -> str:
        return firehose_client.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    final = _poll_until(_status, lambda s: s != "CREATING", timeout_s=timeout_s, interval_s=5)
    assert final == "ACTIVE", f"delivery stream did not become ACTIVE, ended in {final}"


def _list_matching_objects(s3_client, bucket: str, marker: str) -> list[str]:
    keys: list[str] = []
    paginator = s3_client.get_paginator("list_objects_v2")
    try:
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])
    except s3_client.exceptions.NoSuchBucket:
        return []
    if not keys:
        return []
    matched = []
    for key in keys:
        body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
        if marker.encode("utf-8") in body:
            matched.append(key)
    return matched


def _empty_bucket(s3_client, bucket: str) -> None:
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3_client.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
