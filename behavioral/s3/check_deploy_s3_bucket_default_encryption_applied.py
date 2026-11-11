"""deploy-s3-bucket-default-encryption-applied."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-s3-bucket-default-encryption-applied"
GROUP = "deploy"
SERVICES = ["s3"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
Outputs:
  BucketName:
    Value: !Ref Bucket
"""


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed bucket with default BucketEncryption transparently encrypts
    an unencrypted PutObject server-side, verified via HeadObject."""
    stack_name = ctx.unique_name("sim2real-s3-enc-")
    outputs = _deploy_stack(ctx, stack_name, _TEMPLATE)
    bucket = outputs["BucketName"]

    s3 = ctx.client("s3")

    enc = s3.get_bucket_encryption(Bucket=bucket)
    rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
    assert len(rules) == 1, f"expected exactly one encryption rule, got {rules!r}"
    algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    assert algo == "AES256", f"expected the CFN-declared AES256 default, got {algo!r}"

    key = "plain-object.txt"
    # Deliberately do NOT pass ServerSideEncryption -- the bucket default must apply it.
    s3.put_object(Bucket=bucket, Key=key, Body=b"unencrypted-request-body")

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("ServerSideEncryption") == "AES256", (
        f"expected transparent SSE-S3 encryption, got {head.get('ServerSideEncryption')!r}"
    )

    got = s3.get_object(Bucket=bucket, Key=key)
    assert got.get("ServerSideEncryption") == "AES256", (
        f"expected GetObject to also report AES256, got {got.get('ServerSideEncryption')!r}"
    )
    body = got["Body"].read()
    assert body == b"unencrypted-request-body", f"expected the original bytes back, got {body!r}"


def _deploy_stack(ctx: Any, stack_name: str, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real", "Value": "s3-deploy-default-encryption"}],
    )
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    ctx.on_cleanup(lambda: _teardown_stack(ctx, stack_name, outputs))
    return outputs


def _teardown_stack(ctx: Any, stack_name: str, outputs: dict) -> None:
    bucket = outputs.get("BucketName")
    if bucket:
        try:
            _empty_bucket(ctx, bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _empty_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objects = []
        for v in page.get("Versions", []):
            objects.append({"Key": v["Key"], "VersionId": v["VersionId"]})
        for m in page.get("DeleteMarkers", []):
            objects.append({"Key": m["Key"], "VersionId": m["VersionId"]})
        if objects:
            for i in range(0, len(objects), 1000):
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects[i:i + 1000]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
