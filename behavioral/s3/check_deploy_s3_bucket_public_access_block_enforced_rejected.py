"""deploy-s3-bucket-public-access-block-enforced-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-s3-bucket-public-access-block-enforced-rejected"
GROUP = "deploy"
SERVICES = ["s3"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      OwnershipControls:
        Rules:
          - ObjectOwnership: ObjectWriter
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        IgnorePublicAcls: true
        BlockPublicPolicy: true
        RestrictPublicBuckets: true
Outputs:
  BucketName:
    Value: !Ref Bucket
"""


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed bucket's PublicAccessBlock denies a public object ACL at runtime while a
    private ACL succeeds; once the block is disabled the identical public grant succeeds."""
    stack_name = ctx.unique_name("sim2real-s3-pab-")
    outputs = _deploy_stack(ctx, stack_name, _TEMPLATE)
    bucket = outputs["BucketName"]

    s3 = ctx.client("s3")

    pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert pab["BlockPublicAcls"] is True, f"expected BlockPublicAcls=True from the CFN-deployed config, got {pab!r}"
    assert pab["IgnorePublicAcls"] is True, f"expected IgnorePublicAcls=True from the CFN-deployed config, got {pab!r}"
    assert pab["BlockPublicPolicy"] is True, f"expected BlockPublicPolicy=True from the CFN-deployed config, got {pab!r}"
    assert pab["RestrictPublicBuckets"] is True, f"expected RestrictPublicBuckets=True from the CFN-deployed config, got {pab!r}"

    key = "acl-target.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"acl-test-body")

    # Positive control: a private ACL mutation succeeds under the same block.
    s3.put_object_acl(Bucket=bucket, Key=key, ACL="private")
    before = s3.get_object_acl(Bucket=bucket, Key=key)
    assert before["Grants"], "expected at least the owner FULL_CONTROL grant after a private ACL mutation"

    # Break exactly one thing: request a public grant on the object's ACL.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    partition = caller_arn.split(":")[1]
    err = _error(lambda: s3.put_object_acl(Bucket=bucket, Key=key, ACL="public-read"))
    assert err == (
        "AccessDenied",
        f"User: {caller_arn} is not authorized to perform: s3:PutObjectAcl on resource: "
        f'"arn:{partition}:s3:::{bucket}/{key}" because public ACLs are prevented by the '
        "BlockPublicAcls setting in S3 Block Public Access.",
    ), f"expected AccessDenied for public ACL grant, got {err!r}"

    # Effect absent: the object's ACL must NOT contain a public (AllUsers) grant.
    public_grants = _public_grants(s3.get_object_acl(Bucket=bucket, Key=key))
    assert public_grants == [], f"public grant leaked through: {public_grants}"

    # Disabling the block does not propagate instantly, so the identical call is polled.
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    after = _poll_until(
        lambda: _public_grants(s3.get_object_acl(Bucket=bucket, Key=key))
        if _succeeds(lambda: s3.put_object_acl(Bucket=bucket, Key=key, ACL="public-read"))
        else None,
        lambda grants: grants is not None,
        timeout_s=90,
        interval_s=3.0,
        description="the identical public ACL grant succeeds and is visible once the block is disabled",
    )

    # Effect present: the public grant is visible at an independent read.
    assert after, f"expected a public AllUsers grant once the public access block was disabled; got {after!r}"


def _error(fn):
    """Call fn(); return its (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded: {result!r}")


def _succeeds(fn) -> bool:
    from botocore.exceptions import ClientError
    try:
        fn()
        return True
    except ClientError:
        return False


def _public_grants(acl: dict) -> list:
    return [
        g for g in acl["Grants"]
        if g.get("Grantee", {}).get("URI", "").endswith("/global/AllUsers")
    ]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")


def _deploy_stack(ctx: Any, stack_name: str, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real-behav", "Value": "deploy-s3-bucket-public-access-block-enforced-rejected"}],
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
