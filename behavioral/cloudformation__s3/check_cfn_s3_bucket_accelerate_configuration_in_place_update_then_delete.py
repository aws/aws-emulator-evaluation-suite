"""cfn-s3-bucket-accelerate-configuration-in-place-update-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "cfn-s3-bucket-accelerate-configuration-in-place-update-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_NOT_FOUND = ("NoSuchBucket", "The specified bucket does not exist")
#: A stack create/update/delete finishes within minutes; the cap only stops a hung wait.
_WAITER_CFG = {"Delay": 5, "MaxAttempts": 180}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::S3::Bucket's AccelerateConfiguration deploys, reads back through
    GetBucketAccelerateConfiguration, flips Suspended<->Enabled with an in-place CFN update that
    keeps serving objects, and GetBucketAccelerateConfiguration is refused once the stack deletes.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAccelerateConfiguration.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    stack_name = ctx.unique_name("sim2real-cfnreal-accel-")
    bucket = ctx.unique_name("sim2real-cfnreal-accel-")

    ctx.on_cleanup(lambda: _teardown(cfn, s3, stack_name))

    # ---- 1. create: declared Suspended, read back through S3's own API --------------------
    cfn.create_stack(StackName=stack_name, TemplateBody=_template(bucket, "Suspended"))
    _wait(cfn, "stack_create_complete", stack_name)
    physical_before = _physical_bucket_id(cfn, stack_name)
    assert physical_before == bucket, (
        f"the stack must provision the bucket under its own name: {physical_before!r}"
    )
    status = s3.get_bucket_accelerate_configuration(Bucket=bucket).get("Status")
    assert status == "Suspended", f"the templated AccelerationStatus must read back: {status!r}"
    put = s3.put_object(Bucket=bucket, Key="first.txt", Body=b"first")
    assert "ETag" in put, f"PutObject on the bucket must succeed while suspended: {put!r}"
    assert _read(s3, bucket, "first.txt") == b"first"

    # ---- 2. in-place update: Suspended -> Enabled -------------------------------------------
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(bucket, "Enabled"))
    _wait(cfn, "stack_update_complete", stack_name)
    physical_after = _physical_bucket_id(cfn, stack_name)
    assert physical_after == physical_before, (
        f"a mutable property change must update the SAME bucket, not replace it: "
        f"before {physical_before!r}, after {physical_after!r}"
    )
    status = s3.get_bucket_accelerate_configuration(Bucket=bucket).get("Status")
    assert status == "Enabled", f"the in-place update must flip the status to Enabled: {status!r}"
    put = s3.put_object(Bucket=bucket, Key="second.txt", Body=b"second")
    assert "ETag" in put, f"PutObject on the bucket must still succeed once enabled: {put!r}"
    assert _read(s3, bucket, "first.txt") == b"first", "an in-place update keeps the objects"
    assert _read(s3, bucket, "second.txt") == b"second"

    # ---- 3. DeleteStack: the bucket it owns is gone -----------------------------------------
    _empty_bucket(s3, bucket)
    cfn.delete_stack(StackName=stack_name)
    _wait(cfn, "stack_delete_complete", stack_name)
    _assert_refused_soon(
        ctx,
        lambda: s3.get_bucket_accelerate_configuration(Bucket=bucket),
        _NOT_FOUND,
        "GetBucketAccelerateConfiguration after DeleteStack",
    )


def _template(bucket: str, status: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": bucket,
                        "AccelerateConfiguration": {"AccelerationStatus": status},
                    },
                },
            },
        }
    )


def _read(s3, bucket: str, key: str) -> bytes:
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def _wait(cfn, waiter_name: str, stack_name: str) -> None:
    """Block on a CloudFormation waiter; a WaiterError names the stack's own failure reason."""
    try:
        cfn.get_waiter(waiter_name).wait(StackName=stack_name, WaiterConfig=_WAITER_CFG)
    except WaiterError as exc:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        raise AssertionError(
            f"{waiter_name} on {stack_name!r} did not reach its terminal state: "
            f"{stack['StackStatus']} ({stack.get('StackStatusReason')!r}); {exc}"
        ) from exc


def _physical_bucket_id(cfn, stack_name: str) -> str:
    detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Bucket")
    return detail["StackResourceDetail"]["PhysicalResourceId"]


def _empty_bucket(s3, bucket: str) -> None:
    """Delete every object version and delete marker; a bucket already gone is fine."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _assert_refused_soon(ctx, fn, want: tuple[str, str], what: str) -> None:
    """A delete's effect reaches every read within seconds; retry until fn() is refused as want."""
    budget = ctx.time_left()
    deadline = time.monotonic() + (60.0 if budget is None else min(60.0, max(1.0, budget - 5.0)))
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} still succeeded past its deadline: {result!r}")
        time.sleep(2.0)


def _teardown(cfn, s3, stack_name: str) -> None:
    """Empty the bucket (if any), delete the stack and wait; a stack already gone is fine."""
    try:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    for res in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]:
        if res["ResourceType"] == "AWS::S3::Bucket":
            _empty_bucket(s3, res["PhysicalResourceId"])
    cfn.delete_stack(StackName=stack_name)
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig=_WAITER_CFG
        )
    except WaiterError as exc:
        final = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        raise AssertionError(
            f"teardown of {stack_name!r} ended {final['StackStatus']}: "
            f"{final.get('StackStatusReason')!r}"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
