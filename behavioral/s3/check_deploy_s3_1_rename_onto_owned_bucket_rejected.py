"""deploy-s3-1-rename-onto-owned-bucket-rejected."""
from __future__ import annotations

import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-1-rename-onto-owned-bucket-rejected"
GROUP = "deploy-s3-bucket-update"
SERVICES = ["s3"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketNameParam:
    Type: String
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    UpdateReplacePolicy: Retain
    Properties:
      BucketName: !Ref BucketNameParam
      Tags:
        - Key: sim2real
          Value: deploy-s3-1-rename-onto-owned-bucket-rejected
Outputs:
  BucketName:
    Value: !Ref Bucket
"""

_STACK_TAG = "aws:cloudformation:stack-name"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An UpdateStack renaming the stack's bucket onto a name the account already owns fails and
    rolls back to the original bucket and data without adopting or altering the owned bucket; a
    rename to a free name then succeeds."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-s3d1n-")
    orig = ctx.unique_name("sim2real-s3d1n-a-")
    squat = ctx.unique_name("sim2real-s3d1n-c-")
    fresh = ctx.unique_name("sim2real-s3d1n-d-")

    # The pre-existing bucket the rename will collide with -- created by THIS check, not ambient.
    create = {"Bucket": squat}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create)
    ctx.on_cleanup(lambda: _delete_bucket_fully(s3, squat))
    s3.put_bucket_tagging(Bucket=squat, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=squat, Key="squat.txt", Body=b"not-the-stacks")

    # Retained buckets leave the stack on rename; these run after the stack teardown.
    ctx.on_cleanup(lambda: _delete_bucket_fully(s3, orig))
    ctx.on_cleanup(lambda: _delete_bucket_fully(s3, fresh))

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "BucketNameParam", "ParameterValue": orig}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(ctx, stack_name))
    _wait_stack(cfn, stack_name, "CREATE_COMPLETE")
    s3.put_object(Bucket=orig, Key="doc.txt", Body=b"stack-data")

    # ---- the one broken thing: rename onto an owned name ----
    cfn.update_stack(
        StackName=stack_name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "BucketNameParam", "ParameterValue": squat}],
    )
    _wait_stack(cfn, stack_name, "UPDATE_ROLLBACK_COMPLETE")

    failed = [ev for ev in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
              if ev["LogicalResourceId"] == "Bucket" and ev["ResourceStatus"].endswith("_FAILED")]
    assert failed, "stack rolled back but no Bucket resource event reports the failure"
    reason = failed[0].get("ResourceStatusReason") or ""
    assert squat in reason, f"Bucket failure reason does not name the colliding bucket {squat!r}: {reason!r}"

    phys = _physical_id(cfn, stack_name, "Bucket")
    assert phys == orig, f"after rollback the Bucket physical id is {phys!r}, expected the original {orig!r}"
    got = s3.get_object(Bucket=orig, Key="doc.txt")["Body"].read()
    assert got == b"stack-data", f"original bucket's object reads {got!r} after the rollback"

    # Effect absent: the squatted bucket was not adopted and not touched.
    keys = sorted(t["Key"] for t in s3.get_bucket_tagging(Bucket=squat)["TagSet"])
    assert _STACK_TAG not in keys, f"the pre-existing bucket {squat!r} was adopted by the stack: tags {keys!r}"
    squat_body = s3.get_object(Bucket=squat, Key="squat.txt")["Body"].read()
    assert squat_body == b"not-the-stacks", f"pre-existing bucket's object now reads {squat_body!r}"

    # ---- positive control: the same stack renames cleanly onto a free name ----
    cfn.update_stack(
        StackName=stack_name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "BucketNameParam", "ParameterValue": fresh}],
    )
    _wait_stack(cfn, stack_name, "UPDATE_COMPLETE")
    phys = _physical_id(cfn, stack_name, "Bucket")
    assert phys == fresh, f"control rename produced physical id {phys!r}, expected {fresh!r}"
    keys = sorted(t["Key"] for t in s3.get_bucket_tagging(Bucket=fresh)["TagSet"])
    assert _STACK_TAG in keys, f"the stack's new bucket {fresh!r} lacks the stack ownership tag: {keys!r}"
    kept = s3.get_object(Bucket=orig, Key="doc.txt")["Body"].read()
    assert kept == b"stack-data", f"retained original bucket's object reads {kept!r} after the control rename"


def _physical_id(cfn: Any, stack_name: str, logical_id: str) -> str:
    r = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)
    return r["StackResourceDetail"]["PhysicalResourceId"]


def _failure_events(cfn: Any, stack_name: str) -> list:
    out = []
    for ev in cfn.describe_stack_events(StackName=stack_name)["StackEvents"][:25]:
        if "FAILED" in ev.get("ResourceStatus", ""):
            out.append((ev["LogicalResourceId"], ev["ResourceStatus"], ev.get("ResourceStatusReason")))
    return out


def _wait_stack(cfn: Any, stack_name: str, want: str, timeout_s: int = 900) -> None:
    deadline = time.time() + timeout_s
    status = None
    while time.time() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status == want:
            return
        if not status.endswith("_IN_PROGRESS"):
            raise AssertionError(
                f"stack {stack_name} reached {status!r}, expected {want!r}; "
                f"failures: {_failure_events(cfn, stack_name)!r}"
            )
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s}s, expected {want!r}")


def _empty_bucket(s3: Any, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        for i in range(0, len(objs), 1000):
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs[i:i + 1000], "Quiet": True}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _delete_bucket_fully(s3: Any, bucket: str) -> None:
    try:
        _empty_bucket(s3, bucket)
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("NoSuchBucket", "404"):
            return
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(f"s3 bucket {bucket}: {exc!r}") from exc
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"s3 bucket {bucket}: {exc!r}") from exc


def _teardown_stack(ctx: Any, stack_name: str) -> None:
    """Empty every version out of the stack's current bucket, then delete the stack and wait."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    try:
        try:
            bucket = _physical_id(cfn, stack_name, "Bucket")
        except ClientError as err:
            # ValidationError "... does not exist": the stack or its Bucket resource is gone
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "does not exist" not in error.get("Message", ""):
                raise
            bucket = None
        if bucket:
            try:
                _empty_bucket(s3, bucket)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
                    raise
        cfn.delete_stack(StackName=stack_name)
        deadline = time.time() + 600
        while time.time() < deadline:
            try:
                st = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            except ClientError as err:
                # CloudFormation answers a deleted stack with ValidationError "... does not exist"
                error = err.response["Error"]
                if error["Code"] != "ValidationError" or "does not exist" not in error.get("Message", ""):
                    raise
                return
            if st == "DELETE_COMPLETE":
                return
            if st == "DELETE_FAILED":
                raise RuntimeError(f"cloudformation stack {stack_name} DELETE_FAILED: "
                                   f"{_failure_events(cfn, stack_name)!r}")
            time.sleep(5)
        raise RuntimeError(f"cloudformation stack {stack_name} not deleted within 600s")
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(f"cloudformation stack {stack_name}: {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
