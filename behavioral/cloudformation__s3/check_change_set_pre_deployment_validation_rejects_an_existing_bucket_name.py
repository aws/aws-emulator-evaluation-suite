"""change-set-pre-deployment-validation-rejects-an-existing-bucket-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-pre-deployment-validation-rejects-an-existing-bucket-name"
GROUP = "change_sets"
SERVICES = ["cloudformation", "s3"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object version and the bucket; only NoSuchBucket means it is already gone."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if victims:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": victims})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _bucket(ctx, s3, label):
    bucket = ctx.unique_name(f"sim2real-xsvc-{label}-")
    # us-east-1 refuses a LocationConstraint naming itself.
    where = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=bucket, **where)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    return bucket


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _wait_change_set(cf, cs_id, *, timeout_s=180.0, **extra):
    """Poll DescribeChangeSet until CREATE_COMPLETE or FAILED; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        cs = cf.describe_change_set(ChangeSetName=cs_id, **extra)
        if cs["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return cs
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after {timeout_s}s")
        time.sleep(3)


def _delete_stack(cf, stack_id, *, timeout_s=600.0):
    """Delete a stack by id and poll until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {stack['StackStatus']!r}: "
                           f"{stack.get('StackStatusReason')!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CREATE change set declaring a bucket name that already exists fails pre-deployment validation,
    while the same shape naming a bucket nobody holds clears it: the taken name is FAILED with the exact
    VALIDATION_ERROR event, the free name is CREATE_COMPLETE with none.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeEvents.html
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    free = ctx.unique_name("sim2real-xsvc-csfree-")
    free_template = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket",
                                                         "Properties": {"BucketName": free}}}})
    control = cf.create_change_set(StackName=ctx.unique_name("sim2real-xsvc-csfree-"),
                                   ChangeSetType="CREATE", Tags=_TAGS, TemplateBody=free_template,
                                   ChangeSetName=ctx.unique_name("sim2real-xsvc-csfree-cs-"))
    control_stack_id = control["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, control_stack_id))
    control_cs = _wait_change_set(cf, control["Id"], timeout_s=_cap(ctx, 180.0))
    assert (control_cs["Status"], control_cs["ExecutionStatus"]) == ("CREATE_COMPLETE", "AVAILABLE"), (
        f"a bucket name nobody holds must clear validation: "
        f"{(control_cs['Status'], control_cs.get('StatusReason'))!r}")
    control_events = cf.describe_events(ChangeSetName=control["Id"])["OperationEvents"]
    control_failures = [e for e in control_events if e.get("EventType") == "VALIDATION_ERROR"]
    assert control_failures == [], f"a free bucket name must raise no validation events: {control_failures!r}"

    taken = _bucket(ctx, s3, "csval")
    template = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket",
                                                    "Properties": {"BucketName": taken}}}})
    created = cf.create_change_set(StackName=ctx.unique_name("sim2real-xsvc-csval-"),
                                   ChangeSetType="CREATE", Tags=_TAGS, TemplateBody=template,
                                   ChangeSetName=ctx.unique_name("sim2real-xsvc-csval-cs-"))
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert (cs["Status"], cs["ExecutionStatus"]) == ("FAILED", "UNAVAILABLE"), (
        f"validation must fail the change set: {(cs['Status'], cs.get('StatusReason'))!r}")
    assert cs.get("StatusReason") == (
        "The following hook(s)/validation failed: [AWS::EarlyValidation::ResourceExistenceCheck]. "
        "To troubleshoot Early Validation errors, use the DescribeEvents API for detailed failure "
        "information."), cs.get("StatusReason")

    events = cf.describe_events(ChangeSetName=created["Id"])["OperationEvents"]
    failures = [(e.get("EventType"), e.get("LogicalResourceId"), e.get("ResourceType"),
                 e.get("ValidationName"), e.get("ValidationStatus"), e.get("ValidationFailureMode"),
                 e.get("ValidationStatusReason"), e.get("ValidationPath"))
                for e in events if e.get("EventType") == "VALIDATION_ERROR"]
    assert failures == [(
        "VALIDATION_ERROR", "Bucket", "AWS::S3::Bucket",
        "NAME_CONFLICT_VALIDATION", "FAILED", "FAIL",
        "Resource of type 'AWS::S3::Bucket' with identifier '" + taken + "' already exists.",
        "/Resources/Bucket",
    )], f"validation events: {failures!r}"
    assert {e["StackId"] for e in events} == {stack_id}, events
    assert {e.get("OperationType") for e in events} == {"CREATE_CHANGESET"}, events

    # The bucket the check owns is untouched and the stack never left review.
    tagging = s3.get_bucket_tagging(Bucket=taken)["TagSet"]
    assert tagging == _TAGS, f"owned bucket tags: expected {_TAGS!r}, got {tagging!r}"
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "REVIEW_IN_PROGRESS", f"stack must stay in review: got {status!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
