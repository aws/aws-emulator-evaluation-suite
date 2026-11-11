"""change-set-disable-validation-defers-the-bucket-name-collision-to-execution."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-disable-validation-defers-the-bucket-name-collision-to-execution"
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


def _wait_stack(cf, stack_id, *, timeout_s=300.0):
    """Poll DescribeStacks by id until the status leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)


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


def _events(cf, stack_id):
    """Every StackEvent of the stack, oldest first."""
    out = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A change set declaring an existing bucket name fails validation, while the same change set with
    DisableValidation=True reaches AVAILABLE with no VALIDATION_ERROR event; executing it fails at the
    bucket with the exact reason and rolls back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    taken = _bucket(ctx, s3, "csnoval")
    template = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket",
                                                    "Properties": {"BucketName": taken}}}})

    # Control: the identical change set with validation on is refused at validation.
    validated = cf.create_change_set(StackName=ctx.unique_name("sim2real-xsvc-csval-"),
                                     ChangeSetType="CREATE", Tags=_TAGS, TemplateBody=template,
                                     ChangeSetName=ctx.unique_name("sim2real-xsvc-csval-cs-"))
    ctx.on_cleanup(lambda: _delete_stack(cf, validated["StackId"]))
    twin = _wait_change_set(cf, validated["Id"], timeout_s=_cap(ctx, 180.0))
    got = (twin["Status"], twin["ExecutionStatus"], twin.get("StatusReason"))
    want = ("FAILED", "UNAVAILABLE",
            "The following hook(s)/validation failed: [AWS::EarlyValidation::ResourceExistenceCheck]. "
            "To troubleshoot Early Validation errors, use the DescribeEvents API for detailed failure "
            "information.")
    assert got == want, f"with validation on: expected {want!r}, got {got!r}"
    twin_events = cf.describe_events(ChangeSetName=validated["Id"])["OperationEvents"]
    twin_failures = [(e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatusReason"))
                     for e in twin_events if e.get("EventType") == "VALIDATION_ERROR"]
    want_failures = [("Bucket", "NAME_CONFLICT_VALIDATION",
                      "Resource of type 'AWS::S3::Bucket' with identifier '" + taken + "' already exists.")]
    assert twin_failures == want_failures, (
        f"validation events with validation on: expected {want_failures!r}, got {twin_failures!r}")

    created = cf.create_change_set(StackName=ctx.unique_name("sim2real-xsvc-csnoval-"),
                                   ChangeSetType="CREATE", Tags=_TAGS, TemplateBody=template,
                                   DisableValidation=True,
                                   ChangeSetName=ctx.unique_name("sim2real-xsvc-csnoval-cs-"))
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert (cs["Status"], cs["ExecutionStatus"]) == ("CREATE_COMPLETE", "AVAILABLE"), (
        f"with validation disabled: {(cs['Status'], cs.get('StatusReason'))!r}")
    events = cf.describe_events(ChangeSetName=created["Id"])["OperationEvents"]
    skipped = [e for e in events if e.get("EventType") == "VALIDATION_ERROR"]
    assert skipped == [], f"with validation disabled no VALIDATION_ERROR event is expected, got {skipped!r}"

    cf.execute_change_set(ChangeSetName=created["Id"])
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"the collision must fail at execution: {stack['StackStatus']!r}")
    failed = [e.get("ResourceStatusReason") for e in _events(cf, stack_id)
              if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Bucket", "CREATE_FAILED")]
    assert len(failed) == 1, f"bucket CREATE_FAILED reasons: {failed!r}"
    # S3's resource handler wraps the collision; only the RequestToken varies per call.
    reason_pattern = re.compile(
        r'^Resource handler returned message: "' + re.escape(taken) + r" already exists "
        r'\(Service: S3, Status Code: 0, Request ID: null\)" \(RequestToken: '
        r"[0-9a-f-]+, HandlerErrorCode: AlreadyExists\)$")
    assert reason_pattern.match(failed[0]), f"bucket CREATE_FAILED reason: {failed[0]!r}"
    assert s3.get_bucket_tagging(Bucket=taken)["TagSet"] == _TAGS, "the owned bucket must survive"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
