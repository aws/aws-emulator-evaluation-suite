"""deploy-s3express-directorybucket-invalid-data-redundancy-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3express-directorybucket-invalid-data-redundancy-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

# One documented S3 Express One Zone Availability Zone ID per region.
_EXPRESS_ZONE = {
    "us-east-1": "use1-az4", "us-east-2": "use2-az1", "us-west-2": "usw2-az1",
    "ap-northeast-1": "apne1-az4", "ap-south-1": "aps1-az1", "eu-west-1": "euw1-az1",
    "eu-north-1": "eun1-az1",
}
_REJECTED_ROW_SHAPE = ("PROPERTY_VALIDATION", "FAILED", "FAIL",
                       "MultiAvailabilityZone is not a valid enum value. "
                       "Supported values: [SingleAvailabilityZone, SingleLocalZone]",
                       "/Resources/Bucket/Properties/DataRedundancy")


def _template(bucket_name, zone_id, data_redundancy):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3Express::DirectoryBucket", "Properties": {
                "BucketName": bucket_name,
                "LocationName": zone_id,
                "DataRedundancy": data_redundancy,
            }},
        },
    })


def _own_directory_buckets(s3, name):
    buckets = paginate(s3, "list_directory_buckets", "Buckets")
    return [b for b in buckets if b["Name"] == name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation S3 Express directory bucket with an out-of-enum DataRedundancy is refused.

    Early validation names the property and no bucket exists, while SingleAvailabilityZone deploys.
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    zone_id = _EXPRESS_ZONE.get(ctx.region)
    assert zone_id, (
        f"precondition: this check's _EXPRESS_ZONE table has no S3 Express One Zone Availability "
        f"Zone ID for {ctx.region} (a limit of the check, not an AWS refusal); extend the table"
    )
    good_bucket = ctx.unique_name("sim2real-s3x-dr-good-") + f"--{zone_id}--x-s3"
    bad_bucket = ctx.unique_name("sim2real-s3x-dr-bad-") + f"--{zone_id}--x-s3"

    # Positive control: same template, the one property given a VALID value (never dropped).
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-s3x-dr-goodstack-"),
                           _template(good_bucket, zone_id, "SingleAvailabilityZone"))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    good = [b["Name"] for b in paginate(s3, "list_directory_buckets", "Buckets")
            if b["Name"] == good_bucket]
    assert good == [good_bucket], f"the control bucket is not listed: {good!r}"
    head = s3.head_bucket(Bucket=good_bucket)
    got_loc = (head["BucketLocationType"], head["BucketLocationName"])
    assert got_loc == ("AvailabilityZone", zone_id), f"control bucket location {got_loc!r}"

    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-s3x-dr-badstack-"),
                          _template(bad_bucket, zone_id, "MultiAvailabilityZone"))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [("Bucket", *_REJECTED_ROW_SHAPE)], f"validation rows {rows!r}"

    # Rollback absence through S3, by the name the bucket would have, BEFORE this check deletes.
    listed = _own_directory_buckets(s3, bad_bucket)
    assert listed == [], f"the rolled-back bucket is listed: {listed!r}"
    not_found = ("NoSuchBucket", "The specified bucket does not exist.")
    expect_error(lambda: s3.head_bucket(Bucket=bad_bucket), *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
