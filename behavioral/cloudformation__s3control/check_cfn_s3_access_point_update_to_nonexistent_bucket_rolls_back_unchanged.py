"""cfn-s3-access-point-update-to-nonexistent-bucket-rolls-back-unchanged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-access-point-update-to-nonexistent-bucket-rolls-back-unchanged"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3control"]

_STACK_CAP_S = 300.0
_POLL_S = 2.0

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _template(bucket: str, ap_name: str) -> str:
    return json.dumps({
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
            "AP": {
                "Type": "AWS::S3::AccessPoint",
                "DependsOn": "Bucket",
                "Properties": {"Bucket": bucket, "Name": ap_name},
            },
        },
    })


def _template_broken_bucket(real_bucket: str, missing_bucket: str, ap_name: str) -> str:
    """Only the AP's Bucket changes to a name no bucket in this account ever used."""
    return json.dumps({
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": real_bucket}},
            "AP": {
                "Type": "AWS::S3::AccessPoint",
                "DependsOn": "Bucket",
                "Properties": {"Bucket": missing_bucket, "Name": ap_name},
            },
        },
    })


def _settle(cf, stack_id: str, timeout_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until a terminal status; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in _TERMINAL:
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cf, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    events = _events(cf, stack["StackId"])
    failed = [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
              for e in events if e["ResourceStatus"].endswith("_FAILED")]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r}, expected {want!r}; failed resources: {failed!r}"
    )


def _events(cf, stack_id: str) -> list:
    """Every DescribeStackEvents row of the stack, oldest first."""
    rows = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        rows.extend(page["StackEvents"])
    return list(reversed(rows))


def _physical_id(cf, stack_id: str, logical_id: str) -> str:
    resources = cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id}")


def _delete_stack_named(cf, name: str) -> None:
    try:
        stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
                "ValidationError", f"Stack with id {name} does not exist"):
            return
        raise
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(cf, stack_id)
    cf.delete_stack(StackName=stack_id)
    stack = _settle(cf, stack_id)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(f"teardown: stack {name} ended {stack['StackStatus']!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation update that replaces AWS::S3::AccessPoint's create-only Bucket with one
    that does not exist rolls the stack back, leaving the original access point untouched.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html
    """
    cf = ctx.client("cloudformation")
    s3c = ctx.client("s3control")
    account = ctx.account

    bucket = ctx.unique_name("sim2real-cfnapr-bkt-").lower()[:63]
    missing_bucket = ctx.unique_name("sim2real-cfnapr-missing-").lower()[:63]
    ap_name = ctx.unique_name("sim2real-cfnapr-a-").lower()[:50]
    stack_name = ctx.unique_name("sim2real-cfnapr-stack-")

    ctx.on_cleanup(lambda: _delete_stack_named(cf, stack_name))

    # ---- positive control: the access point deploys against the real bucket
    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template(bucket, ap_name),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "CREATE_COMPLETE")
    assert _physical_id(cf, stack_id, "AP") == ap_name, "the access point's physical id is its Name"
    before = s3c.get_access_point(AccountId=account, Name=ap_name)
    assert before["Bucket"] == bucket, f"GetAccessPoint Bucket before the update {before['Bucket']!r}"

    # ---- break exactly one thing: point the same access point at a bucket that never existed
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template_broken_bucket(bucket, missing_bucket, ap_name),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"an access point update to a nonexistent bucket must roll back, got "
        f"{stack['StackStatus']!r}: {_events(cf, stack_id)!r}"
    )
    events = _events(cf, stack_id)
    failed = [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events
              if e["LogicalResourceId"] == "AP" and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert failed, f"expected an AP UPDATE_FAILED event, stack events were {events!r}"

    # ---- effect absent: the access point still points at the original bucket, unchanged
    assert _physical_id(cf, stack_id, "AP") == ap_name, (
        "a rolled-back update must leave the access point's physical id unchanged"
    )
    after = s3c.get_access_point(AccountId=account, Name=ap_name)
    assert after["Bucket"] == bucket, (
        f"GetAccessPoint Bucket after the rolled-back update was {after['Bucket']!r}, "
        f"expected the original {bucket!r} unchanged"
    )

    # ---- restore: an identical call (the positive control's shape) succeeds again
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(bucket, ap_name),
        Tags=[{"Key": "sim2real", "Value": stack_name}, {"Key": "retry", "Value": "1"}],
    )
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "UPDATE_COMPLETE")
    restored = s3c.get_access_point(AccountId=account, Name=ap_name)
    assert restored["Bucket"] == bucket, f"GetAccessPoint Bucket after restore {restored['Bucket']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
