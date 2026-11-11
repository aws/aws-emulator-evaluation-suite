"""create-stack-s3-bucket-name-conflict-rolls-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stack-s3-bucket-name-conflict-rolls-back"
GROUP = "stack_lifecycle"
SERVICES = ["cloudformation"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}


def _wait_terminal(cf, stack_id, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "NOT_FOUND"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} terminal not met within {timeout_s}s (last={last!r})")


def _bucket_template(bucket_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Bucket": {"Type": "AWS::S3::Bucket",
                                  "Properties": {"BucketName": bucket_name}}},
    })


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with an AWS::S3::Bucket whose BucketName is already taken ends ROLLBACK_COMPLETE
    with no resources and leaves the existing bucket alone; the same template with a free name
    creates the bucket."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    taken_bucket = ctx.unique_name("sim2real-behav-cfn-conflict-").lower()[:63]
    s3.create_bucket(
        Bucket=taken_bucket,
        CreateBucketConfiguration={"LocationConstraint": ctx.region} if ctx.region != "us-east-1" else {},
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=taken_bucket))

    bad_stack = ctx.unique_name("sim2real-behav-cfn-conflict-")
    bad_id = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_bucket_template(taken_bucket),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_if_present(cfn, bad_id))

    bad_status = _wait_terminal(cfn, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a stack whose bucket name is already taken: expected ROLLBACK_COMPLETE, "
        f"got {bad_status!r}"
    )

    events = cfn.describe_stack_events(StackName=bad_id)["StackEvents"]
    reasons = [e.get("ResourceStatusReason", "") for e in events
               if e["ResourceStatus"] == "CREATE_FAILED"]
    assert any("Validation failed" in r for r in reasons), (
        f"expected a CREATE_FAILED event naming the validation failure, got {reasons!r}"
    )

    resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    assert resources == [], (
        f"a rolled-back-from-nothing stack must have no live resources, got {resources!r}"
    )
    s3.head_bucket(Bucket=taken_bucket)

    good_bucket = ctx.unique_name("sim2real-behav-cfn-free-").lower()[:63]
    good_stack = ctx.unique_name("sim2real-behav-cfn-free-")
    good_id = cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_bucket_template(good_bucket),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_if_present(cfn, good_id))
    good_status = _wait_terminal(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the identical template with a free bucket name: expected CREATE_COMPLETE, "
        f"got {good_status!r} — the conflict case's failure was not isolated to the taken name"
    )
    s3.head_bucket(Bucket=good_bucket)


def _delete_if_present(cfn, stack_id: str) -> None:
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    try:
        _wait_terminal(cfn, stack_id)
    except AssertionError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
