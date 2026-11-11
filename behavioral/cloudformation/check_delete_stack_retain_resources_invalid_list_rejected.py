"""delete-stack-retain-resources-invalid-list-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-stack-retain-resources-invalid-list-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStack RetainResources naming a logical ID that doesn't exist in the stack is
    rejected rather than silently ignored, while naming the real failed resource lets the
    delete complete and genuinely retains that resource."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cfn-retain-")

    cfn.create_stack(
        StackName=name, TemplateBody=_TEMPLATE, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(ctx, name))
    _wait_stack_status(ctx, name, {"CREATE_COMPLETE"})

    bucket_name = cfn.describe_stack_resource(StackName=name, LogicalResourceId="Bucket")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))

    # Put an object in the bucket so that CloudFormation's delete of AWS::S3::Bucket fails
    # (a non-empty bucket cannot be deleted), forcing the stack into DELETE_FAILED.
    s3.put_object(Bucket=bucket_name, Key="marker.txt", Body=b"keep-me")

    cfn.delete_stack(StackName=name)
    _wait_stack_status(ctx, name, {"DELETE_FAILED"})

    got = _expect_error(
        lambda: cfn.delete_stack(StackName=name, RetainResources=["NoSuchLogicalId"])
    )
    expected = (
        "ValidationError",
        "The specified resources to retain must be in a valid state. "
        "Do not specify resources that are in the DELETE_COMPLETE state.",
    )
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # (b) effect absent: the stack is still stuck in DELETE_FAILED, unaffected by the rejected call
    still_failed = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    assert still_failed == "DELETE_FAILED", f"expected DELETE_FAILED still, got {still_failed}"

    # (c) positive control: retaining the actual failed resource lets deletion complete
    cfn.delete_stack(StackName=name, RetainResources=["Bucket"])
    _wait_stack_status(ctx, name, {"DELETE_COMPLETE"})

    # The retained bucket must still exist even though the stack is fully deleted.
    s3.head_bucket(Bucket=bucket_name)


def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_stack(ctx, name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _wait_stack_status(ctx, name, terminal_statuses, timeout_s=240.0, interval_s=4.0):
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=name)["Stacks"]
            last = stacks[0]["StackStatus"]
        except ClientError as exc:
            # Once a stack is fully torn down (DELETE_COMPLETE), CloudFormation can stop
            # resolving it by name shortly after -- treat that as having reached
            # DELETE_COMPLETE if that is one of the desired terminal statuses.
            if "does not exist" in str(exc) and "DELETE_COMPLETE" in terminal_statuses:
                return "DELETE_COMPLETE"
            raise
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} never reached {terminal_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
