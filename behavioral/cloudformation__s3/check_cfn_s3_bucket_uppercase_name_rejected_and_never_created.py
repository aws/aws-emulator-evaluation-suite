"""cfn-s3-bucket-uppercase-name-rejected-and-never-created."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-bucket-uppercase-name-rejected-and-never-created"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "s3"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

_HANDLER_REASON = re.compile(
    r'Resource handler returned message: "(?P<message>.*?)".*HandlerErrorCode: (?P<code>\w+)'
)


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _resource_failure(cfn, stack_id: str, logical_id: str) -> tuple[str, str]:
    """``(HandlerErrorCode, message)`` from the CREATE_FAILED event for *logical_id*."""
    for event in cfn.describe_stack_events(StackName=stack_id)["StackEvents"]:
        if event["LogicalResourceId"] != logical_id or event["ResourceStatus"] != "CREATE_FAILED":
            continue
        reason = event.get("ResourceStatusReason", "")
        match = _HANDLER_REASON.search(reason)
        if match:
            return match.group("code"), match.group("message")
        raise AssertionError(f"could not parse handler reason: {reason!r}")
    raise AssertionError(f"no CREATE_FAILED event for {logical_id!r} in stack {stack_id!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::S3::Bucket whose BucketName has uppercase characters rolls back and
    no bucket is ever created under that name, while the same template with a valid name deploys."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bad_bucket = ctx.unique_name("sim2real-behav-cfn-s3bad-") + "BAD"
    bad_stack_name = ctx.unique_name("sim2real-behav-cfn-s3bad-")
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bad_bucket}},
            },
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack_id))

    status = _wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    code, message = _resource_failure(cfn, bad_stack_id, "Bucket")
    assert code == "InternalFailure", f"expected HandlerErrorCode InternalFailure, got {code!r}"
    assert message == "Bucket name should not contain uppercase characters", (
        f"expected the standard uppercase-name message, got {message!r}"
    )

    try:
        s3.head_bucket(Bucket=bad_bucket)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "404", (
            f"expected the never-created bucket to answer 404, got {exc.response['Error']['Code']!r}"
        )
    else:
        raise AssertionError(f"bucket {bad_bucket!r} unexpectedly exists")

    # Positive control, in the same file: a validly-named bucket deploys cleanly.
    good_bucket = ctx.unique_name("sim2real-behav-cfn-s3ok-").lower()[:63]
    good_stack_name = ctx.unique_name("sim2real-behav-cfn-s3ok-")
    good_stack_id = cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": good_bucket}},
            },
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack_id))
    good_status = _wait_stack(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {good_status!r}"
    s3.head_bucket(Bucket=good_bucket)  # control: the validly-named bucket is real

    for stack_id in (bad_stack_id, good_stack_id):
        _delete_stack_and_wait(cfn, stack_id)
        final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        assert final == "DELETE_COMPLETE", f"stack {stack_id} delete ended {final!r}"
    try:
        s3.get_bucket_versioning(Bucket=good_bucket)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
    else:
        raise AssertionError(f"bucket {good_bucket!r} still exists after its stack delete")
    assert got == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"the control bucket after its stack delete: {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
