"""force-delete-stack-rejected-unless-delete-failed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "force-delete-stack-rejected-unless-delete-failed"
GROUP = "deletion-mode"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 180.0
BODY = b"sim2real-force-delete"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """DeletionMode FORCE_DELETE_STACK is refused on a healthy stack and only works from DELETE_FAILED,
    where it deletes the stack and abandons the resource that blocked the delete (read back via S3).
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfn-force-").lower()[:63]
    stack_name = ctx.unique_name("sim2real-cfn-force-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
            "B": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
            "P": {"Type": "AWS::SSM::Parameter",
                  "Properties": {"Type": "String", "Value": "sim2real"}}}}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown(cfn, s3, stack_id, bucket))
    created = _wait(cfn, stack_id, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"})
    assert created == "CREATE_COMPLETE", f"stack create: expected CREATE_COMPLETE, got {created!r}"

    code, message = _error(lambda: cfn.delete_stack(StackName=stack_id,
                                                    DeletionMode="FORCE_DELETE_STACK"))
    assert code == "ValidationError", (
        f"FORCE_DELETE_STACK on a CREATE_COMPLETE stack: expected ValidationError, got {code!r} "
        f"({message!r})"
    )
    assert message == (
        f"Invalid operation on stack [{stack_id}]. You can activate DeletionMode "
        "FORCE_DELETE_STACK in a delete stack operation only when the stack is in the "
        "DELETE_FAILED state."
    ), message
    after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert after == "CREATE_COMPLETE", f"a refused delete must leave CREATE_COMPLETE, got {after!r}"
    s3.head_bucket(Bucket=bucket)

    # A non-empty bucket makes the ordinary delete fail, reaching DELETE_FAILED.
    s3.put_object(Bucket=bucket, Key="k", Body=BODY)
    cfn.delete_stack(StackName=stack_id)
    first = _wait(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert first == "DELETE_FAILED", (
        f"deleting a stack whose bucket holds an object: expected DELETE_FAILED, got {first!r}"
    )
    states = {r["LogicalResourceId"]: r["ResourceStatus"]
              for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]}
    assert states == {"B": "DELETE_FAILED", "P": "DELETE_COMPLETE"}, (
        f"only the non-empty bucket should block the delete; resource statuses {states!r}"
    )

    cfn.delete_stack(StackName=stack_id, DeletionMode="FORCE_DELETE_STACK")
    forced = _wait(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert forced == "DELETE_COMPLETE", (
        f"FORCE_DELETE_STACK from DELETE_FAILED: expected DELETE_COMPLETE, got {forced!r}"
    )
    # The abandoned bucket is still a working bucket holding our object.
    body = s3.get_object(Bucket=bucket, Key="k")["Body"].read()
    assert body == BODY, f"the force-deleted stack's bucket must keep its object; read {body!r}"


def _error(fn) -> tuple[str, str]:
    """Exact error code and message; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("call was expected to be refused but SUCCEEDED")


def _wait(cfn, stack_id: str, terminal: set[str]) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(f"stack {stack_id!r} not in {sorted(terminal)!r} after {STACK_TIMEOUT_S}s "
                         f"(last={last!r})")


def _teardown(cfn, s3, stack_id: str, bucket: str) -> None:
    """Empty the bucket first so an ordinary delete can converge, then remove stack and bucket."""
    _leaks: list = []
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    if cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=stack_id)
        try:
            _wait(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
        except AssertionError as exc:
            _leaks.append((f"stack {stack_id}: {exc}", exc))
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
