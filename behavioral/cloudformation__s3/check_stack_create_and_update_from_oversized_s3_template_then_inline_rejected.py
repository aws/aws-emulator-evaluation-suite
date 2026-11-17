"""stack-create-and-update-from-oversized-s3-template-then-inline-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-create-and-update-from-oversized-s3-template-then-inline-rejected"
GROUP = "s3-templates"
SERVICES = ["cloudformation", "s3"]

_INLINE_LIMIT = 51_200
_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _template(marker: str, target_bytes: int) -> str:
    """A valid JSON template of exactly ``target_bytes`` bytes, padded through its Metadata."""
    skeleton = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Metadata": {"Pad": ""},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"Marker": {"Value": marker}},
    }
    bare = len(json.dumps(skeleton, separators=(",", ":")).encode())
    pad = target_bytes - bare
    assert pad > 0, f"{target_bytes} bytes is too small for a skeleton of {bare} bytes"
    skeleton["Metadata"]["Pad"] = "d" * pad
    body = json.dumps(skeleton, separators=(",", ":"))
    assert len(body.encode()) == target_bytes, f"built {len(body.encode())} bytes, wanted {target_bytes}"
    return body


def _template_url(ctx, bucket: str, key: str) -> str:
    """The path-style https URL CloudFormation resolves a TemplateURL against."""
    return f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}"


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _inline_length_error(body: str) -> tuple[str, str]:
    """The exact ValidationError CreateStack raises for a TemplateBody over the inline limit."""
    echoed = f"{body[:100]}...<{len(body)} chars total>"
    return (
        "ValidationError",
        f"1 validation error detected: Value '{echoed}' at 'templateBody' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_INLINE_LIMIT}",
    )


def _settle(cfn, stack_id: str, *, ctx, budget_s: float = 180.0) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves a transitional status."""
    left = ctx.time_left()
    budget_s = budget_s if left is None else min(budget_s, left)
    deadline = time.monotonic() + budget_s
    stack = None
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in _STACK_TERMINAL:
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {budget_s}s")
        time.sleep(3.0)


def _delete_stack(cfn, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + 180.0
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED":
            raise AssertionError(f"delete of {stack_id} ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"delete of {stack_id} did not finish within 180s")
        time.sleep(3.0)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """DeleteObjects every key, then DeleteBucket; a non-empty bucket cannot be removed."""
    keys = [{"Key": o["Key"]} for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    if keys:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
        if failed:
            raise AssertionError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]!r}")
    s3.delete_bucket(Bucket=bucket)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A template over the 51,200-byte TemplateBody limit deploys and redeploys from a private S3
    object, GetTemplate returning each object's template unchanged, while the same bytes passed
    inline to CreateStack are refused by length with no stack minted.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfn-s3-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    body_v1 = _template("v1", 60_000)
    s3.put_object(Bucket=bucket, Key="templates/v1.json", Body=body_v1.encode())

    stack_name = ctx.unique_name("sim2real-behav-cfn-s3-tpl-")
    stack_id = cfn.create_stack(StackName=stack_name, TemplateURL=_template_url(ctx, bucket, "templates/v1.json"))["StackId"]
    ctx.on_cleanup(lambda sid=stack_id: _delete_stack(cfn, sid))

    created = _settle(cfn, stack_id, ctx=ctx)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create from the {len(body_v1)}-byte S3 template ended {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )
    got = cfn.get_template(StackName=stack_id)["TemplateBody"]
    assert got == json.loads(body_v1), "GetTemplate must return the first object's template unchanged"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in created.get("Outputs", [])}
    assert outputs == {"Marker": "v1"}, f"outputs after create were {outputs!r}, expected the v1 marker"

    body_v2 = _template("v2", 61_000)
    s3.put_object(Bucket=bucket, Key="templates/v2.json", Body=body_v2.encode())
    cfn.update_stack(StackName=stack_id, TemplateURL=_template_url(ctx, bucket, "templates/v2.json"))

    updated = _settle(cfn, stack_id, ctx=ctx)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"update from the {len(body_v2)}-byte S3 template ended {updated['StackStatus']!r}: "
        f"{updated.get('StackStatusReason')!r}"
    )
    got = cfn.get_template(StackName=stack_id)["TemplateBody"]
    assert got == json.loads(body_v2), "GetTemplate must return the second object's template unchanged"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in updated.get("Outputs", [])}
    assert outputs == {"Marker": "v2"}, f"outputs after update were {outputs!r}, expected the v2 marker"

    inline_name = ctx.unique_name("sim2real-behav-cfn-s3-inline-")
    code, msg = _error(lambda: cfn.create_stack(StackName=inline_name, TemplateBody=body_v1))
    want = _inline_length_error(body_v1)
    assert (code, msg) == want, f"inline CreateStack of {len(body_v1)} bytes: got {(code, msg)!r}, want {want!r}"
    gone = _error(lambda: cfn.describe_stacks(StackName=inline_name))
    assert gone == ("ValidationError", f"Stack with id {inline_name} does not exist"), (
        f"a refused inline create must leave no stack; DescribeStacks gave {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
