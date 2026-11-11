"""nested-change-set-child-execution-status-unavailable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nested-change-set-child-execution-status-unavailable"
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


def _bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-xsvc-csunavail-")
    where = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=bucket, **where)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    return bucket


def _handles(*names):
    return {n: {"Type": "AWS::CloudFormation::WaitConditionHandle"} for n in names}


_CHILD_V1 = json.dumps({"Resources": _handles("H1")})
_CHILD_V2 = json.dumps({"Resources": _handles("H1", "H2")})
_PARENT = json.dumps({
    "Parameters": {"ChildUrl": {"Type": "String"}},
    "Resources": {"Child": {"Type": "AWS::CloudFormation::Stack",
                            "Properties": {"TemplateURL": {"Ref": "ChildUrl"}}}},
})


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


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


def _stack_change(cs, logical_id):
    rcs = [c["ResourceChange"] for c in cs["Changes"]]
    assert [(rc["LogicalResourceId"], rc["ResourceType"], rc["Action"]) for rc in rcs] == [
        (logical_id, "AWS::CloudFormation::Stack", "Modify")], rcs
    return rcs[0]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A nested stack's own change set reports ExecutionStatus UNAVAILABLE naming it executable
    from the root change set, and ExecuteChangeSet on that child id is refused outright.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/change-sets-for-nested-stacks.html
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket = _bucket(ctx, s3)
    urls = {}
    for key, body in (("child-v1", _CHILD_V1), ("child-v2", _CHILD_V2)):
        s3.put_object(Bucket=bucket, Key=f"{key}.json", Body=body.encode())
        urls[key] = f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}.json"

    def params(child):
        return [{"ParameterKey": "ChildUrl", "ParameterValue": urls[child]}]

    root_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-csunavail-"), Tags=_TAGS,
                              TemplateBody=_PARENT, Parameters=params("child-v1"))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, root_id))
    stack = _wait_stack(cf, root_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"setup: {stack['StackStatus']!r} {stack.get('StackStatusReason')!r}")
    child_stack = cf.describe_stack_resource(StackName=root_id, LogicalResourceId="Child")[
        "StackResourceDetail"]["PhysicalResourceId"]

    root_cs = cf.create_change_set(StackName=root_id, ChangeSetType="UPDATE", IncludeNestedStacks=True,
                                   UsePreviousTemplate=True, Parameters=params("child-v2"),
                                   ChangeSetName=ctx.unique_name("sim2real-xsvc-csunavail-cs-"))["Id"]
    root = _wait_change_set(cf, root_cs, timeout_s=_cap(ctx, 300.0))
    assert root["Status"] == "CREATE_COMPLETE", f"root change set: {root.get('StatusReason')!r}"
    assert root.get("ExecutionStatus") == "AVAILABLE", (
        f"the root change set must itself be directly executable: {root.get('ExecutionStatus')!r}")

    child_cs = _stack_change(root, "Child")["ChangeSetId"]
    child = _wait_change_set(cf, child_cs, timeout_s=_cap(ctx, 180.0))
    assert child["Status"] == "CREATE_COMPLETE", f"child change set: {child.get('StatusReason')!r}"

    # --- the gap: a child's own change set names itself non-executable and the root as the one
    # that must be used, and a direct ExecuteChangeSet against it is refused outright ---
    assert (child.get("ExecutionStatus"), child.get("StatusReason")) == (
        "UNAVAILABLE", "Only executable from the root change set.",
    ), (child.get("ExecutionStatus"), child.get("StatusReason"))

    child_not_executable = (
        "InvalidChangeSetStatus",
        f"ChangeSet [{child_cs}] cannot be executed in its current execution status of [UNAVAILABLE]",
    )
    expect_error(lambda: cf.execute_change_set(ChangeSetName=child_cs, StackName=child_stack),
                 *child_not_executable)

    # --- effect absent: the refused execute left the child stack and its resource untouched ---
    child_detail = cf.describe_stack_resource(StackName=child_stack, LogicalResourceId="H1")[
        "StackResourceDetail"]
    assert child_detail["ResourceStatus"] == "CREATE_COMPLETE", child_detail
    # H2 must not exist yet, since the refused child execute never applied it.
    h2_absent = ("ValidationError", f"Resource H2 does not exist for stack {child_stack}")
    expect_error(lambda: cf.describe_stack_resource(StackName=child_stack, LogicalResourceId="H2"),
                 *h2_absent)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
