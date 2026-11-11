"""change-set-include-nested-stacks-links-the-change-set-tree."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-include-nested-stacks-links-the-change-set-tree"
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


def _handles(*names):
    return {n: {"Type": "AWS::CloudFormation::WaitConditionHandle"} for n in names}


_GRAND_V1 = json.dumps({"Resources": _handles("G1")})
_GRAND_V2 = json.dumps({"Resources": _handles("G1", "G2")})
_CHILD = json.dumps({
    "Parameters": {"GrandUrl": {"Type": "String"}},
    "Resources": {"Grand": {"Type": "AWS::CloudFormation::Stack",
                            "Properties": {"TemplateURL": {"Ref": "GrandUrl"}}}},
})
_PARENT = json.dumps({
    "Parameters": {"ChildUrl": {"Type": "String"}, "GrandUrl": {"Type": "String"}},
    "Resources": {"Child": {"Type": "AWS::CloudFormation::Stack",
                            "Properties": {"TemplateURL": {"Ref": "ChildUrl"},
                                           "Parameters": {"GrandUrl": {"Ref": "GrandUrl"}}}}},
})


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, the call succeeded: {result!r}")


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


def _wait_unlisted(cf, stack_id, cs_id, *, timeout_s=120.0):
    """Poll ListChangeSets until the stack lists cs_id no more."""
    deadline = time.monotonic() + timeout_s
    while True:
        listed = {s["ChangeSetId"] for s in cf.list_change_sets(StackName=stack_id)["Summaries"]}
        if cs_id not in listed:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"nested change set {cs_id} survived its root's deletion")
        time.sleep(3)


def _stack_change(cs, logical_id):
    rcs = [c["ResourceChange"] for c in cs["Changes"]]
    assert [(rc["LogicalResourceId"], rc["ResourceType"], rc["Action"]) for rc in rcs] == [
        (logical_id, "AWS::CloudFormation::Stack", "Modify")], rcs
    return rcs[0]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """IncludeNestedStacks builds a change-set tree: each nested stack change carries its child set's
    ChangeSetId, each child names its ParentChangeSetId and the root, and deleting the root removes it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeChangeSet.html
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket = _bucket(ctx, s3, "csnest")
    urls = {}
    for key, body in (("child", _CHILD), ("grand-v1", _GRAND_V1), ("grand-v2", _GRAND_V2)):
        s3.put_object(Bucket=bucket, Key=f"{key}.json", Body=body.encode())
        urls[key] = f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}.json"

    def params(grand):
        return [{"ParameterKey": "ChildUrl", "ParameterValue": urls["child"]},
                {"ParameterKey": "GrandUrl", "ParameterValue": urls[grand]}]

    root_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-csnest-"), Tags=_TAGS,
                              TemplateBody=_PARENT, Parameters=params("grand-v1"))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, root_id))
    stack = _wait_stack(cf, root_id, timeout_s=_cap(ctx, 400.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"setup: {stack['StackStatus']!r} {stack.get('StackStatusReason')!r}")
    child_stack = cf.describe_stack_resource(StackName=root_id, LogicalResourceId="Child")[
        "StackResourceDetail"]["PhysicalResourceId"]
    grand_stack = cf.describe_stack_resource(StackName=child_stack, LogicalResourceId="Grand")[
        "StackResourceDetail"]["PhysicalResourceId"]

    root_cs = cf.create_change_set(StackName=root_id, ChangeSetType="UPDATE", IncludeNestedStacks=True,
                                   UsePreviousTemplate=True, Parameters=params("grand-v2"),
                                   ChangeSetName=ctx.unique_name("sim2real-xsvc-csnest-cs-"))["Id"]
    root = _wait_change_set(cf, root_cs, timeout_s=_cap(ctx, 300.0))
    assert root["Status"] == "CREATE_COMPLETE", f"root change set: {root.get('StatusReason')!r}"
    assert root.get("IncludeNestedStacks") is True, root.get("IncludeNestedStacks")
    assert ("ParentChangeSetId" in root, "RootChangeSetId" in root) == (False, False), (
        f"the root names no parent or root: {root.get('ParentChangeSetId')!r} "
        f"{root.get('RootChangeSetId')!r}")

    child_cs = _stack_change(root, "Child")["ChangeSetId"]
    child = _wait_change_set(cf, child_cs, timeout_s=_cap(ctx, 180.0))
    assert child["Status"] == "CREATE_COMPLETE", f"child change set: {child.get('StatusReason')!r}"
    assert (child["StackId"], child["ParentChangeSetId"], child["RootChangeSetId"]) == (
        child_stack, root_cs, root_cs), child

    grand_cs = _stack_change(child, "Grand")["ChangeSetId"]
    grand = _wait_change_set(cf, grand_cs, timeout_s=_cap(ctx, 180.0))
    assert grand["Status"] == "CREATE_COMPLETE", f"grandchild change set: {grand.get('StatusReason')!r}"
    assert (grand["StackId"], grand["ParentChangeSetId"], grand["RootChangeSetId"]) == (
        grand_stack, child_cs, root_cs), grand
    assert [(c["ResourceChange"]["LogicalResourceId"], c["ResourceChange"]["Action"])
            for c in grand["Changes"]] == [("G2", "Add")], grand["Changes"]

    listed = {s["ChangeSetId"]: s for s in cf.list_change_sets(StackName=grand_stack)["Summaries"]}
    assert (listed[grand_cs].get("ParentChangeSetId"), listed[grand_cs].get("RootChangeSetId")) == (
        child_cs, root_cs), listed[grand_cs]

    # Deleting the root change set deletes the whole tree.
    cf.delete_change_set(ChangeSetName=root_cs)
    for cs_id, stack_id in ((child_cs, child_stack), (grand_cs, grand_stack)):
        _wait_unlisted(cf, stack_id, cs_id)
        gone = _error(lambda c=cs_id: cf.describe_change_set(ChangeSetName=c))
        assert gone == ("ChangeSetNotFound", f"ChangeSet [{cs_id}] does not exist"), gone


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
