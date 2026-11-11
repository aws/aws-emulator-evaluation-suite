"""stack-nested-child-update-failure-reason-chain."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-nested-child-update-failure-reason-chain"
GROUP = "nested-stacks"
SERVICES = ["cloudformation", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A nested child failing its update surfaces in the parent as the exact Embedded stack reason
    naming the child id and the child's own reason, and both stacks roll back to UPDATE_ROLLBACK_COMPLETE.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-nested-stacks.html"""
    cfn, s3 = ctx.client("cloudformation"), ctx.client("s3")
    bucket = _bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="child-v1.json", Body=_child(fail=False).encode())
    s3.put_object(Bucket=bucket, Key="child-v2.json", Body=_child(fail=True).encode())

    parent_name = ctx.unique_name("sim2real-cfn-nest-")
    parent = _create(ctx, cfn, parent_name, _parent(_url(s3, bucket, "child-v1.json")))
    assert _settle(cfn, parent, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"parent create ended {_stack(cfn, parent)!r}"
    child = cfn.describe_stack_resource(StackName=parent, LogicalResourceId="Child")["StackResourceDetail"]["PhysicalResourceId"]
    assert re.fullmatch(rf"arn:aws[a-z-]*:cloudformation:{ctx.region}:{ctx.account}:stack/{parent_name}-Child-[A-Za-z0-9]+/"
                        r"[0-9a-f-]{36}", child), f"the nested stack id {child!r}"
    before_parent, before_child = len(_events(cfn, parent)), len(_events(cfn, child))

    cfn.update_stack(StackName=parent, TemplateBody=_parent(_url(s3, bucket, "child-v2.json")))
    assert _settle(cfn, parent, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"parent update ended {_stack(cfn, parent)!r}"
    assert _settle(cfn, child, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"child ended {_stack(cfn, child)!r}"

    prows = _rows(_events(cfn, parent)[before_parent:])
    failed = [r for r in prows if r[:2] == ("Child", "UPDATE_FAILED")]
    assert failed == [("Child", "UPDATE_FAILED",
                       f"Embedded stack {child} was not successfully updated. Currently in "
                       "UPDATE_ROLLBACK_IN_PROGRESS with reason: The following resource(s) failed to create: [Fast]. ")], (
        f"the parent's event for the failed child: {failed!r}")
    assert _of(prows, parent_name)[:2] == [
        ("UPDATE_IN_PROGRESS", "User Initiated"),
        ("UPDATE_ROLLBACK_IN_PROGRESS", "The following resource(s) failed to update: [Child]. "),
    ], f"parent stack-level events: {_of(prows, parent_name)!r}"

    crows = _rows(_events(cfn, child)[before_child:])
    assert [r for r in crows if r[:2] == ("Fast", "CREATE_FAILED")] == [
        ("Fast", "CREATE_FAILED", "WaitCondition timed out. Received 0 conditions when expecting 1")], (
        f"the child's own failure: {crows!r}")
    kept = [r["LogicalResourceId"] for r in cfn.describe_stack_resources(StackName=child)["StackResources"]]
    assert kept == ["Handle"], f"the child's resources after the rollback: {kept!r}"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, parent).get("Outputs", [])}
    assert outputs == {"Version": "v1"}, f"the parent must read the rolled-back child: {outputs!r}"


def _child(*, fail: bool) -> str:
    """The child: a handle and its version output; ``fail`` adds a wait condition that times out."""
    res: dict = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if fail:
        res["Fast"] = {"Type": "AWS::CloudFormation::WaitCondition",
                       "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "1", "Count": 1}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res,
                       "Outputs": {"Version": {"Value": "v2" if fail else "v1"}}})


def _parent(url: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Child": {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": url}}},
        "Outputs": {"Version": {"Value": {"Fn::GetAtt": ["Child", "Outputs.Version"]}}},
    })


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows(events: list[dict], *keys: str) -> list[tuple]:
    """``(LogicalResourceId, ResourceStatus, ResourceStatusReason, *keys)`` per event; absent is None."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"),
             *(e.get(k) for k in keys)) for e in events]


def _of(rows: list[tuple], logical_id: str) -> list[tuple]:
    """The rows of one logical resource, without the logical id."""
    return [r[1:] for r in rows if r[0] == logical_id]


def _bucket(ctx, s3) -> str:
    """A fresh bucket in the stack's region, emptied and deleted at cleanup."""
    name = ctx.unique_name("sim2real-cfn-")
    kwargs: dict = {"Bucket": name}
    # us-east-1 is the one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAGS})
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _url(s3, bucket: str, key: str) -> str:
    """The object's regional path-style S3 URL; CloudFormation reads it with the caller's credentials."""
    return f"https://s3.{s3.meta.region_name}.amazonaws.com/{bucket}/{key}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
