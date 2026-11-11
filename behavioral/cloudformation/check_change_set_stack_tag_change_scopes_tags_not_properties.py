"""change-set-stack-tag-change-scopes-tags-not-properties."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "change-set-stack-tag-change-scopes-tags-not-properties"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {
    "Param": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": "v"}},
    "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
}})


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


def _by_logical_id(cs):
    """The change set's ResourceChange entries keyed by LogicalResourceId."""
    return {c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in cs["Changes"]}

@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Changing only the stack Tags yields a Modify on the taggable resource with Scope ["Tags"] and a
    Tags-attribute detail, no change for the untaggable handle, and execution keeps the physical id.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ResourceChange.html
    """
    cf = ctx.client("cloudformation")
    v1 = [{"Key": "sim2real", "Value": CHECK}, {"Key": "stage", "Value": "one"}]
    v2 = [{"Key": "sim2real", "Value": CHECK}, {"Key": "stage", "Value": "two"}]
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-cstags-"),
                               TemplateBody=_TEMPLATE, Tags=v1)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"
    param_before = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Param")[
        "StackResourceDetail"]["PhysicalResourceId"]

    cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                 UsePreviousTemplate=True, Tags=v2,
                                 ChangeSetName=ctx.unique_name("sim2real-behav-cstags-cs-"))["Id"]
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    assert sorted((t["Key"], t["Value"]) for t in cs["Tags"]) == sorted(
        (t["Key"], t["Value"]) for t in v2), cs["Tags"]
    changes = _by_logical_id(cs)
    assert sorted(changes) == ["Param"], f"only the taggable resource changes: {sorted(changes)!r}"
    rc = changes["Param"]
    assert (rc["Action"], rc.get("Replacement"), rc["Scope"]) == ("Modify", "False", ["Tags"]), rc
    details = [(d["Target"]["Attribute"], d["Target"].get("RequiresRecreation"), d.get("Evaluation"),
                d.get("ChangeSource")) for d in rc["Details"]]
    assert details == [("Tags", "Never", "Static", None)], details

    cf.execute_change_set(ChangeSetName=cs_id)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"execute: {stack['StackStatus']!r}"
    after = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Param")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert after == param_before, f"a tag-only change must not replace: {param_before!r} -> {after!r}"
    assert {t["Key"]: t["Value"] for t in stack["Tags"]}["stage"] == "two", stack["Tags"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
