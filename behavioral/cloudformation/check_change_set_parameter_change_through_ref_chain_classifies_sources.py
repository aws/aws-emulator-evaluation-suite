"""change-set-parameter-change-through-ref-chain-classifies-sources."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "change-set-parameter-change-through-ref-chain-classifies-sources"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

_TEMPLATE = json.dumps({
    "Parameters": {"Prefix": {"Type": "String"}, "Fixed": {"Type": "String"}},
    "Resources": {
        # Name is create-only: a new Prefix replaces A, so A's Ref (its name) changes.
        "A": {"Type": "AWS::SSM::Parameter",
              "Properties": {"Name": {"Fn::Sub": "/${Prefix}-a"}, "Type": "String", "Value": "a"}},
        # B's create-only Name is built from A's Ref.
        "B": {"Type": "AWS::SSM::Parameter",
              "Properties": {"Name": {"Fn::Sub": "${A}-b"}, "Type": "String", "Value": "b"}},
        # C's updatable Value is A's Ref.
        "C": {"Type": "AWS::SSM::Parameter",
              "Properties": {"Name": {"Fn::Sub": "/${Fixed}-c"}, "Type": "String",
                             "Value": {"Ref": "A"}}},
    },
})


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

def _details(rc):
    return sorted((d["Target"].get("Name"), d["Target"].get("RequiresRecreation"),
                   d.get("Evaluation"), d.get("ChangeSource"), d.get("CausingEntity"))
                  for d in rc["Details"])


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A parameter change flowing through a Ref chain is attributed ParameterReference at the root and
    ResourceReference downstream, B's Replacement is True because its own Name is create-only, and
    execution matches the preview.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ResourceChangeDetail.html
    """
    cf = ctx.client("cloudformation")
    p1 = ctx.unique_name("sim2real-behav-csdyn-")
    p2 = ctx.unique_name("sim2real-behav-csdyn-")
    fixed = ctx.unique_name("sim2real-behav-csdyn-")

    def params(prefix):
        return [{"ParameterKey": "Prefix", "ParameterValue": prefix},
                {"ParameterKey": "Fixed", "ParameterValue": fixed}]

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-csdyn-"),
                               TemplateBody=_TEMPLATE, Parameters=params(p1), Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"

    def physical():
        return {r["LogicalResourceId"]: r["PhysicalResourceId"]
                for r in cf.list_stack_resources(StackName=stack_id)["StackResourceSummaries"]}

    before = physical()
    assert before == {"A": f"/{p1}-a", "B": f"/{p1}-a-b", "C": f"/{fixed}-c"}, before

    cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                 UsePreviousTemplate=True, Parameters=params(p2),
                                 ChangeSetName=ctx.unique_name("sim2real-behav-csdyn-cs-"))["Id"]
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    changes = _by_logical_id(cs)
    got = {k: (v["Action"], v.get("Replacement")) for k, v in changes.items()}
    assert got == {"A": ("Modify", "True"), "B": ("Modify", "True"),
                   "C": ("Modify", "False")}, got

    assert _details(changes["A"]) == [
        ("Name", "Always", "Dynamic", "DirectModification", None),
        ("Name", "Always", "Static", "ParameterReference", "Prefix"),
    ], _details(changes["A"])
    assert _details(changes["B"]) == [
        ("Name", "Always", "Static", "ResourceReference", "A"),
    ], _details(changes["B"])
    assert _details(changes["C"]) == [
        ("Value", "Never", "Static", "ResourceReference", "A"),
    ], _details(changes["C"])

    # The executed update replaces A and B (their names change) and keeps C's physical id.
    cf.execute_change_set(ChangeSetName=cs_id)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"execute: {stack['StackStatus']!r} {stack.get('StackStatusReason')!r}")
    after = physical()
    assert after == {"A": f"/{p2}-a", "B": f"/{p2}-a-b", "C": f"/{fixed}-c"}, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
