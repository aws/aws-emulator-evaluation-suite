"""change-set-include-property-values-add-modify-remove-contexts."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "change-set-include-property-values-add-modify-remove-contexts"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _param(name, value):
    return {"Type": "AWS::SSM::Parameter",
            "Properties": {"Name": name, "Type": "String", "Value": value}}


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
    """IncludePropertyValues gives exact Before/AfterValue on a Modify and Before/AfterContext JSON on
    Modify, Add (no BeforeContext) and Remove (no AfterContext); only the Modify carries Replacement.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ResourceChange.html
    """
    cf = ctx.client("cloudformation")
    keep = "/" + ctx.unique_name("sim2real-behav-csipv-keep-")
    gone = "/" + ctx.unique_name("sim2real-behav-csipv-gone-")
    new = "/" + ctx.unique_name("sim2real-behav-csipv-new-")
    v1 = json.dumps({"Resources": {"Keep": _param(keep, "k1"), "Gone": _param(gone, "g1")}})
    v2 = json.dumps({"Resources": {"Keep": _param(keep, "k2"), "New": _param(new, "n1")}})

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-csipv-"),
                               TemplateBody=v1, Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"

    cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE", TemplateBody=v2,
                                 ChangeSetName=ctx.unique_name("sim2real-behav-csipv-cs-"))["Id"]
    cs = _wait_change_set(cf, cs_id, IncludePropertyValues=True, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    changes = _by_logical_id(cs)
    assert {k: v["Action"] for k, v in changes.items()} == {
        "Keep": "Modify", "Gone": "Remove", "New": "Add"}, changes

    def props(name, value):
        return {"Properties": {"Name": name, "Type": "String", "Value": value}}

    mod = changes["Keep"]
    assert json.loads(mod["BeforeContext"]) == props(keep, "k1"), mod.get("BeforeContext")
    assert json.loads(mod["AfterContext"]) == props(keep, "k2"), mod.get("AfterContext")
    assert mod.get("Replacement") == "False", f"Modify Replacement: {mod.get('Replacement')!r}"
    targets = [(d["Target"].get("Path"), d["Target"].get("BeforeValue"),
                d["Target"].get("AfterValue"), d["Target"].get("AttributeChangeType"))
               for d in mod["Details"]]
    assert targets == [("/Properties/Value", "k1", "k2", "Modify")], targets

    add = changes["New"]
    assert json.loads(add["AfterContext"]) == props(new, "n1"), add.get("AfterContext")
    assert "BeforeContext" not in add, f"an Add has no BeforeContext: {add.get('BeforeContext')!r}"
    assert "Replacement" not in add, f"an Add has no Replacement: {add.get('Replacement')!r}"
    assert add.get("PhysicalResourceId") is None, add.get("PhysicalResourceId")

    rem = changes["Gone"]
    assert json.loads(rem["BeforeContext"]) == props(gone, "g1"), rem.get("BeforeContext")
    assert "AfterContext" not in rem, f"a Remove has no AfterContext: {rem.get('AfterContext')!r}"
    assert "Replacement" not in rem, f"a Remove has no Replacement: {rem.get('Replacement')!r}"
    assert (rem.get("PhysicalResourceId"), rem.get("PolicyAction")) == (gone, "Delete"), rem

    # Without the flag the same change set carries no contexts or values.
    plain = _by_logical_id(cf.describe_change_set(ChangeSetName=cs_id))
    leaked = {k: sorted({"BeforeContext", "AfterContext"} & set(v)) for k, v in plain.items()}
    assert leaked == {"Keep": [], "Gone": [], "New": []}, leaked


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
