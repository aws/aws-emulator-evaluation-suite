"""change-set-replacement-vs-modify-classification."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-replacement-vs-modify-classification"
GROUP = 'change_sets'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _wait_change_set(cf, stack, cs_name, *, timeout_s=300, interval_s=5):
    """Poll DescribeChangeSet until Status is terminal; return the response."""
    deadline = time.monotonic() + timeout_s
    while True:
        resp = cf.describe_change_set(StackName=stack, ChangeSetName=cs_name)
        if resp["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"change set {cs_name} stuck in {resp['Status']!r} after {timeout_s}s"
            )
        time.sleep(interval_s)


def _param_exists(ssm, name):
    """True iff the SSM parameter exists (ParameterNotFound => False)."""
    try:
        ssm.get_parameter(Name=name)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ParameterNotFound":
            return False
        raise


def _template(replaced_name, modified_name, mutable_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            # Name is create-only for AWS::SSM::Parameter -> changing it replaces.
            "Replaced": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": replaced_name, "Type": "String", "Value": "static"},
            },
            # Value is updatable in place -> changing it modifies, and the Name
            # is deliberately held constant so this resource is never replaced.
            "Modified": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": modified_name, "Type": "String",
                               "Value": mutable_value},
            },
        },
    })


def _change_by_logical_id(changes):
    out = {}
    for c in changes:
        rc = c["ResourceChange"]
        out[rc["LogicalResourceId"]] = rc
    return out


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A change set touching a create-only and an updatable property reports Replacement True/Always
    and False/Never; executing it replaces the first (old one destroyed) and keeps the second's id.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack = ctx.unique_name("sim2real-behav-csrepl-")
    name_v1 = "/" + ctx.unique_name("sim2real-behav-csrepl-a-")
    name_v2 = "/" + ctx.unique_name("sim2real-behav-csrepl-b-")
    stable_name = "/" + ctx.unique_name("sim2real-behav-csrepl-mod-")

    cf.create_stack(
        StackName=stack, TemplateBody=_template(name_v1, stable_name, "before"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )
    before = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cf.list_stack_resources(StackName=stack)["StackResourceSummaries"]
    }
    assert set(before) == {"Replaced", "Modified"}, before

    cs_name = ctx.unique_name("sim2real-behav-csrepl-cs-")
    cf.create_change_set(
        StackName=stack, ChangeSetName=cs_name,
        TemplateBody=_template(name_v2, stable_name, "after"),
    )
    ctx.on_cleanup(lambda: cf.delete_change_set(StackName=stack, ChangeSetName=cs_name))
    cs = _wait_change_set(cf, stack, cs_name)
    assert cs["Status"] == "CREATE_COMPLETE", f"change set failed: {cs.get('StatusReason')!r}"

    changes = _change_by_logical_id(cs.get("Changes", []))
    assert set(changes) == {"Replaced", "Modified"}, (
        f"the change set must report both touched resources, got {sorted(changes)}"
    )

    repl = changes["Replaced"]
    assert repl["Action"] == "Modify", f"expected Action=Modify, got {repl['Action']!r}"
    assert repl.get("Replacement") == "True", (
        f"changing the create-only property Name must be classified Replacement=True, got "
        f"{repl.get('Replacement')!r}"
    )
    assert "Properties" in repl.get("Scope", []), (
        f"Scope must name the changed section, got {repl.get('Scope')!r}"
    )
    repl_targets = {
        d["Target"]["Name"]: d for d in repl.get("Details", []) if d.get("Target", {}).get("Name")
    }
    assert "Name" in repl_targets, (
        f"Details must attribute the change to the Name property, got {repl.get('Details')!r}"
    )
    detail = repl_targets["Name"]
    assert detail["Target"]["Attribute"] == "Properties", detail
    assert detail["Target"]["RequiresRecreation"] == "Always", (
        f"a create-only property must report RequiresRecreation=Always, got "
        f"{detail['Target']['RequiresRecreation']!r}"
    )
    assert detail.get("Evaluation") == "Static", (
        f"a literal property change is statically evaluable, got {detail.get('Evaluation')!r}"
    )
    assert detail.get("ChangeSource") == "DirectModification", (
        f"expected ChangeSource=DirectModification, got {detail.get('ChangeSource')!r}"
    )

    mod = changes["Modified"]
    assert mod["Action"] == "Modify", f"expected Action=Modify, got {mod['Action']!r}"
    assert mod.get("Replacement") == "False", (
        f"changing an updatable property must be classified Replacement=False, got "
        f"{mod.get('Replacement')!r}"
    )
    mod_targets = {
        d["Target"]["Name"]: d for d in mod.get("Details", []) if d.get("Target", {}).get("Name")
    }
    assert "Value" in mod_targets, (
        f"Details must attribute the change to the Value property, got {mod.get('Details')!r}"
    )
    assert mod_targets["Value"]["Target"]["RequiresRecreation"] == "Never", (
        f"an updatable property must report RequiresRecreation=Never, got "
        f"{mod_targets['Value']['Target']['RequiresRecreation']!r}"
    )

    # The prediction must match what execution actually does.
    cf.execute_change_set(StackName=stack, ChangeSetName=cs_name)
    executed = _wait_terminal(cf, stack)
    assert executed["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {executed['StackStatus']!r}: "
        f"{executed.get('StackStatusReason')!r}"
    )
    after = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cf.list_stack_resources(StackName=stack)["StackResourceSummaries"]
    }
    assert after["Replaced"] != before["Replaced"], (
        f"Replacement=True must actually change the physical id, still {after['Replaced']!r}"
    )
    assert after["Modified"] == before["Modified"], (
        f"Replacement=False must preserve the physical id, {before['Modified']!r} -> "
        f"{after['Modified']!r}"
    )
    assert not _param_exists(ssm, name_v1), (
        f"the replaced physical resource {name_v1} must be destroyed after the replacement"
    )
    assert _param_exists(ssm, name_v2), f"the replacement resource {name_v2} must exist"
    assert ssm.get_parameter(Name=stable_name)["Parameter"]["Value"] == "after", (
        "the in-place modification must have been applied to the same physical resource"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
