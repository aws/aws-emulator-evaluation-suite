"""if-guarded-ref-follows-condition-flips-through-change-sets."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "if-guarded-ref-follows-condition-flips-through-change-sets"
GROUP = "cloudformation"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"Make": {"Type": "String", "AllowedValues": ["yes", "no"]}},
    "Conditions": {"MakeIt": {"Fn::Equals": [{"Ref": "Make"}, "yes"]}},
    "Resources": {
        "Always": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        "Maybe": {"Type": "AWS::CloudFormation::WaitConditionHandle", "Condition": "MakeIt"},
    },
    "Outputs": {
        "Guarded": {"Value": {"Fn::If": ["MakeIt", {"Ref": "Maybe"}, "none"]}},
        "OnlyWhenMade": {"Condition": "MakeIt", "Value": {"Ref": "Maybe"}},
    },
})


def _wait(cf, stack_id: str, budget_s: float = 300.0) -> dict:
    """The stack once it leaves every *_IN_PROGRESS state."""
    deadline = time.monotonic() + budget_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {budget_s}s")
        time.sleep(3)


def _delete_stack(cf, stack_id: str):
    """A cleanup that deletes the stack and raises unless it reaches DELETE_COMPLETE."""

    def run_delete() -> None:
        cf.delete_stack(StackName=stack_id)
        status = _wait(cf, stack_id)["StackStatus"]
        if status != "DELETE_COMPLETE":
            raise AssertionError(f"stack delete ended {status!r}")

    return run_delete


def _change_set(cf, stack_id: str, name: str, make: str) -> list:
    """Create an update change set setting Make and return its resource changes once complete."""
    cf.create_change_set(StackName=stack_id, ChangeSetName=name, UsePreviousTemplate=True,
                         ChangeSetType="UPDATE",
                         Parameters=[{"ParameterKey": "Make", "ParameterValue": make}])
    deadline = time.monotonic() + 180
    while True:
        cs = cf.describe_change_set(StackName=stack_id, ChangeSetName=name)
        if cs["Status"] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after 180s")
        time.sleep(3)
    assert cs["Status"] == "CREATE_COMPLETE", f"change set {cs['Status']!r}: {cs.get('StatusReason')!r}"
    assert cs["ExecutionStatus"] == "AVAILABLE", f"change set execution status {cs['ExecutionStatus']!r}"
    return [
        (c["ResourceChange"]["Action"], c["ResourceChange"]["LogicalResourceId"],
         c["ResourceChange"]["ResourceType"])
        for c in cs["Changes"]
    ]


def _execute(cf, stack_id: str, name: str) -> dict:
    cf.execute_change_set(StackName=stack_id, ChangeSetName=name)
    stack = _wait(cf, stack_id)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"update ended {stack['StackStatus']!r}"
    return stack


def _state(cf, stack: dict) -> tuple:
    """(outputs by key, physical ids by logical id) of the stack."""
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    resources = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cf.describe_stack_resources(StackName=stack["StackId"])["StackResources"]
    }
    return outputs, resources


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Flipping a condition through change sets adds then removes its resource, and an Fn::If-guarded
    Ref and a conditional output follow the flip: 'none' and absent, then the resource id, then back."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cflip-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=_TEMPLATE,
                               Parameters=[{"ParameterKey": "Make", "ParameterValue": "no"}])["StackId"]
    ctx.on_cleanup(_delete_stack(cf, stack_id))
    stack = _wait(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"create ended {stack['StackStatus']!r}"
    outputs, resources = _state(cf, stack)
    assert outputs == {"Guarded": "none"}, f"outputs with the condition false: {outputs!r}"
    assert sorted(resources) == ["Always"], f"resources with the condition false: {sorted(resources)!r}"
    always = resources["Always"]

    changes = _change_set(cf, stack_id, "sim2real-make-yes", "yes")
    assert changes == [("Add", "Maybe", "AWS::CloudFormation::WaitConditionHandle")], (
        f"changes when the condition turns true: {changes!r}"
    )
    outputs, resources = _state(cf, _execute(cf, stack_id, "sim2real-make-yes"))
    assert sorted(resources) == ["Always", "Maybe"], f"resources after the flip: {sorted(resources)!r}"
    assert resources["Always"] == always, "the unconditional resource changed physical id"
    # The handle's id is a presigned URL, so messages report relations rather than its value.
    assert sorted(outputs) == ["Guarded", "OnlyWhenMade"], f"outputs with the condition true: {sorted(outputs)!r}"
    assert outputs["Guarded"] == resources["Maybe"], "Guarded output is not the Maybe handle's id"
    assert outputs["OnlyWhenMade"] == resources["Maybe"], "OnlyWhenMade output is not the Maybe handle's id"

    changes = _change_set(cf, stack_id, "sim2real-make-no", "no")
    assert changes == [("Remove", "Maybe", "AWS::CloudFormation::WaitConditionHandle")], (
        f"changes when the condition turns false: {changes!r}"
    )
    outputs, resources = _state(cf, _execute(cf, stack_id, "sim2real-make-no"))
    assert outputs == {"Guarded": "none"}, f"outputs after the flip back: {outputs!r}"
    assert sorted(resources) == ["Always"], f"resources after the flip back: {sorted(resources)!r}"
    assert resources["Always"] == always, "the unconditional resource changed physical id"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
