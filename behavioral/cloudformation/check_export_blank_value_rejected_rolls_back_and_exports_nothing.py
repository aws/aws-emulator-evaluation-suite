"""export-blank-value-rejected-rolls-back-and-exports-nothing."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "export-blank-value-rejected-rolls-back-and-exports-nothing"
GROUP = "cloudformation"
SERVICES = ["cloudformation"]

_HANDLE = {"Type": "AWS::CloudFormation::WaitConditionHandle"}


def _template(value: str, export_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": _HANDLE},
        "Outputs": {"Shared": {"Value": value, "Export": {"Name": export_name}}},
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


def _export_values(cf, names: set) -> dict:
    """{export name: value} for the given names, paging the account's whole export list."""
    found = {}
    for page in cf.get_paginator("list_exports").paginate():
        for export in page["Exports"]:
            if export["Name"] in names:
                found[export["Name"]] = export["Value"]
    return found


def _stack_reason(cf, stack_id: str, stack_name: str, status: str) -> list:
    """Every ResourceStatusReason the stack's own events carry for ``status``."""
    reasons = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if event["LogicalResourceId"] == stack_name and event["ResourceStatus"] == status:
                reasons.append(event.get("ResourceStatusReason"))
    return reasons


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An export whose value is empty or whitespace-only rolls the create back and is never listed,
    while the same template exporting a non-blank value creates and lists it."""
    cf = ctx.client("cloudformation")
    cases = {"empty": "", "blank": "   ", "control": "sim2real-shared-value"}
    stacks = {}
    for key, value in cases.items():
        name = ctx.unique_name(f"sim2real-behav-exp{key}-")
        export_name = ctx.unique_name(f"sim2real-behav-exp{key}-")
        stack_id = cf.create_stack(StackName=name, TemplateBody=_template(value, export_name))["StackId"]
        ctx.on_cleanup(_delete_stack(cf, stack_id))
        stacks[key] = (name, stack_id, export_name)

    final = {key: _wait(cf, stack_id) for key, (_, stack_id, _) in stacks.items()}
    assert final["control"]["StackStatus"] == "CREATE_COMPLETE", (
        f"control stack ended {final['control']['StackStatus']!r}"
    )
    outputs = final["control"].get("Outputs", [])
    assert [(o["OutputKey"], o["OutputValue"], o.get("ExportName")) for o in outputs] == [
        ("Shared", cases["control"], stacks["control"][2])
    ], f"control stack outputs {outputs!r}"

    for key in ("empty", "blank"):
        name, stack_id, _ = stacks[key]
        status = final[key]["StackStatus"]
        assert status == "ROLLBACK_COMPLETE", f"{key} export stack ended {status!r}"
        assert "Outputs" not in final[key], f"{key} export stack shows outputs {final[key]['Outputs']!r}"
        reasons = _stack_reason(cf, stack_id, name, "ROLLBACK_IN_PROGRESS")
        expected = ("Cannot export output Shared.  Exported values must not be empty or "
                    "whitespace-only.. Rollback requested by user.")
        assert reasons == [expected], f"{key} export stack rollback reasons {reasons!r}"

    exported = _export_values(cf, {export_name for _, _, export_name in stacks.values()})
    assert exported == {stacks["control"][2]: cases["control"]}, (
        f"exports listed for the three names: {exported!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
