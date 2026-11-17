"""outputs-only-change-set-previews-no-resource-change."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'outputs-only-change-set-previews-no-resource-change'
GROUP = 'change_sets'
SERVICES = ['cloudformation']

_SETTLED_STACK = (
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
)
_SETTLED_CHANGE_SET = ("CREATE_COMPLETE", "FAILED", "DELETE_COMPLETE", "DELETE_FAILED")


def _body(*, second_wave: bool) -> str:
    """The stack template; ``second_wave`` adds outputs and changes nothing else."""
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Keeper": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Type": "StringList", "Value": "north,south,east"},
            }
        },
        "Outputs": {"KeeperName": {"Value": {"Ref": "Keeper"}}},
    }
    if second_wave:
        doc["Outputs"]["KeeperLabel"] = {
            "Value": {"Fn::Join": [":", [{"Ref": "Keeper"}, "wave2"]]}
        }
        doc["Outputs"]["KeeperRegion"] = {"Value": {"Fn::Sub": "${AWS::Region}/${Keeper}"}}
    return json.dumps(doc)


def _described(cf, stack: str) -> dict:
    """The stack's description."""
    return cf.describe_stacks(StackName=stack)["Stacks"][0]


def _settle_stack(cf, stack: str, *, budget_s: float = 420.0) -> dict:
    """Poll until the stack reports a settled status; raise when the budget runs out."""
    deadline = time.monotonic() + budget_s
    while True:
        described = _described(cf, stack)
        if described["StackStatus"] in _SETTLED_STACK:
            return described
        if time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack!r} still at {described['StackStatus']!r} after {budget_s}s"
            )
        time.sleep(3)


def _settle_change_set(cf, change_set: str, *, budget_s: float = 300.0) -> dict:
    """Poll until the change set reports a settled status; raise when the budget runs out."""
    deadline = time.monotonic() + budget_s
    while True:
        described = cf.describe_change_set(ChangeSetName=change_set)
        if described["Status"] in _SETTLED_CHANGE_SET:
            return described
        if time.monotonic() > deadline:
            raise AssertionError(
                f"change set still at {described['Status']!r} after {budget_s}s"
            )
        time.sleep(3)


def _teardown(cf, stack: str):
    """A cleanup that deletes the stack and waits for it; a failed delete raises."""

    def undo() -> None:
        try:
            cf.delete_stack(StackName=stack)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        deadline = time.monotonic() + 420.0
        while True:
            try:
                status = _described(cf, stack)["StackStatus"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ValidationError":
                    return
                raise
            if status == "DELETE_COMPLETE":
                return
            if time.monotonic() > deadline:
                raise AssertionError(f"stack {stack!r} still at {status!r} after the delete")
            time.sleep(3)

    return undo


def _outputs(described: dict) -> dict:
    """The stack's outputs as a key -> value mapping."""
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _physical_ids(cf, stack: str) -> dict:
    """Each logical id in the stack mapped to its physical id."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cf.describe_stack_resources(StackName=stack)["StackResources"]
    }


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A change set whose template differs only in its Outputs section previews an empty
    change list, and executing it resolves the new outputs without replacing the resource.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-changesets.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/outputs-section-structure.html
    """
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-behav-cfnoutonly-")
    change_set = ctx.unique_name("sim2real-behav-cfncs-")

    cf.create_stack(
        StackName=stack,
        TemplateBody=_body(second_wave=False),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(cf, stack))
    created = _settle_stack(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"stack settled at {created['StackStatus']!r}, expected CREATE_COMPLETE"
        f" ({created.get('StackStatusReason')!r})"
    )
    before = _physical_ids(cf, stack)
    assert _outputs(created) == {"KeeperName": before["Keeper"]}, (
        f"outputs before the change set were {_outputs(created)!r},"
        f" expected only KeeperName={before['Keeper']!r}"
    )

    handle = cf.create_change_set(
        StackName=stack,
        ChangeSetName=change_set,
        ChangeSetType="UPDATE",
        TemplateBody=_body(second_wave=True),
    )["Id"]
    previewed = _settle_change_set(cf, handle)
    assert previewed["Status"] == "CREATE_COMPLETE", (
        f"the outputs-only change set settled at {previewed['Status']!r},"
        f" expected CREATE_COMPLETE ({previewed.get('StatusReason')!r})"
    )
    assert previewed["ExecutionStatus"] == "AVAILABLE", (
        f"execution status was {previewed['ExecutionStatus']!r}, expected AVAILABLE"
    )
    assert previewed["Changes"] == [], (
        f"an outputs-only diff previewed {len(previewed['Changes'])} resource change(s):"
        f" {previewed['Changes']!r}"
    )

    cf.execute_change_set(ChangeSetName=handle)
    executed = _settle_stack(cf, stack)
    assert executed["StackStatus"] == "UPDATE_COMPLETE", (
        f"executing the outputs-only change set settled at {executed['StackStatus']!r},"
        f" expected UPDATE_COMPLETE ({executed.get('StackStatusReason')!r})"
    )

    after = _physical_ids(cf, stack)
    assert after == before, (
        f"the resource moved from {before!r} to {after!r}; an outputs-only change replaces nothing"
    )
    kept = before["Keeper"]
    assert _outputs(executed) == {
        "KeeperName": kept,
        "KeeperLabel": f"{kept}:wave2",
        "KeeperRegion": f"{ctx.region}/{kept}",
    }, f"outputs after execution were {_outputs(executed)!r}, keeper {kept!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
