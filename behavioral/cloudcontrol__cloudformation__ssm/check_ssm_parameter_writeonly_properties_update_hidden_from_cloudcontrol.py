"""ssm-parameter-writeonly-properties-update-hidden-from-cloudcontrol."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-parameter-writeonly-properties-update-hidden-from-cloudcontrol"
GROUP = "deploy"
SERVICES = ["cloudcontrol", "cloudformation", "ssm"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _template(param_name: str, description: str, allowed_pattern: str, tier: str) -> str:
    return json.dumps({
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": param_name,
                    "Type": "String",
                    "Value": "abc123",
                    "Description": description,
                    "AllowedPattern": allowed_pattern,
                    "Tier": tier,
                },
            }
        }
    })


def _wait_terminal(cf, stack, *, timeout_s=300.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        s = cf.describe_stacks(StackName=stack)["Stacks"][0]
        if s["StackStatus"] in _TERMINAL:
            return s
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack} stuck at {s['StackStatus']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _wait_change_set(cf, stack, name, *, timeout_s=180.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        r = cf.describe_change_set(StackName=stack, ChangeSetName=name)
        if r["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return r
        if time.monotonic() >= deadline:
            raise AssertionError(f"change set {name} stuck at {r['Status']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _describe_param(ssm, name):
    return ssm.describe_parameters(ParameterFilters=[{"Key": "Name", "Values": [name]}])[
        "Parameters"
    ][0]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_stack(cf, stack: str) -> None:
    """Delete the stack and wait; raise unless it ends DELETE_COMPLETE."""
    # Wait on the stack id: a deleted stack answers DescribeStacks by id with DELETE_COMPLETE,
    # and by name with "does not exist".
    stack_id = cf.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    cf.delete_stack(StackName=stack_id)
    final = _wait_terminal(cf, stack_id)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack} delete ended {final['StackStatus']!r}: {final.get('StackStatusReason')!r}"
        )


def _assert_populated(props: dict, param_name: str, when: str) -> None:
    """The model carries the readable Name, Type and Value, so an absence in it can fail."""
    readable = (props.get("Name"), props.get("Type"), props.get("Value"))
    assert readable == (param_name, "String", "abc123"), (
        f"{when}: GetResource model lacks the readable Name/Type/Value of the parameter: {props!r}"
    )


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CFN-declared SSM Parameter's Description, AllowedPattern and Tier take effect but never
    appear in Cloud Control's ResourceModel, and a change set touching only them is classified
    Replacement=False/RequiresRecreation=Never per property and applies in place.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    cc = ctx.client("cloudcontrol")

    stack = ctx.unique_name("sim2real-behav-ssmwo-")
    param_name = ctx.unique_name("sim2real-behav-ssmwo-param-")

    cf.create_stack(
        StackName=stack,
        TemplateBody=_template(param_name, "desc-v1", "^[a-zA-Z0-9]+$", "Standard"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )

    before = _describe_param(ssm, param_name)
    assert before["Description"] == "desc-v1", f"Description did not take effect: {before!r}"
    assert before["AllowedPattern"] == "^[a-zA-Z0-9]+$", f"AllowedPattern did not take effect: {before!r}"
    assert before["Tier"] == "Standard", f"Tier did not take effect: {before!r}"
    version_before = before["Version"]

    physical_id = cf.list_stack_resources(StackName=stack)["StackResourceSummaries"][0][
        "PhysicalResourceId"
    ]
    model_before = cc.get_resource(TypeName="AWS::SSM::Parameter", Identifier=physical_id)
    props_before = json.loads(model_before["ResourceDescription"]["Properties"])
    _assert_populated(props_before, param_name, "before the update")
    for write_only in ("Description", "AllowedPattern", "Tier"):
        assert write_only not in props_before, (
            f"GetResource must never report the write-only {write_only}, got {props_before!r}"
        )

    cs_name = ctx.unique_name("sim2real-behav-ssmwo-cs-")
    cf.create_change_set(
        StackName=stack, ChangeSetName=cs_name,
        TemplateBody=_template(param_name, "desc-v2", "^[a-z0-9]+$", "Advanced"),
    )
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_change_set(StackName=stack, ChangeSetName=cs_name),
        "ChangeSetNotFound",
    ))
    cs = _wait_change_set(cf, stack, cs_name)
    assert cs["Status"] == "CREATE_COMPLETE", f"change set failed: {cs.get('StatusReason')!r}"

    changes = cs.get("Changes", [])
    assert len(changes) == 1, f"expected exactly one resource change, got {len(changes)}: {changes!r}"
    rc = changes[0]["ResourceChange"]
    assert rc["Action"] == "Modify", f"expected Action=Modify, got {rc['Action']!r}"
    assert rc.get("Replacement") == "False", (
        f"a Description/AllowedPattern/Tier-only change must be classified Replacement=False, "
        f"got {rc.get('Replacement')!r}"
    )
    details_by_name = {d["Target"]["Name"]: d for d in rc.get("Details", [])}
    assert set(details_by_name) == {"Description", "AllowedPattern", "Tier"}, (
        f"expected Details to name exactly the three changed write-only properties, got "
        f"{sorted(details_by_name)}"
    )
    for prop_name, detail in details_by_name.items():
        target = detail["Target"]
        assert target["Attribute"] == "Properties", target
        assert target["RequiresRecreation"] == "Never", (
            f"{prop_name} is not create-only, must report RequiresRecreation=Never, got {target!r}"
        )
        assert detail.get("Evaluation") == "Static", (
            f"{prop_name}: expected Evaluation=Static, got {detail.get('Evaluation')!r}"
        )
        assert detail.get("ChangeSource") == "DirectModification", (
            f"{prop_name}: expected ChangeSource=DirectModification, got {detail.get('ChangeSource')!r}"
        )

    cf.execute_change_set(StackName=stack, ChangeSetName=cs_name)
    executed = _wait_terminal(cf, stack)
    assert executed["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {executed['StackStatus']!r}: {executed.get('StackStatusReason')!r}"
    )

    after = _describe_param(ssm, param_name)
    assert after["Description"] == "desc-v2", f"updated Description did not take effect: {after!r}"
    assert after["AllowedPattern"] == "^[a-z0-9]+$", f"updated AllowedPattern did not take effect: {after!r}"
    assert after["Tier"] == "Advanced", f"updated Tier did not take effect: {after!r}"
    # Updated IN PLACE, proven by SSM's own monotonic version counter continuing from where it
    # was (a true delete+recreate would start a brand new parameter back at Version 1), rather
    # than by the literal Name, which a replacement using the same Name would also preserve.
    assert after["Version"] == version_before + 1, (
        f"an in-place update must advance the existing parameter's version counter by exactly "
        f"one; expected {version_before + 1}, got {after['Version']} (a reset to 1 would mean "
        f"the parameter was actually destroyed and recreated despite Replacement=False)"
    )

    model_after = cc.get_resource(TypeName="AWS::SSM::Parameter", Identifier=physical_id)
    props_after = json.loads(model_after["ResourceDescription"]["Properties"])
    _assert_populated(props_after, param_name, "after the update")
    for write_only in ("Description", "AllowedPattern", "Tier"):
        assert write_only not in props_after, (
            f"GetResource must never report the write-only {write_only}, got {props_after!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
