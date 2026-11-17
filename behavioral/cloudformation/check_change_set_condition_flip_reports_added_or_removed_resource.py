"""change-set-condition-flip-reports-added-or-removed-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-condition-flip-reports-added-or-removed-resource"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"MakeIt": {"Type": "String", "AllowedValues": ["true", "false"]}},
        "Conditions": {"ShouldMake": {"Fn::Equals": [{"Ref": "MakeIt"}, "true"]}},
        "Resources": {
            "Always": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Conditional": {"Type": "AWS::CloudFormation::WaitConditionHandle", "Condition": "ShouldMake"},
        },
    })


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


_ANY_STATUS = object()


def _wait_stack(cf, name, *, updated_since=_ANY_STATUS, timeout_s=300.0):
    """Poll DescribeStacks by name until the status leaves *_IN_PROGRESS. With ``updated_since``
    (the LastUpdatedTime before an update, None if the stack was never updated) the stack must also
    carry a LastUpdatedTime other than that one, so the stale pre-update status is never returned."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=name)["Stacks"][0]
        stamp = stack.get("LastUpdatedTime")
        started = updated_since is _ANY_STATUS or (stamp is not None and stamp != updated_since)
        if not stack["StackStatus"].endswith("_IN_PROGRESS") and started:
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)


def _wait_change_set(cf, cs_id, *, timeout_s=180.0):
    """Poll DescribeChangeSet until CREATE_COMPLETE or FAILED; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        cs = cf.describe_change_set(ChangeSetName=cs_id)
        if cs["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return cs
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after {timeout_s}s")
        time.sleep(3)


def _delete_change_set(cf, cs_id):
    """Delete the change set; an executed one is removed with its stack, so that is not a leak."""
    try:
        cf.delete_change_set(ChangeSetName=cs_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ValidationError", "InvalidChangeSetStatus"):
            raise


def _delete_stack(cf, name, *, timeout_s=300.0):
    cf.delete_stack(StackName=name)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            stack = cf.describe_stacks(StackName=name)["Stacks"][0]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if stack["StackStatus"] == "DELETE_FAILED":
            raise AssertionError(f"stack {name} reached DELETE_FAILED")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {name} still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)


def _resource_ids(cf, name):
    return sorted(
        r["LogicalResourceId"]
        for r in cf.list_stack_resources(StackName=name)["StackResourceSummaries"]
    )


def _change_summary(cs):
    """(Action, LogicalResourceId, ResourceType, Scope, Details) per Changes entry, excluding the
    minted PhysicalResourceId (a presigned URL that carries this run's own credentials)."""
    return sorted(
        (c["ResourceChange"]["Action"], c["ResourceChange"]["LogicalResourceId"],
         c["ResourceChange"]["ResourceType"], tuple(c["ResourceChange"]["Scope"]),
         tuple(c["ResourceChange"]["Details"]))
        for c in cs["Changes"]
    )


def _update(ctx, cf, name, make_it: str):
    cs_id = cf.create_change_set(
        StackName=name, ChangeSetName=ctx.unique_name("sim2real-behav-cscond-cs-"),
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "MakeIt", "ParameterValue": make_it}],
        Tags=_TAGS, ChangeSetType="UPDATE",
    )["Id"]
    ctx.on_cleanup(lambda: _delete_change_set(cf, cs_id))
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs['Status']!r} {cs.get('StatusReason')!r}"
    before = cf.describe_stacks(StackName=name)["Stacks"][0].get("LastUpdatedTime")
    cf.execute_change_set(ChangeSetName=cs_id)
    stack = _wait_stack(cf, name, updated_since=before, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"execute: {stack['StackStatus']!r} {stack.get('StackStatusReason')!r}"
    )
    return cs


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A change set evaluates a Condition on each side of the update: flipping it false-to-true
    reports Add for the resource it gates, and flipping it back reports Remove, each executing
    to the resource set the condition's new value implies.
    """
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cscond-")

    cf.create_stack(StackName=name, TemplateBody=_template(),
                     Parameters=[{"ParameterKey": "MakeIt", "ParameterValue": "false"}], Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack(cf, name))
    stack = _wait_stack(cf, name, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"
    assert _resource_ids(cf, name) == ["Always"], _resource_ids(cf, name)

    # --- Condition false -> true: the gated resource is Added.
    add_cs = _update(ctx, cf, name, "true")
    assert _change_summary(add_cs) == [("Add", "Conditional", "AWS::CloudFormation::WaitConditionHandle",
                                         (), ())], _change_summary(add_cs)
    assert _resource_ids(cf, name) == ["Always", "Conditional"], _resource_ids(cf, name)

    # --- Condition true -> false: the same resource is Removed.
    remove_cs = _update(ctx, cf, name, "false")
    assert _change_summary(remove_cs) == [
        ("Remove", "Conditional", "AWS::CloudFormation::WaitConditionHandle", (), ())
    ], _change_summary(remove_cs)
    assert _resource_ids(cf, name) == ["Always"], _resource_ids(cf, name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
