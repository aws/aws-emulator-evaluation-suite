"""change-set-outputs-only-diff-is-executable-not-rejected-as-no-changes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-outputs-only-diff-is-executable-not-rejected-as-no-changes"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Label": {"Type": "String"}},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"LabelOut": {"Value": {"Ref": "Label"}}},
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


def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChangeSet with a truly identical template, parameters and tags ends FAILED with the
    no-changes message and leaves the stack untouched, while a change set whose only difference
    is an Output's value is CREATE_COMPLETE, executable, with an empty Changes list.
    """
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-csout-")
    label1 = ctx.unique_name("sim2real-behav-csout-label-")
    label2 = ctx.unique_name("sim2real-behav-csout-label-")

    cf.create_stack(StackName=name, TemplateBody=_template(),
                     Parameters=[{"ParameterKey": "Label", "ParameterValue": label1}], Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack(cf, name))
    stack = _wait_stack(cf, name, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"
    baseline_ids = _resource_ids(cf, name)
    baseline_outputs = _outputs(stack)
    assert baseline_outputs == {"LabelOut": label1}, baseline_outputs

    # --- Break exactly one thing: a change set whose template, parameters and tags are all
    # identical to the stack's current ones, so nothing at all would change.
    noop_id = cf.create_change_set(
        StackName=name, ChangeSetName=ctx.unique_name("sim2real-behav-csout-cs-"),
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "Label", "ParameterValue": label1}],
        Tags=_TAGS, ChangeSetType="UPDATE",
    )["Id"]
    ctx.on_cleanup(lambda: _delete_change_set(cf, noop_id))
    noop_cs = _wait_change_set(cf, noop_id, timeout_s=_cap(ctx, 180.0))
    assert noop_cs["Status"] == "FAILED", f"zero-diff change set: {noop_cs['Status']!r}"
    assert noop_cs["StatusReason"] == (
        "The submitted information didn't contain changes. "
        "Submit different information to create a change set."
    ), f"unexpected StatusReason: {noop_cs['StatusReason']!r}"
    assert noop_cs["ExecutionStatus"] == "UNAVAILABLE", (
        f"a failed change set must stay UNAVAILABLE, got {noop_cs['ExecutionStatus']!r}"
    )

    # --- Effect absent: the rejected zero-diff change set must not have touched the stack.
    untouched = cf.describe_stacks(StackName=name)["Stacks"][0]
    assert untouched["StackStatus"] == "CREATE_COMPLETE", (
        f"a failed change set must leave the stack status unchanged, got {untouched['StackStatus']!r}"
    )
    assert "LastUpdatedTime" not in untouched, (
        f"a failed change set must not stamp LastUpdatedTime, got {untouched.get('LastUpdatedTime')!r}"
    )
    assert _resource_ids(cf, name) == baseline_ids, _resource_ids(cf, name)

    # --- Positive control: a change set whose only diff is the Output's value is executable.
    out_id = cf.create_change_set(
        StackName=name, ChangeSetName=ctx.unique_name("sim2real-behav-csout-cs-"),
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "Label", "ParameterValue": label2}],
        Tags=_TAGS, ChangeSetType="UPDATE",
    )["Id"]
    ctx.on_cleanup(lambda: _delete_change_set(cf, out_id))
    out_cs = _wait_change_set(cf, out_id, timeout_s=_cap(ctx, 180.0))
    assert out_cs["Status"] == "CREATE_COMPLETE", (
        f"outputs-only change set: {out_cs['Status']!r} {out_cs.get('StatusReason')!r}"
    )
    assert out_cs["Changes"] == [], f"expected no resource Changes, got {out_cs['Changes']!r}"
    assert out_cs["ExecutionStatus"] == "AVAILABLE", (
        f"an executable change set must be AVAILABLE, got {out_cs['ExecutionStatus']!r}"
    )

    before = cf.describe_stacks(StackName=name)["Stacks"][0].get("LastUpdatedTime")

    cf.execute_change_set(ChangeSetName=out_id)
    stack = _wait_stack(cf, name, updated_since=before, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"execute: {stack['StackStatus']!r} {stack.get('StackStatusReason')!r}"
    )
    assert _outputs(stack) == {"LabelOut": label2}, (
        f"executing the Outputs-only change set must update the Output, got {_outputs(stack)!r}"
    )
    assert _resource_ids(cf, name) == baseline_ids, (
        f"an Outputs-only change must not touch the resource set, got {_resource_ids(cf, name)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
