"""change-set-resource-types-excluding-a-template-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-resource-types-excluding-a-template-type-rejected"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_BASE_TEMPLATE = json.dumps({"Resources": {
    "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
}})
_FULL_TEMPLATE = json.dumps({"Resources": {
    "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
    "Param": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": "v"}},
}})


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, the call succeeded: {result!r}")


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


def _resource_logical_ids(cf, stack_id):
    """The stack's current resources' LogicalResourceIds, independent of any change set."""
    return {r["LogicalResourceId"] for r in cf.describe_stack_resources(StackName=stack_id)["StackResources"]}


def _by_logical_id(cs):
    """The change set's ResourceChange entries keyed by LogicalResourceId."""
    return {c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in cs["Changes"]}


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An UPDATE change set whose ResourceTypes allowlist omits a type the update adds is refused
    with the exact error and adds nothing; the identical update under an allowlist that covers it
    succeeds. A CREATE change set under the same omitting allowlist is accepted.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
    """
    cf = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-csrt-")
    cs_base = ctx.unique_name("sim2real-behav-csrt-cs0-")
    cs_denied = ctx.unique_name("sim2real-behav-csrt-cs1-")
    cs_allowed = ctx.unique_name("sim2real-behav-csrt-cs2-")

    created0 = cf.create_change_set(
        StackName=stack_name, ChangeSetName=cs_base, ChangeSetType="CREATE",
        TemplateBody=_BASE_TEMPLATE, Tags=_TAGS)
    stack_id = created0["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs0 = _wait_change_set(cf, created0["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs0["Status"] == "CREATE_COMPLETE", f"base change set: {cs0.get('StatusReason')!r}"
    cf.execute_change_set(ChangeSetName=created0["Id"])
    base_stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert base_stack["StackStatus"] == "CREATE_COMPLETE", (
        f"base stack: {base_stack['StackStatus']!r} {base_stack.get('StackStatusReason')!r}")
    base_ids = _resource_logical_ids(cf, stack_id)
    assert base_ids == {"Handle"}, f"base stack must hold only Handle, got {base_ids!r}"

    # Break exactly one thing: an UPDATE adding Param, under an allowlist that omits its type.
    got = _error(lambda: cf.create_change_set(
        StackName=stack_id, ChangeSetName=cs_denied, ChangeSetType="UPDATE",
        TemplateBody=_FULL_TEMPLATE, Tags=_TAGS,
        ResourceTypes=["AWS::CloudFormation::WaitConditionHandle"]))
    assert got == (
        "ValidationError",
        "Resource type AWS::SSM::Parameter is not allowed by parameter ResourceTypes "
        "[AWS::CloudFormation::WaitConditionHandle]",
    ), f"allowlist omitting AWS::SSM::Parameter answered {got!r}"

    # The effect is absent: an independent read shows the stack unchanged.
    denied_ids = _resource_logical_ids(cf, stack_id)
    assert denied_ids == {"Handle"}, f"the refused update must add nothing, got {denied_ids!r}"
    unchanged = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert unchanged["StackStatus"] == "CREATE_COMPLETE", (
        f"a refused change-set create must not move the stack, got {unchanged['StackStatus']!r}")

    # Restore: the identical update, with an allowlist that covers the new type, succeeds.
    created = cf.create_change_set(
        StackName=stack_id, ChangeSetName=cs_allowed, ChangeSetType="UPDATE",
        TemplateBody=_FULL_TEMPLATE, Tags=_TAGS,
        ResourceTypes=["AWS::CloudFormation::WaitConditionHandle", "AWS::SSM::Parameter"])
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"restored change set: {cs.get('StatusReason')!r}"
    assert sorted(_by_logical_id(cs)) == ["Param"], cs["Changes"]
    cf.execute_change_set(ChangeSetName=created["Id"])
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"restored execute: {stack['StackStatus']!r} {stack.get('StackStatusReason')!r}")
    final_ids = _resource_logical_ids(cf, stack_id)
    assert final_ids == {"Handle", "Param"}, f"the restored update must add Param, got {final_ids!r}"

    # A CREATE change set for a new stack under the allowlist the UPDATE was refused with.
    fresh = cf.create_change_set(
        StackName=ctx.unique_name("sim2real-behav-csrt-new-"),
        ChangeSetName=ctx.unique_name("sim2real-behav-csrt-cs3-"), ChangeSetType="CREATE",
        TemplateBody=_FULL_TEMPLATE, Tags=_TAGS,
        ResourceTypes=["AWS::CloudFormation::WaitConditionHandle"])
    ctx.on_cleanup(lambda: _delete_stack(cf, fresh["StackId"]))
    fresh_cs = _wait_change_set(cf, fresh["Id"], timeout_s=_cap(ctx, 180.0))
    assert (fresh_cs["Status"], sorted(_by_logical_id(fresh_cs))) == ("CREATE_COMPLETE", ["Handle", "Param"]), (
        f"CREATE change set under the omitting allowlist: {fresh_cs['Status']!r} "
        f"{fresh_cs.get('StatusReason')!r}, changes {sorted(_by_logical_id(fresh_cs))!r}; expected "
        f"CREATE_COMPLETE adding Handle and Param")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
