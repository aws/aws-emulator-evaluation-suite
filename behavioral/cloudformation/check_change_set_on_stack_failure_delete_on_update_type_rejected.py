"""change-set-on-stack-failure-delete-on-update-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-on-stack-failure-delete-on-update-type-rejected"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(*handles):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {h: {"Type": "AWS::CloudFormation::WaitConditionHandle"} for h in handles},
    })


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


def _by_logical_id(cs):
    """The change set's ResourceChange entries keyed by LogicalResourceId."""
    return {c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in cs["Changes"]}

@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChangeSet(ChangeSetType=UPDATE, OnStackFailure=DELETE) is refused with the exact
    ValidationError and leaves no change set; the same UPDATE with OnStackFailure=ROLLBACK is created.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
    """
    cf = ctx.client("cloudformation")
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-csosfu-"),
                               TemplateBody=_template("One"), Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"

    cs_name = ctx.unique_name("sim2real-behav-csosfu-cs-")
    got = _error(lambda: cf.create_change_set(
        StackName=stack_id, ChangeSetName=cs_name, ChangeSetType="UPDATE",
        TemplateBody=_template("One", "Two"), OnStackFailure="DELETE"))
    assert got == (
        "ValidationError",
        "OnStackFailure parameter can only be specified to DELETE when ChangeSetType is CREATE.",
    ), f"UPDATE change set with OnStackFailure=DELETE answered {got!r}"

    # Effect absent: no change set of that name exists on the stack.
    listed = [s["ChangeSetName"] for s in cf.list_change_sets(StackName=stack_id)["Summaries"]]
    assert cs_name not in listed, f"the refused change set is listed: {listed!r}"
    missing = _error(lambda: cf.describe_change_set(StackName=stack_id, ChangeSetName=cs_name))
    assert missing == ("ChangeSetNotFound", f"ChangeSet [{cs_name}] does not exist"), missing

    # Control: the same name and template with OnStackFailure=ROLLBACK is accepted.
    cs_id = cf.create_change_set(
        StackName=stack_id, ChangeSetName=cs_name, ChangeSetType="UPDATE",
        TemplateBody=_template("One", "Two"), OnStackFailure="ROLLBACK")["Id"]
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"control change set: {cs.get('StatusReason')!r}"
    assert cs.get("OnStackFailure") == "ROLLBACK", f"OnStackFailure echo: {cs.get('OnStackFailure')!r}"
    actions = sorted((rc["LogicalResourceId"], rc["Action"]) for rc in _by_logical_id(cs).values())
    assert actions == [("Two", "Add")], f"control change set must add only Two, got {actions!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
