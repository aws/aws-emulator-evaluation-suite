"""change-set-on-stack-failure-with-disable-rollback-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-on-stack-failure-with-disable-rollback-rejected"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
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


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExecuteChangeSet(DisableRollback) on a change set created with OnStackFailure is refused with
    the exact ValidationError and leaves it AVAILABLE; the plain execute then creates the stack.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ExecuteChangeSet.html
    """
    cf = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-csosf-")
    cs_name = ctx.unique_name("sim2real-behav-csosf-cs-")

    created = cf.create_change_set(
        StackName=stack_name, ChangeSetName=cs_name, ChangeSetType="CREATE",
        TemplateBody=_TEMPLATE, OnStackFailure="DO_NOTHING", Tags=_TAGS)
    stack_id, cs_id = created["StackId"], created["Id"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs['Status']!r} {cs.get('StatusReason')!r}"
    assert cs.get("OnStackFailure") == "DO_NOTHING", (
        f"DescribeChangeSet must echo OnStackFailure, got {cs.get('OnStackFailure')!r}")

    got = _error(lambda: cf.execute_change_set(ChangeSetName=cs_id, DisableRollback=True))
    assert got == (
        "ValidationError",
        "Either DisableRollback or OnStackFailure can be specified, but not both. "
        "Validation error as OnStackFailure parameter was specified during CreateChangeSet.",
    ), f"ExecuteChangeSet(DisableRollback=True) over OnStackFailure answered {got!r}"

    # Effect absent: the refused execute neither consumed the change set nor started the stack.
    after = cf.describe_change_set(ChangeSetName=cs_id)
    assert (after["Status"], after["ExecutionStatus"]) == ("CREATE_COMPLETE", "AVAILABLE"), (
        f"the refused execute must leave the change set executable, got "
        f"{(after['Status'], after['ExecutionStatus'])!r}")
    pending = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert pending == "REVIEW_IN_PROGRESS", f"the stack must still await review, got {pending!r}"

    # Control: the same change set without DisableRollback executes.
    cf.execute_change_set(ChangeSetName=cs_id)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"plain execute: {stack['StackStatus']!r} {stack.get('StackStatusReason')!r}")
    assert stack.get("DisableRollback") is True, (
        f"OnStackFailure=DO_NOTHING must be recorded as DisableRollback=True, got "
        f"{stack.get('DisableRollback')!r}")
    executed = cf.describe_change_set(ChangeSetName=cs_id)["ExecutionStatus"]
    assert executed == "EXECUTE_COMPLETE", f"executed change set reports {executed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
