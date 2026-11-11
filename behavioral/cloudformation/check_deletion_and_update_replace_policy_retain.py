"""deletion-and-update-replace-policy-retain."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-and-update-replace-policy-retain"
GROUP = 'stack_lifecycle'
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


def _param_exists(ssm, name):
    """True iff the SSM parameter exists (ParameterNotFound => False)."""
    try:
        ssm.get_parameter(Name=name)
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ParameterNotFound":
            return False
        raise


def _delete_param_quietly(ssm, name):
    """Best-effort teardown for a resource CloudFormation deliberately retained."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise




def _template(keeper, goner, rolling):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Keeper": {
                "Type": "AWS::SSM::Parameter",
                "DeletionPolicy": "Retain",
                "Properties": {"Name": keeper, "Type": "String", "Value": "keep-me"},
            },
            "Goner": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": goner, "Type": "String", "Value": "delete-me"},
            },
            "Rolling": {
                "Type": "AWS::SSM::Parameter",
                # Name is an immutable property, so changing it forces a
                # replacement -- which UpdateReplacePolicy governs.
                "UpdateReplacePolicy": "Retain",
                "Properties": {"Name": rolling, "Type": "String", "Value": "rolling"},
            },
        },
    })


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """UpdateReplacePolicy:Retain keeps the replaced resource and DeletionPolicy:Retain keeps its
    resource after DeleteStack, independently; the current and no-policy resources are destroyed."""
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack = ctx.unique_name("sim2real-behav-retain-")
    keeper = "/" + ctx.unique_name("sim2real-behav-retain-keep-")
    goner = "/" + ctx.unique_name("sim2real-behav-retain-gone-")
    rolling_v1 = "/" + ctx.unique_name("sim2real-behav-retain-roll1-")
    rolling_v2 = "/" + ctx.unique_name("sim2real-behav-retain-roll2-")

    # Retained resources outlive the stack, so they need their own teardown.
    ctx.on_cleanup(lambda: _delete_param_quietly(ssm, keeper))
    ctx.on_cleanup(lambda: _delete_param_quietly(ssm, rolling_v1))
    ctx.on_cleanup(lambda: _delete_param_quietly(ssm, rolling_v2))

    cf.create_stack(StackName=stack, TemplateBody=_template(keeper, goner, rolling_v1))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )
    assert _param_exists(ssm, keeper) and _param_exists(ssm, goner), "setup did not provision"
    assert _param_exists(ssm, rolling_v1), "setup did not provision the replaceable resource"

    # --- UpdateReplacePolicy:Retain -- replace Rolling by changing its Name.
    cf.update_stack(StackName=stack, TemplateBody=_template(keeper, goner, rolling_v2))
    updated = _wait_terminal(cf, stack)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {updated['StackStatus']!r}: "
        f"{updated.get('StackStatusReason')!r}"
    )
    assert _param_exists(ssm, rolling_v2), "the replacement resource must exist after the update"
    assert _param_exists(ssm, rolling_v1), (
        f"UpdateReplacePolicy:Retain must leave the replaced resource {rolling_v1} in place; "
        "it was destroyed"
    )
    retained_after_update = ssm.get_parameter(Name=rolling_v1)["Parameter"]["Value"]
    assert retained_after_update == "rolling", (
        f"the retained predecessor {rolling_v1} must keep its original value, not merely exist; "
        f"got {retained_after_update!r}"
    )
    physical = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cf.list_stack_resources(StackName=stack)["StackResourceSummaries"]
    }
    assert physical.get("Rolling") == rolling_v2.lstrip("/") or physical.get("Rolling") == rolling_v2, (
        f"the stack must now track the replacement resource, got {physical.get('Rolling')!r}"
    )

    # --- DeletionPolicy:Retain -- tear the whole stack down.
    cf.delete_stack(StackName=stack)
    deadline = time.monotonic() + 600
    while _describe(cf, stack) is not None:
        assert time.monotonic() < deadline, f"stack {stack} not deleted within 600s"
        time.sleep(5)

    assert _param_exists(ssm, keeper), (
        f"DeletionPolicy:Retain must survive DeleteStack; {keeper} was destroyed"
    )
    keeper_value = ssm.get_parameter(Name=keeper)["Parameter"]["Value"]
    assert keeper_value == "keep-me", (
        f"the retained parameter {keeper} must keep its original value, not merely exist; "
        f"got {keeper_value!r}"
    )
    assert not _param_exists(ssm, goner), (
        f"a resource with no DeletionPolicy must be destroyed by DeleteStack; {goner} survived"
    )
    assert not _param_exists(ssm, rolling_v2), (
        f"UpdateReplacePolicy:Retain must NOT imply DeletionPolicy:Retain; {rolling_v2} survived "
        "DeleteStack"
    )
    assert _param_exists(ssm, rolling_v1), (
        f"the earlier retained replacement {rolling_v1} must still exist"
    )
    rolling_v1_value = ssm.get_parameter(Name=rolling_v1)["Parameter"]["Value"]
    assert rolling_v1_value == "rolling", (
        f"the earlier retained replacement {rolling_v1} must keep its original value, not merely "
        f"exist; got {rolling_v1_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
