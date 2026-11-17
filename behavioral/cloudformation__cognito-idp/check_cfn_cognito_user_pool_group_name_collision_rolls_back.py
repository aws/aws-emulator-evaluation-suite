"""cfn-cognito-user-pool-group-name-collision-rolls-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cognito-user-pool-group-name-collision-rolls-back"
GROUP = "deploy_functional"
SERVICES = ["cloudformation", "cognito-idp"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _wait_terminal(cf, name, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(3)
    raise AssertionError(f"stack {name} terminal not reached within {timeout_s}s (last={last!r})")


def _group_template(group_name: str, pool_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::Cognito::UserPoolGroup",
                "Properties": {
                    "GroupName": group_name,
                    "UserPoolId": pool_id,
                },
            },
        },
    })


def _delete_stack_if_present(cf, stack_name: str) -> None:
    try:
        cf.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ValidationError":
            return
        raise
    cf.delete_stack(StackName=stack_name)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack declaring a UserPoolGroup whose GroupName already exists in the pool is refused
    by a pre-create name-conflict validation and rolls back, leaving the pre-existing group
    untouched; the same template under an unused name succeeds.
    """
    cf = ctx.client("cloudformation")
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-xsvc-cogcol-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    taken_name = ctx.unique_name("sim2real-xsvc-coggrp-taken-")
    idp.create_group(UserPoolId=pool_id, GroupName=taken_name, Description="pre-existing")
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=taken_name))
    pre_existing = idp.get_group(UserPoolId=pool_id, GroupName=taken_name)["Group"]

    stack_name = ctx.unique_name("sim2real-xsvc-coggrpcol-")
    ctx.on_cleanup(lambda: _delete_stack_if_present(cf, stack_name))

    cf.create_stack(StackName=stack_name, TemplateBody=_group_template(taken_name, pool_id))
    status = _wait_terminal(cf, stack_name)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack status after declaring an already-taken GroupName is {status!r}, expected "
        "ROLLBACK_COMPLETE"
    )

    validation_events = [
        e for e in cf.describe_events(StackName=stack_name)["OperationEvents"]
        if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "Group"
    ]
    assert len(validation_events) == 1, (
        f"expected exactly one VALIDATION_ERROR event for Group, got {len(validation_events)}"
    )
    event = validation_events[0]
    assert event["ValidationName"] == "NAME_CONFLICT_VALIDATION", (
        f"ValidationName was {event['ValidationName']!r}, expected 'NAME_CONFLICT_VALIDATION'"
    )
    expected_reason = (
        f"Resource of type 'AWS::Cognito::UserPoolGroup' with identifier "
        f"'{pool_id}|{taken_name}' already exists."
    )
    assert event["ValidationStatusReason"] == expected_reason, (
        f"ValidationStatusReason was {event['ValidationStatusReason']!r}, expected {expected_reason!r}"
    )
    assert event["PhysicalResourceId"] == "", (
        f"the conflicting resource must never have been created, but PhysicalResourceId is "
        f"{event['PhysicalResourceId']!r}"
    )

    # No stack resource record exists at all -- the create was refused before provisioning.
    resources = cf.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert resources == [], f"expected no stack resources to have been provisioned, got {resources!r}"

    # Nothing about the pre-existing group changed.
    unchanged = idp.get_group(UserPoolId=pool_id, GroupName=taken_name)["Group"]
    assert unchanged["CreationDate"] == pre_existing["CreationDate"], (
        f"pre-existing group CreationDate changed from {pre_existing['CreationDate']!r} to "
        f"{unchanged['CreationDate']!r} -- the rolled-back stack must not have touched it"
    )
    assert unchanged["Description"] == "pre-existing", (
        f"pre-existing group description changed to {unchanged['Description']!r}"
    )

    # The failed stack left no resource of its own behind.
    names = sorted(g["GroupName"] for g in idp.list_groups(UserPoolId=pool_id)["Groups"])
    assert names == [taken_name], f"pool groups are {names!r}, expected only [{taken_name!r}]"

    # Positive control: an unused name in an otherwise identical template succeeds.
    other_name = ctx.unique_name("sim2real-xsvc-coggrp-free-")
    other_stack = ctx.unique_name("sim2real-xsvc-coggrpok-")
    ctx.on_cleanup(lambda: _delete_stack_if_present(cf, other_stack))
    cf.create_stack(StackName=other_stack, TemplateBody=_group_template(other_name, pool_id))
    status = _wait_terminal(cf, other_stack)
    assert status == "CREATE_COMPLETE", (
        f"control stack with an unused GroupName got status {status!r}, expected CREATE_COMPLETE"
    )
    created = idp.get_group(UserPoolId=pool_id, GroupName=other_name)["Group"]
    assert created["GroupName"] == other_name, f"control group is {created!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
