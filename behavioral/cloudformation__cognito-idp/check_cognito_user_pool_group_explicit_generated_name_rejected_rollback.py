"""cognito-user-pool-group-explicit-generated-name-rejected-rollback."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cognito-user-pool-group-explicit-generated-name-rejected-rollback"
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


def _group_template(group_name, pool_id: str, description: str) -> str:
    props = {"UserPoolId": pool_id, "Description": description, "Precedence": 1}
    if group_name is not None:
        props["GroupName"] = group_name
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Group": {"Type": "AWS::Cognito::UserPoolGroup", "Properties": props}},
        "Outputs": {"GroupRef": {"Value": {"Ref": "Group"}}},
    })


def _delete_stack_if_present(cf, stack_name: str) -> None:
    try:
        cf.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ValidationError":
            return
        raise
    cf.delete_stack(StackName=stack_name)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Declaring a UserPoolGroup's CFN-generated name explicitly forces a create-only replacement
    onto the same name, so the update fails with the custom-named reason and rolls back, the group
    untouched (same CreationDate), and an ordinary update afterward still succeeds in place.
    """
    cf = ctx.client("cloudformation")
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-xsvc-cogpoolneg-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    stack_name = ctx.unique_name("sim2real-xsvc-coggrpneg-")
    ctx.on_cleanup(lambda: _delete_stack_if_present(cf, stack_name))

    cf.create_stack(StackName=stack_name, TemplateBody=_group_template(None, pool_id, "d1"))
    status = _wait_terminal(cf, stack_name)
    assert status == "CREATE_COMPLETE", f"stack status after create is {status!r}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in cf.describe_stacks(
        StackName=stack_name
    )["Stacks"][0].get("Outputs", [])}
    generated = outputs["GroupRef"]
    assert generated, "GroupRef output is empty; CloudFormation did not generate a name"
    created = idp.get_group(UserPoolId=pool_id, GroupName=generated)["Group"]

    # Declaring the exact generated name explicitly: GroupName is create-only, so this requires
    # a replacement that would claim the same (pool, name) the stack already owns.
    cf.update_stack(StackName=stack_name, TemplateBody=_group_template(generated, pool_id, "d1"))
    status = _wait_terminal(cf, stack_name)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"stack status after declaring the generated name explicitly is {status!r}, expected "
        "UPDATE_ROLLBACK_COMPLETE"
    )

    failures = [
        e for e in cf.describe_stack_events(StackName=stack_name)["StackEvents"]
        if e.get("LogicalResourceId") == "Group" and e.get("ResourceStatus") == "UPDATE_FAILED"
    ]
    assert len(failures) == 1, f"expected exactly one UPDATE_FAILED event for Group, got {len(failures)}"
    reason = failures[0].get("ResourceStatusReason", "")
    expected = (
        "CloudFormation cannot update a stack when a custom-named resource requires replacing. "
        f"Rename {generated} and update the stack again."
    )
    assert reason == expected, f"UPDATE_FAILED reason was {reason!r}, expected {expected!r}"

    # Nothing was created or destroyed: same physical group, same CreationDate.
    kept = idp.get_group(UserPoolId=pool_id, GroupName=generated)["Group"]
    assert kept["CreationDate"] == created["CreationDate"], (
        f"group CreationDate changed from {created['CreationDate']!r} to {kept['CreationDate']!r}"
        " -- the refused update must not have touched the resource"
    )
    names = [g["GroupName"] for g in idp.list_groups(UserPoolId=pool_id)["Groups"]]
    assert names == [generated], f"pool groups are {names!r}, expected exactly [{generated!r}]"

    # Positive control: the stack is not wedged -- an ordinary update (no name declared) still
    # succeeds and reaches the same resource.
    cf.update_stack(StackName=stack_name, TemplateBody=_group_template(None, pool_id, "d2"))
    status = _wait_terminal(cf, stack_name)
    assert status == "UPDATE_COMPLETE", (
        f"a plain description update after the rollback got status {status!r}, expected "
        "UPDATE_COMPLETE -- the stack must still be usable"
    )
    after_control = idp.get_group(UserPoolId=pool_id, GroupName=generated)["Group"]
    assert after_control["Description"] == "d2", (
        f"description after the control update is {after_control['Description']!r}, expected 'd2'"
    )
    assert after_control["CreationDate"] == created["CreationDate"], (
        "the control update replaced the group instead of updating it in place"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
