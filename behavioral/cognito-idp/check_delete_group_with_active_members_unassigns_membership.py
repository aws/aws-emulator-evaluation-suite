"""delete-group-with-active-members-unassigns-membership."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-group-with-active-members-unassigns-membership"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGroup on a group with an existing member succeeds and AdminListGroupsForUser
    no longer lists that group for the member afterward."""
    cidp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cidp)

    username = ctx.unique_name("sim2real-groupuser-")
    cidp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword="Sim2Real-Passw0rd!23",
    )

    group_name = ctx.unique_name("sim2real-group-")
    cidp.create_group(UserPoolId=pool_id, GroupName=group_name)
    cidp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)

    before = cidp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)
    before_names = {g["GroupName"] for g in before["Groups"]}
    assert group_name in before_names, "expected group to be assigned to the user before deletion"

    cidp.delete_group(UserPoolId=pool_id, GroupName=group_name)

    code, message = _error(lambda: cidp.get_group(UserPoolId=pool_id, GroupName=group_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetGroup on the deleted group, got {code}"
    )
    assert message == "Group not found.", f"GetGroup on the deleted group: message {message!r}"

    after = cidp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)
    after_names = {g["GroupName"] for g in after["Groups"]}
    assert group_name not in after_names, "deleted group is still listed as a membership for the user"

    code2, message2 = _error(
        lambda: cidp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)
    )
    assert code2 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-adding the user to the deleted group, got {code2}"
    )
    assert message2 == "Group not found.", f"AdminAddUserToGroup on the deleted group: message {message2!r}"


def _create_user_pool(ctx, cidp) -> str:
    resp = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
    )
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
