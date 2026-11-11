"""admin-add-list-remove-user-from-group."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "admin-add-list-remove-user-from-group"
GROUP = 'user-group-membership'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminAddUserToGroup, AdminListGroupsForUser and AdminRemoveUserFromGroup form a full cycle."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    group_name = ctx.unique_name("sim2real-behav-cip-group-")
    c.create_group(UserPoolId=pool_id, GroupName=group_name)
    ctx.on_cleanup(lambda _p=pool_id, _g=group_name: c.delete_group(UserPoolId=_p, GroupName=_g))

    c.admin_add_user_to_group(
        UserPoolId=pool_id, Username=username, GroupName=group_name
    )
    groups = c.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)[
        "Groups"
    ]
    assert any(g["GroupName"] == group_name for g in groups), (
        f"expected {group_name} in groups for user, got {groups}"
    )

    c.admin_remove_user_from_group(
        UserPoolId=pool_id, Username=username, GroupName=group_name
    )
    groups_after = c.admin_list_groups_for_user(
        UserPoolId=pool_id, Username=username
    )["Groups"]
    assert not any(g["GroupName"] == group_name for g in groups_after), (
        f"expected {group_name} removed from groups for user, got {groups_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
