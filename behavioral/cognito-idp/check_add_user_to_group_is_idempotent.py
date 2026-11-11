"""add-user-to-group-is-idempotent."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "add-user-to-group-is-idempotent"
GROUP = 'user-group-membership'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminAddUserToGroup is idempotent: a repeat add yields exactly one membership."""
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
    c.admin_add_user_to_group(
        UserPoolId=pool_id, Username=username, GroupName=group_name
    )

    groups = c.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)[
        "Groups"
    ]
    matches = [g for g in groups if g["GroupName"] == group_name]
    assert len(matches) == 1, f"expected exactly one membership entry, got {matches}"

    members = c.list_users_in_group(UserPoolId=pool_id, GroupName=group_name)[
        "Users"
    ]
    assert [u["Username"] for u in members].count(username) == 1, (
        f"expected the user listed once in the group, got {members}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
