"""add-remove-user-from-group."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "add-remove-user-from-group"
GROUP = 'groups'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddUserToGroup -> ListGroupsForUser shows membership; RemoveUserFromGroup removes it."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))
    group = ctx.unique_name("sim2real-behav-grp-")
    iam.create_group(GroupName=group, Path="/")
    ctx.on_cleanup(lambda n=group: iam.delete_group(GroupName=n))
    iam.add_user_to_group(UserName=user, GroupName=group)
    ctx.on_cleanup(lambda u=user, g=group: iam.remove_user_from_group(UserName=u, GroupName=g))
    resp = iam.list_groups_for_user(UserName=user)
    group_names = [g["GroupName"] for g in resp["Groups"]]
    assert group in group_names, f"expected {group} in ListGroupsForUser after AddUserToGroup, got {group_names}"
    # Remove
    iam.remove_user_from_group(UserName=user, GroupName=group)
    resp = iam.list_groups_for_user(UserName=user)
    group_names = [g["GroupName"] for g in resp["Groups"]]
    assert group not in group_names, f"expected {group} absent from ListGroupsForUser after RemoveUserFromGroup, got {group_names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
