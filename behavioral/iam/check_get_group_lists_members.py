"""get-group-lists-members."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "get-group-lists-members"
GROUP = 'groups'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroup returns exactly the added member, and no longer lists it after removal."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))
    group = ctx.unique_name("sim2real-behav-grp-")
    iam.create_group(GroupName=group, Path="/")
    ctx.on_cleanup(lambda n=group: iam.delete_group(GroupName=n))
    iam.add_user_to_group(UserName=user, GroupName=group)
    ctx.on_cleanup(lambda u=user, g=group: iam.remove_user_from_group(UserName=u, GroupName=g))
    resp = iam.get_group(GroupName=group)
    user_names = [u["UserName"] for u in resp["Users"]]
    assert user_names == [user], f"expected only {user!r} in group {group!r}, got {user_names!r}"

    iam.remove_user_from_group(UserName=user, GroupName=group)
    resp = iam.get_group(GroupName=group)
    user_names = [u["UserName"] for u in resp["Users"]]
    assert user not in user_names, (
        f"expected {user!r} removed from group {group!r}, still present in {user_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
