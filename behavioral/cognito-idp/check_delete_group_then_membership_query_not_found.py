"""delete-group-then-membership-query-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-group-then-membership-query-not-found"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteGroup, GetGroup fails with ResourceNotFoundException and the group leaves
    AdminListGroupsForUser, while an untouched sibling group still resolves and stays listed."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    doomed_group = ctx.unique_name("sim2real-group-doomed-")
    surviving_group = ctx.unique_name("sim2real-group-alive-")
    username = ctx.unique_name("sim2real-user-")

    idp.create_group(UserPoolId=pool_id, GroupName=doomed_group)
    idp.create_group(UserPoolId=pool_id, GroupName=surviving_group)
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=doomed_group)
    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=surviving_group)

    before = {g["GroupName"] for g in idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]}
    assert doomed_group in before and surviving_group in before, (
        f"expected both {doomed_group!r} and {surviving_group!r} in the pre-delete membership "
        f"set, got {before!r}"
    )

    idp.delete_group(UserPoolId=pool_id, GroupName=doomed_group)

    code, message = _error(lambda: idp.get_group(UserPoolId=pool_id, GroupName=doomed_group))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetGroup on the deleted group, got {code!r}"
    )
    assert message == "Group not found.", f"GetGroup on the deleted group: message {message!r}"

    after = {g["GroupName"] for g in idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]}
    assert doomed_group not in after, (
        f"deleted group {doomed_group!r} is still listed as a membership for the user: {after!r}"
    )

    control = idp.get_group(UserPoolId=pool_id, GroupName=surviving_group)["Group"]
    assert control["GroupName"] == surviving_group, (
        f"expected GetGroup on the untouched sibling to return {surviving_group!r}, got "
        f"{control['GroupName']!r}"
    )
    assert surviving_group in after, (
        f"untouched sibling group {surviving_group!r} disappeared from membership after an "
        f"unrelated group was deleted: {after!r}"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool-"})
    resp = idp.create_user_pool(PoolName=name, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
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
