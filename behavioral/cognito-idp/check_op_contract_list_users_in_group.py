"""op-contract-list-users-in-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-users-in-group"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsersInGroup returns exactly the members added to the group; unknown group name is rejected."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    group_name = ctx.unique_name("sim2real-group-")
    idp.create_group(UserPoolId=pool_id, GroupName=group_name)

    member = ctx.unique_name("sim2real-member-")
    non_member = ctx.unique_name("sim2real-nonmember-")
    idp.admin_create_user(UserPoolId=pool_id, Username=member, MessageAction="SUPPRESS")
    idp.admin_create_user(UserPoolId=pool_id, Username=non_member, MessageAction="SUPPRESS")
    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=member, GroupName=group_name)

    members = []
    token = None
    while True:
        kwargs = {"UserPoolId": pool_id, "GroupName": group_name}
        if token:
            kwargs["NextToken"] = token
        resp = idp.list_users_in_group(**kwargs)
        members.extend(resp["Users"])
        token = resp.get("NextToken")
        if not token:
            break

    usernames = {u["Username"] for u in members}
    assert usernames == {member}, usernames

    err = _client_error(
        lambda: idp.list_users_in_group(UserPoolId=pool_id, GroupName="no-such-group")
    )
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = "Group not found."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        "DeletionProtection": "INACTIVE",
    }
    params.update(overrides)
    resp = idp.create_user_pool(**params)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
