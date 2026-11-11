"""op-contract-adminAddUserToGroup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminAddUserToGroup"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminAddUserToGroup adds a user to a group (observable via AdminListGroupsForUser)
    and rejects a username that doesn't exist in the pool."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    group_name = _unique(ctx, "group")
    idp.create_group(UserPoolId=pool_id, GroupName=group_name)
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=group_name))
    username = _create_user(ctx, pool_id, _unique(ctx, "user"), _PASSWORD)

    # Success path: user not yet in any group.
    before = idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    before_names = [g["GroupName"] for g in before]
    assert group_name not in before_names, f"expected {group_name} absent before add, got {before_names}"

    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)

    after = idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    names = [g["GroupName"] for g in after]
    assert group_name in names, f"expected {group_name} in {names} after AdminAddUserToGroup"

    # Error boundary: nonexistent username -> UserNotFoundException.
    code, message = _error(
        lambda: idp.admin_add_user_to_group(
            UserPoolId=pool_id, Username=_unique(ctx, "ghost"), GroupName=group_name
        )
    )
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    assert message == "User does not exist.", message


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=_unique(ctx, "pool"),
        # Pin explicitly rather than rely on the create-time default, so a future default change
        # can't silently make the cleanup delete below start failing.
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        **kwargs,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_user(ctx, pool_id, username, password=None, permanent=True, attrs=None):
    idp = ctx.client("cognito-idp")
    kwargs = {
        "UserPoolId": pool_id,
        "Username": username,
        "MessageAction": "SUPPRESS",
        "UserAttributes": attrs
        or [
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    }
    if password:
        kwargs["TemporaryPassword"] = password
    idp.admin_create_user(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, pool_id, username))
    if password and permanent:
        idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username


def _safe_delete_user(ctx, pool_id, username) -> None:
    idp = ctx.client("cognito-idp")
    try:
        idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _error(fn):
    """(code, message) of the expected refusal; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
