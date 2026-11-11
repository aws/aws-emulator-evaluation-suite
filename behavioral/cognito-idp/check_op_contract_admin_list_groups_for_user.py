"""op-contract-adminListGroupsForUser."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminListGroupsForUser"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminListGroupsForUser reflects exactly the groups the user was added to (and
    only those), and rejects a username that doesn't exist."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    group_a = _unique(ctx, "group-a")
    group_b = _unique(ctx, "group-b")
    for g in (group_a, group_b):
        idp.create_group(UserPoolId=pool_id, GroupName=g)
        ctx.on_cleanup(lambda g=g: idp.delete_group(UserPoolId=pool_id, GroupName=g))
    username = _create_user(ctx, pool_id, _unique(ctx, "user"), _PASSWORD)

    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_a)
    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_b)

    groups = idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    names = sorted(g["GroupName"] for g in groups)
    assert names == sorted([group_a, group_b]), f"expected [{group_a}, {group_b}], got {names}"

    # Error boundary: nonexistent username -> UserNotFoundException.
    code = _client_error(
        lambda: idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=_unique(ctx, "ghost"))
    )
    assert code.get("Code") == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    assert code.get("Message") == "User does not exist.", code.get("Message")


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    kwargs.setdefault(
        "UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    )
    pool_id = idp.create_user_pool(PoolName=_unique(ctx, "pool"), **kwargs)["UserPool"]["Id"]
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


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
