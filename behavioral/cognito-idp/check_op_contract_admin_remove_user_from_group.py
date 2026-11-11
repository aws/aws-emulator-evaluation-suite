"""op-contract-adminRemoveUserFromGroup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminRemoveUserFromGroup"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminRemoveUserFromGroup removes exactly the targeted membership with HTTP 200 (observable via
    AdminListGroupsForUser), succeeds with HTTP 200 and no change for a nonexistent GroupName, and rejects a
    username that doesn't exist with UserNotFoundException 'User does not exist.', leaving the membership intact."""
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

    status = idp.admin_remove_user_from_group(
        UserPoolId=pool_id, Username=username, GroupName=group_a
    )["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from AdminRemoveUserFromGroup, got {status}"

    remaining = [
        g["GroupName"]
        for g in idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    ]
    assert remaining == [group_b], f"expected only [{group_b}] remaining, got {remaining}"

    # A GroupName that does not exist is accepted as a no-op, not refused.
    status = idp.admin_remove_user_from_group(
        UserPoolId=pool_id, Username=username, GroupName=_unique(ctx, "missing-group")
    )["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 removing the user from a nonexistent group, got {status}"
    after_missing = [
        g["GroupName"]
        for g in idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    ]
    assert after_missing == [group_b], f"expected [{group_b}] unchanged, got {after_missing}"

    # Error boundary: nonexistent username -> UserNotFoundException.
    code, message = _error(
        lambda: idp.admin_remove_user_from_group(
            UserPoolId=pool_id, Username=_unique(ctx, "ghost"), GroupName=group_b
        )
    )
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    assert message == "User does not exist.", message

    # The rejected call must have had zero side effect on the real user's membership.
    unchanged = [
        g["GroupName"]
        for g in idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    ]
    assert unchanged == [group_b], f"expected [{group_b}] still intact after rejected call, got {unchanged}"


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})
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
