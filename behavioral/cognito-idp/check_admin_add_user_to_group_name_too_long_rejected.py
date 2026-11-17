"""admin-add-user-to-group-name-too-long-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-add-user-to-group-name-too-long-rejected"
GROUP = "validation"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminAddUserToGroup accepts a GroupName at its documented ceiling of 128 characters,
    observable via AdminListGroupsForUser, and rejects 129 with InvalidParameterException."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_POOL_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-behav-user-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")

    prefix = ctx.unique_name("sim2real-behav-group-") + "-"
    at_ceiling = (prefix + "g" * 128)[:128]
    idp.create_group(UserPoolId=pool_id, GroupName=at_ceiling)
    ctx.on_cleanup(lambda: idp.delete_group(UserPoolId=pool_id, GroupName=at_ceiling))

    # Positive control: a GroupName at the documented 128-char ceiling is accepted, and the
    # membership is observable through an independent read.
    idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=at_ceiling)
    membership = [
        g["GroupName"]
        for g in idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    ]
    assert membership == [at_ceiling], f"expected membership [{at_ceiling!r}], got {membership}"

    too_long = at_ceiling + "x"
    code, message = _error(
        lambda: idp.admin_add_user_to_group(
            UserPoolId=pool_id, Username=username, GroupName=too_long
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = (
        f"1 validation error detected: Value '{too_long}' at 'groupName' failed to satisfy "
        "constraint: Member must have length less than or equal to 128"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the rejected call left membership exactly as the positive control set it
    unchanged = [
        g["GroupName"]
        for g in idp.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    ]
    assert unchanged == [at_ceiling], f"expected membership unchanged [{at_ceiling!r}], got {unchanged}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
