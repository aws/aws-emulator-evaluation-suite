"""admin-get-user-auth-factors-deleted-user-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-get-user-auth-factors-deleted-user-not-found-rejected"
GROUP = "state"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminGetUserAuthFactors resolves a live username and, once AdminDeleteUser removes the
    user, the same username is rejected with UserNotFoundException and its exact message."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_POOL_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    doomed = ctx.unique_name("sim2real-behav-user-")
    survivor = ctx.unique_name("sim2real-behav-user-")
    for username in (doomed, survivor):
        idp.admin_create_user(
            UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS"
        )

    before = idp.admin_get_user_auth_factors(UserPoolId=pool_id, Username=doomed)
    assert before["Username"] == doomed, f"expected Username {doomed!r}, got {before.get('Username')!r}"

    idp.admin_delete_user(UserPoolId=pool_id, Username=doomed)

    code, message = _error(
        lambda: idp.admin_get_user_auth_factors(UserPoolId=pool_id, Username=doomed)
    )
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    expected = "User does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a sibling user in the same pool still resolves
    still_there = idp.admin_get_user_auth_factors(UserPoolId=pool_id, Username=survivor)
    assert still_there["Username"] == survivor, (
        f"expected Username {survivor!r}, got {still_there.get('Username')!r}"
    )


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
