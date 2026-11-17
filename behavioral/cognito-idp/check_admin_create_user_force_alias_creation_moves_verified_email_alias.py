"""admin-create-user-force-alias-creation-moves-verified-email-alias."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-create-user-force-alias-creation-moves-verified-email-alias"
GROUP = "alias-lifecycle"
SERVICES = ["cognito-idp"]

_USERNAME_EXISTS = ("UsernameExistsException", "User account already exists")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminCreateUser with ForceAliasCreation=true claims an email already verified as
    another user's alias: the new user gets it, and the old user's email_verified flips to
    false. ForceAliasCreation=false on the same input is refused instead.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        AliasAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    email = f"{ctx.unique_name('sim2real-behav-cip-alias')}@example.com"
    user_a = ctx.unique_name("sim2real-behav-cip-user-a-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=user_a, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=user_a))

    before = _attrs(c, pool_id, user_a)
    assert before["email_verified"] == "true", f"user A email_verified before the claim was {before['email_verified']!r}"
    resolved_before = c.admin_get_user(UserPoolId=pool_id, Username=email)
    assert resolved_before["Username"] == user_a, (
        f"the verified alias resolved to {resolved_before['Username']!r} before any claim, expected {user_a!r}"
    )

    user_b = ctx.unique_name("sim2real-behav-cip-user-b-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=user_b, MessageAction="SUPPRESS", ForceAliasCreation=True,
        UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=user_b))

    after_b = _attrs(c, pool_id, user_b)
    assert after_b["email"] == email, f"user B's email is {after_b.get('email')!r}, expected {email!r}"
    assert after_b["email_verified"] == "true", f"user B email_verified is {after_b['email_verified']!r}"
    resolved_after = c.admin_get_user(UserPoolId=pool_id, Username=email)
    assert resolved_after["Username"] == user_b, (
        f"the alias resolved to {resolved_after['Username']!r} after the claim, expected {user_b!r}"
    )

    after_a = _attrs(c, pool_id, user_a)
    assert after_a["email_verified"] == "false", (
        f"user A's email_verified after losing the alias is {after_a['email_verified']!r}, expected 'false'"
    )
    assert after_a["email"] == email, f"user A's email attribute changed to {after_a.get('email')!r}"

    user_c = ctx.unique_name("sim2real-behav-cip-user-c-")
    expect_error(
        lambda: c.admin_create_user(
            UserPoolId=pool_id, Username=user_c, MessageAction="SUPPRESS", ForceAliasCreation=False,
            UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
        ),
        *_USERNAME_EXISTS,
    )

    expect_error(
        lambda: c.admin_get_user(UserPoolId=pool_id, Username=user_c),
        "UserNotFoundException", "User does not exist.",
    )
    resolved_still = c.admin_get_user(UserPoolId=pool_id, Username=email)
    assert resolved_still["Username"] == user_b, (
        f"the alias resolved to {resolved_still['Username']!r} after the refused claim, expected it to stay {user_b!r}"
    )


def _attrs(c, pool_id, username):
    user = c.admin_get_user(UserPoolId=pool_id, Username=username)
    return {a["Name"]: a["Value"] for a in user["UserAttributes"]}


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: keys {sorted(result)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
