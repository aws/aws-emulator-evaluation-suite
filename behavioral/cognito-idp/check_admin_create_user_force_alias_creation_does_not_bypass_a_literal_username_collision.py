"""admin-create-user-force-alias-creation-does-not-bypass-a-literal-username-collision."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-create-user-force-alias-creation-does-not-bypass-a-literal-username-collision"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_USERNAME_EXISTS = ("UsernameExistsException", "User account already exists")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ForceAliasCreation=true reconciles a colliding alias, not a colliding literal
    Username: AdminCreateUser with the same Username as an existing user is still refused,
    the original user's attributes stay unchanged, and an unrelated create still succeeds.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        AliasAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    email_a = f"{ctx.unique_name('sim2real-behav-cip-mail-a')}@example.com"
    c.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": email_a}, {"Name": "email_verified", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))

    email_b = f"{ctx.unique_name('sim2real-behav-cip-mail-b')}@example.com"
    expect_error(
        lambda: c.admin_create_user(
            UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS", ForceAliasCreation=True,
            UserAttributes=[{"Name": "email", "Value": email_b}, {"Name": "email_verified", "Value": "true"}],
        ),
        *_USERNAME_EXISTS,
    )

    after = _attrs(c, pool_id, username)
    assert after["email"] == email_a, (
        f"the refused create still changed the email to {after.get('email')!r}, expected it to stay {email_a!r}"
    )
    assert after["email_verified"] == "true", f"the refused create changed email_verified to {after['email_verified']!r}"

    other_username = ctx.unique_name("sim2real-behav-cip-other-")
    resp = c.admin_create_user(
        UserPoolId=pool_id, Username=other_username, MessageAction="SUPPRESS", ForceAliasCreation=True,
        UserAttributes=[{"Name": "email", "Value": email_b}, {"Name": "email_verified", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=other_username))
    assert resp["User"]["Username"] == other_username, (
        f"the unrelated create returned Username {resp['User']['Username']!r}, expected {other_username!r}"
    )
    resolved = c.admin_get_user(UserPoolId=pool_id, Username=email_b)
    assert resolved["Username"] == other_username, (
        f"email_b's alias resolved to {resolved['Username']!r}, expected the unrelated create {other_username!r}"
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
