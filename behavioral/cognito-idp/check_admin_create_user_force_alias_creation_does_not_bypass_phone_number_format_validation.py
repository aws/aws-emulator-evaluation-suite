"""admin-create-user-force-alias-creation-does-not-bypass-phone-number-format-validation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-create-user-force-alias-creation-does-not-bypass-phone-number-format-validation"
GROUP = "alias-lifecycle"
SERVICES = ["cognito-idp"]

_BAD_FORMAT = ("InvalidParameterException", "Invalid phone number format.")
_USER_NOT_FOUND = ("UserNotFoundException", "User does not exist.")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: keys {sorted(result)!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminCreateUser with ForceAliasCreation=true still refuses a malformed phone_number
    before it ever reaches alias resolution; a well-formed claim on the same verified number
    still moves the alias.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-phonealias-pool-"),
        AliasAttributes=["phone_number"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    phone = "+12065550100"
    user_a = ctx.unique_name("sim2real-behav-cip-phonealias-user-a-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=user_a, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "phone_number", "Value": phone}, {"Name": "phone_number_verified", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=user_a))

    user_b = ctx.unique_name("sim2real-behav-cip-phonealias-user-b-")
    expect_error(
        lambda: c.admin_create_user(
            UserPoolId=pool_id, Username=user_b, MessageAction="SUPPRESS", ForceAliasCreation=True,
            UserAttributes=[{"Name": "phone_number", "Value": "2065550100"}, {"Name": "phone_number_verified", "Value": "true"}],
        ),
        *_BAD_FORMAT,
    )
    expect_error(
        lambda: c.admin_get_user(UserPoolId=pool_id, Username=user_b),
        *_USER_NOT_FOUND,
    )

    user_c = ctx.unique_name("sim2real-behav-cip-phonealias-user-c-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=user_c, MessageAction="SUPPRESS", ForceAliasCreation=True,
        UserAttributes=[{"Name": "phone_number", "Value": phone}, {"Name": "phone_number_verified", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=user_c))

    resolved = c.admin_get_user(UserPoolId=pool_id, Username=phone)
    assert resolved["Username"] == user_c, (
        f"the well-formed claim resolved the alias to {resolved['Username']!r}, expected {user_c!r}"
    )
    a_after = c.admin_get_user(UserPoolId=pool_id, Username=user_a)
    a_after_attrs = {a["Name"]: a["Value"] for a in a_after["UserAttributes"]}
    assert a_after_attrs["phone_number_verified"] == "false", (
        f"user A's phone_number_verified after losing the alias is {a_after_attrs['phone_number_verified']!r}, expected 'false'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
