"""admin-create-user-force-alias-creation-alias-sign-in-authenticates-new-owner."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-create-user-force-alias-creation-alias-sign-in-authenticates-new-owner"
GROUP = "alias-lifecycle"
SERVICES = ["cognito-idp"]

PASSWORD_A = "Sim2Real!PassA0"
PASSWORD_B = "Sim2Real!PassB0"

_BAD_CREDS = ("NotAuthorizedException", "Incorrect username or password.")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: keys {sorted(result)!r}")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminInitiateAuth by an email alias AdminCreateUser moved with ForceAliasCreation=true
    authenticates the user the alias now points to, not the user it left.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-aliasauth-pool-"),
        AliasAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-aliasauth-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    email = f"{ctx.unique_name('sim2real-behav-cip-aliasauth')}@example.com"
    user_a = ctx.unique_name("sim2real-behav-cip-aliasauth-user-a-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=user_a, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=user_a))
    c.admin_set_user_password(UserPoolId=pool_id, Username=user_a, Password=PASSWORD_A, Permanent=True)

    before = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": email, "PASSWORD": PASSWORD_A},
    )
    before_identity = c.get_user(AccessToken=before["AuthenticationResult"]["AccessToken"])
    assert before_identity["Username"] == user_a, (
        f"signing in by the alias before any claim reached {before_identity['Username']!r}, expected {user_a!r}"
    )

    user_b = ctx.unique_name("sim2real-behav-cip-aliasauth-user-b-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=user_b, MessageAction="SUPPRESS", ForceAliasCreation=True,
        UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=user_b))
    c.admin_set_user_password(UserPoolId=pool_id, Username=user_b, Password=PASSWORD_B, Permanent=True)

    a_after = c.admin_get_user(UserPoolId=pool_id, Username=user_a)
    a_after_attrs = {a["Name"]: a["Value"] for a in a_after["UserAttributes"]}
    assert a_after_attrs["email_verified"] == "false", (
        f"user A's email_verified after losing the alias is {a_after_attrs['email_verified']!r}, expected 'false'"
    )

    after = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": email, "PASSWORD": PASSWORD_B},
    )
    after_identity = c.get_user(AccessToken=after["AuthenticationResult"]["AccessToken"])
    assert after_identity["Username"] == user_b, (
        f"signing in by the alias after the claim reached {after_identity['Username']!r}, expected {user_b!r}"
    )

    expect_error(
        lambda: c.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": email, "PASSWORD": PASSWORD_A},
        ),
        *_BAD_CREDS,
    )

    still_a = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user_a, "PASSWORD": PASSWORD_A},
    )
    still_a_identity = c.get_user(AccessToken=still_a["AuthenticationResult"]["AccessToken"])
    assert still_a_identity["Username"] == user_a, (
        f"signing in by user A's own username reached {still_a_identity['Username']!r}, expected {user_a!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
