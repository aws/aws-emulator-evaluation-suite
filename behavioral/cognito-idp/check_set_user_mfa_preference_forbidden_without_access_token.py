"""set-user-mfa-preference-forbidden-without-access-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-user-mfa-preference-forbidden-without-access-token"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetUserMFAPreference called with an invalid access token is rejected with
    NotAuthorizedException instead of silently applying the preference; the same
    request with a real access token is applied and is visible via GetUser.
    """
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username, token = _create_confirmed_user_with_token(ctx, pool_id, client_id)

    before = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before.get("PreferredMfaSetting") is None, (
        f"expected a freshly confirmed user to have no MFA preference yet, "
        f"got {before.get('PreferredMfaSetting')!r}"
    )

    # Negative: invalid access token must not silently mutate MFA preference.
    code, message = _error(
        lambda: cognito.set_user_mfa_preference(
            AccessToken="not-a-real-token",
            SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
        )
    )
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for a malformed access token, got {code!r}"
    )
    expected_message = "Invalid Access Token"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_bad = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after_bad.get("PreferredMfaSetting") is None, (
        f"the rejected call must not have set a preference; expected None, "
        f"got {after_bad.get('PreferredMfaSetting')!r}"
    )
    assert after_bad.get("UserMFASettingList", []) == [], (
        f"the rejected call must not have enabled any MFA method; expected [], "
        f"got {after_bad.get('UserMFASettingList')!r}"
    )

    # Positive control: identical call with the real access token succeeds and the
    # user's access token remains usable (the rejected call didn't corrupt state).
    cognito.set_user_mfa_preference(
        AccessToken=token,
        SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
    )
    still_valid = cognito.get_user(AccessToken=token)
    assert still_valid["Username"] == username, (
        f"the real access token must still be usable after the rejected call; "
        f"expected Username {username!r}, got {still_valid['Username']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id):
    cognito = ctx.client("cognito-idp")
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _create_confirmed_user_with_token(ctx, pool_id, client_id):
    cognito = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Passw0rd!"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return username, auth["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
