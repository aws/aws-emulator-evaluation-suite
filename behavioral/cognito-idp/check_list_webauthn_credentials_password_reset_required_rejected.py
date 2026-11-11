"""list-webauthn-credentials-password-reset-required-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-webauthn-credentials-password-reset-required-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListWebAuthnCredentials for a user in RESET_REQUIRED fails with PasswordResetRequiredException and
    its exact message, while another user's token lists an empty list, as does the reset user once
    CONFIRMED again."""
    cip = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_pool_client(ctx, pool_id)

    reset_user = "erin"
    ok_user = "frank"
    password = "Sim2Real123"
    reset_token = _create_confirmed_user_and_login(
        ctx,
        pool_id,
        client_id,
        reset_user,
        password,
        extra_attrs=[
            {"Name": "email", "Value": f"{reset_user}@sim2real-example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    ok_token = _create_confirmed_user_and_login(ctx, pool_id, client_id, ok_user, password)

    # force the first user into RESET_REQUIRED
    cip.admin_reset_user_password(UserPoolId=pool_id, Username=reset_user)
    status = cip.admin_get_user(UserPoolId=pool_id, Username=reset_user)["UserStatus"]
    assert status == "RESET_REQUIRED", f"expected RESET_REQUIRED after admin_reset_user_password, got {status}"

    code, message = _error(lambda: cip.list_web_authn_credentials(AccessToken=reset_token))
    assert code == "PasswordResetRequiredException", f"expected PasswordResetRequiredException, got {code}"
    expected = "Password reset required for the user"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # control: an unaffected user in the same pool still succeeds, so the rejection
    # tracks reset_user's own state rather than being a blanket denial in the pool
    creds = cip.list_web_authn_credentials(AccessToken=ok_token)
    assert creds["Credentials"] == [], f"expected no credentials for the unaffected user, got {creds['Credentials']}"

    # restore: resolving RESET_REQUIRED back to CONFIRMED and re-authenticating makes
    # the identical call succeed again for the same user
    cip.admin_set_user_password(UserPoolId=pool_id, Username=reset_user, Password=password, Permanent=True)
    status2 = cip.admin_get_user(UserPoolId=pool_id, Username=reset_user)["UserStatus"]
    assert status2 == "CONFIRMED", f"expected CONFIRMED after admin_set_user_password, got {status2}"

    restored_token = cip.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": reset_user, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]
    restored_creds = cip.list_web_authn_credentials(AccessToken=restored_token)
    assert restored_creds["Credentials"] == [], (
        f"expected the restored user's identical call to succeed, got {restored_creds['Credentials']}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as err:
        err = err.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("real AWS rejects this call, but it SUCCEEDED")


def _create_pool(ctx):
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        AccountRecoverySetting={
            "RecoveryMechanisms": [{"Priority": 1, "Name": "verified_email"}]
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_pool_client(ctx, pool_id):
    cip = ctx.client("cognito-idp")
    return cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]


def _create_confirmed_user_and_login(ctx, pool_id, client_id, username, password, extra_attrs=None):
    cip = ctx.client("cognito-idp")
    cip.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=extra_attrs or [],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cip.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    resp = cip.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
