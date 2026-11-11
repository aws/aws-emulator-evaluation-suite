"""set-user-mfa-preference-unverified-sms-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-user-mfa-preference-unverified-sms-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetUserMFAPreference with SMS preferred but not enabled fails with InvalidParameterException and its
    exact message and leaves SMS_MFA unlisted and not preferred, while the request without the
    contradiction succeeds."""
    cip = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_pool_client(ctx, pool_id)
    username = "bob"
    password = "Sim2Real123"
    token = _create_confirmed_user_and_login(
        ctx,
        pool_id,
        client_id,
        username,
        password,
        extra_attrs=[{"Name": "phone_number", "Value": "+15005550006"}],
    )

    code, message = _error(
        lambda: cip.set_user_mfa_preference(
            AccessToken=token,
            SMSMfaSettings={"Enabled": False, "PreferredMfa": True},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "Can't mark a disabled mfa as preferred"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: SMS MFA was never activated/preferred for the user
    user = cip.get_user(AccessToken=token)
    mfa_list = user.get("UserMFASettingList") or []
    assert "SMS_MFA" not in mfa_list, f"expected SMS_MFA absent, got UserMFASettingList={mfa_list!r}"
    preferred = user.get("PreferredMfaSetting")
    assert preferred != "SMS_MFA", f"expected PreferredMfaSetting != SMS_MFA, got {preferred!r}"

    # positive control: the same (non-contradictory) disable request still succeeds
    cip.set_user_mfa_preference(AccessToken=token, SMSMfaSettings={"Enabled": False, "PreferredMfa": False})


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
