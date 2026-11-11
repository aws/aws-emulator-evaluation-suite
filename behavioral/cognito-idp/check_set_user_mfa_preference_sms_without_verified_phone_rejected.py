"""set-user-mfa-preference-sms-without-verified-phone-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-user-mfa-preference-sms-without-verified-phone-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserMFAPreference rejects enabling SMS MFA for a user with no verified phone
    number, but the identical request succeeds once the phone number is verified."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-smspref-"), UserPoolTags=_POOL_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Pwd9!"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    access_token = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    # user has no phone_number attribute at all, let alone a verified one
    code, message = _error(
        lambda: cognito.set_user_mfa_preference(
            AccessToken=access_token,
            SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "User does not have delivery config set to turn on SMS_MFA"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no SMS MFA preference was recorded for the user
    user = cognito.get_user(AccessToken=access_token)
    assert user.get("PreferredMfaSetting") is None, (
        f"expected no preferred MFA setting after the rejected call, got "
        f"{user.get('PreferredMfaSetting')!r}"
    )
    assert "SMS_MFA" not in (user.get("UserMFASettingList") or []), (
        f"SMS_MFA should not be enrolled after the rejected call, got "
        f"{user.get('UserMFASettingList')!r}"
    )

    # positive control: the identical request succeeds once the phone number is verified
    cognito.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "phone_number", "Value": "+15555550123"},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
    )
    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    user_after = cognito.get_user(AccessToken=access_token)
    assert user_after.get("PreferredMfaSetting") == "SMS_MFA", (
        f"expected PreferredMfaSetting == 'SMS_MFA' once the phone number is verified, got "
        f"{user_after.get('PreferredMfaSetting')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
