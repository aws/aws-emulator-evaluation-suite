"""admin-set-user-mfa-preference-conflicting-settings-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-conflicting-settings-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminSetUserMFAPreference rejects marking both SMS and software-token MFA as
    PreferredMfa=True at the same time, since only one factor may be preferred."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-mfaconf-"))[
        "UserPool"
    ]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Pwd9!"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
        # phone_number is verified up-front so the InvalidParameterException below is attributable
        # to the two-preferred-factors conflict, not to the unrelated unverified-SMS-factor
        # rejection.
        UserAttributes=[
            {"Name": "phone_number", "Value": "+15005550006"},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    code, message = _error(
        lambda: cognito.admin_set_user_mfa_preference(
            UserPoolId=pool_id,
            Username=username,
            SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "Two MFA types marked as preferred, only one is allowed."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the user's MFA preference was not changed by the rejected call
    user = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user.get("PreferredMfaSetting") is None
    assert not user.get("UserMFASettingList")

    # positive control: a single preferred method against the same user succeeds
    # and takes effect (not just "did not raise")
    cognito.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    after = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after.get("PreferredMfaSetting") == "SMS_MFA", after.get("PreferredMfaSetting")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
