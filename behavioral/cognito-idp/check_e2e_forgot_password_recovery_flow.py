"""e2e-forgot-password-recovery-flow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-forgot-password-recovery-flow"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConfirmForgotPassword with a wrong code fails with CodeMismatchException and leaves the old
    password working; after AdminSetUserPassword the new password signs in and the old one fails
    with NotAuthorizedException, each refusal with its exact message."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-forgot-pw-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-forgot-pw-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("s2rforgotpw")
    old_password = "Or1ginalPassw0rd!"
    new_password = "Br4ndNewPassw0rd!"
    email = f"{username}@example.com"

    cognito.sign_up(
        ClientId=client_id,
        Username=username,
        Password=old_password,
        UserAttributes=[{"Name": "email", "Value": email}],
    )
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    # admin_confirm_sign_up confirms the account but does NOT mark the auto-verified
    # attribute as verified (that only happens via the real code-confirmation path).
    # ForgotPassword requires a verified recovery attribute to have somewhere to
    # deliver the reset code, so mark email verified explicitly.
    cognito.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email_verified", "Value": "true"}],
    )

    baseline = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": old_password},
    )
    assert "AccessToken" in baseline["AuthenticationResult"], (
        f"positive control failed: expected AccessToken for the original password, got {baseline['AuthenticationResult']!r}"
    )

    forgot = cognito.forgot_password(ClientId=client_id, Username=username)
    assert "CodeDeliveryDetails" in forgot, (
        f"expected ForgotPassword to report CodeDeliveryDetails, got {forgot!r}"
    )

    confirm_code, confirm_message = _error(
        lambda: cognito.confirm_forgot_password(
            ClientId=client_id,
            Username=username,
            ConfirmationCode="000000",
            Password=new_password,
        )
    )
    assert confirm_code == "CodeMismatchException", (
        f"expected CodeMismatchException for a wrong confirmation code, got {confirm_code!r}"
    )
    assert confirm_message == "Invalid verification code provided, please try again.", (
        f"expected the exact CodeMismatchException message 'Invalid verification code provided, please try again.', got {confirm_message!r}"
    )

    # Effect absent: the wrong code did not change the password.
    old_still_works = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": old_password},
    )
    assert "AccessToken" in old_still_works["AuthenticationResult"], (
        f"expected the original password to still authenticate after a rejected reset, got {old_still_works['AuthenticationResult']!r}"
    )
    new_not_yet_code, new_not_yet_message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": new_password},
        )
    )
    assert new_not_yet_code == "NotAuthorizedException", (
        f"expected the not-yet-set new password to be rejected with NotAuthorizedException, got {new_not_yet_code!r}"
    )
    assert new_not_yet_message == "Incorrect username or password.", (
        f"expected the exact NotAuthorizedException message 'Incorrect username or password.', got {new_not_yet_message!r}"
    )

    # Positive control: a legitimate password-recovery path (admin reset) completes it.
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=new_password, Permanent=True
    )
    now_works = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": new_password},
    )
    assert "AccessToken" in now_works["AuthenticationResult"], (
        f"expected AccessToken for the new password after admin_set_user_password, got {now_works['AuthenticationResult']!r}"
    )
    old_now_fails, old_now_fails_message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": old_password},
        )
    )
    assert old_now_fails == "NotAuthorizedException", (
        f"expected the superseded old password to be rejected with NotAuthorizedException, got {old_now_fails!r}"
    )
    assert old_now_fails_message == "Incorrect username or password.", (
        f"expected the exact NotAuthorizedException message 'Incorrect username or password.', got {old_now_fails_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
