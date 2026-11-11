"""confirm-forgot-password-code-mismatch-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "confirm-forgot-password-code-mismatch-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmForgotPassword with the wrong code fails and leaves the password unchanged."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-behav-user-")
    old_password = "OriginalPassw0rd!1"
    new_password = "BrandNewPassw0rd!2"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            # ForgotPassword requires a verified attribute to deliver the reset code to;
            # real Cognito rejects with InvalidParameterException otherwise.
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=old_password,
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=old_password, Permanent=True
    )

    # trigger a real password-reset code delivery
    idp.forgot_password(ClientId=client_id, Username=username)

    code, message = _error(
        lambda: idp.confirm_forgot_password(
            ClientId=client_id,
            Username=username,
            ConfirmationCode="000000",
            Password=new_password,
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    assert message == "Invalid verification code provided, please try again.", (
        f"expected the exact code-mismatch message, got {message!r}"
    )

    # password must remain unchanged: the OLD password should still authenticate
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": old_password},
    )
    assert "AuthenticationResult" in auth, "old password no longer authenticates after code-mismatch reset"

    # the NEW password must NOT authenticate, confirming the reset never took effect
    new_pw_code, new_pw_message = _error(
        lambda: idp.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": new_password},
        )
    )
    assert new_pw_code == "NotAuthorizedException", f"expected new password rejected, got {new_pw_code}"
    assert new_pw_message == "Incorrect username or password.", (
        f"expected the exact wrong-password message, got {new_pw_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]
    return client["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
