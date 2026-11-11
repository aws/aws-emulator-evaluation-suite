"""confirm-signup-wrong-code-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "confirm-signup-wrong-code-rejected"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmSignUp with a wrong code fails with CodeMismatchException and leaves the user
    UNCONFIRMED and unable to log in; AdminConfirmSignUp then confirms the user and login works."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-confirm-neg-pool-"),
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
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-confirm-neg"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-confirm-neg-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("s2rnegconfirm")
    password = "Str0ngPassw0rd!"
    email = f"{username}@example.com"

    cognito.sign_up(
        ClientId=client_id,
        Username=username,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": email}],
    )

    code, message = _error(
        lambda: cognito.confirm_sign_up(
            ClientId=client_id, Username=username, ConfirmationCode="000000"
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    assert message == "Invalid verification code provided, please try again.", (
        f"expected the exact code-mismatch message, got {message!r}"
    )

    status = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", f"expected UNCONFIRMED after a rejected code, got {status}"
    login_code, login_message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert login_code == "UserNotConfirmedException", (
        f"expected UserNotConfirmedException while unconfirmed, got {login_code}"
    )
    assert login_message == "User is not confirmed.", (
        f"expected the exact unconfirmed-user message, got {login_message!r}"
    )

    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    status = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED after AdminConfirmSignUp, got {status}"
    auth = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AccessToken" in auth["AuthenticationResult"], (
        f"expected AccessToken after confirming and logging in, got {auth['AuthenticationResult']}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
