"""confirm-signup-code-mismatch-fails."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "confirm-signup-code-mismatch-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmSignUp with a wrong code is refused with CodeMismatchException and the exact message,
    the user stays UNCONFIRMED and login answers UserNotConfirmedException; AdminConfirmSignUp then
    confirms the user, who can log in."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-behav-user-")
    password = "TestPassw0rd!1"
    idp.sign_up(
        ClientId=client_id,
        Username=username,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    code, message = _error(
        lambda: idp.confirm_sign_up(
            ClientId=client_id, Username=username, ConfirmationCode="000000"
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    assert message == "Invalid verification code provided, please try again.", (
        f"expected the exact code-mismatch message, got {message!r}"
    )

    # user should remain unconfirmed since the (wrong) code was rejected
    user = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["UserStatus"] == "UNCONFIRMED", f"unexpected status {user['UserStatus']}"

    # effect absent via a second independent read: login is still blocked for the unconfirmed user
    login_code, login_message = _error(
        lambda: idp.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert login_code == "UserNotConfirmedException", (
        f"expected UserNotConfirmedException, got {login_code}"
    )
    assert login_message == "User is not confirmed.", (
        f"expected the exact unconfirmed-user message, got {login_message!r}"
    )

    # positive control: a legitimate confirmation path still works for this same user, proving
    # the earlier rejection was specific to the wrong code and not a blanket ConfirmSignUp failure
    idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    user = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["UserStatus"] == "CONFIRMED", f"unexpected status {user['UserStatus']}"
    auth = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AccessToken" in auth["AuthenticationResult"], f"expected AccessToken, got {auth}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


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
        # Without it no confirmation code is generated, and a wrong code answers
        # ExpiredCodeException rather than CodeMismatchException.
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id: str, extra_flows: list[str] | None = None) -> str:
    idp = ctx.client("cognito-idp")
    flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    if extra_flows:
        flows = list(set(flows + extra_flows))
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=flows,
        GenerateSecret=False,
    )["UserPoolClient"]
    return client["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
