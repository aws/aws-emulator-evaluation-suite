"""forgot-password-wrong-code-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forgot-password-wrong-code-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_LENIENT_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, so an
    emulator accepting a call real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After ForgotPassword sends a code by EMAIL for the email attribute, ConfirmForgotPassword with a
    wrong code fails with CodeMismatchException; the original password still signs in and the
    proposed one fails with NotAuthorizedException, each refusal with its exact message."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
        AutoVerifiedAttributes=["email"],
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    password = "Str0ngPassw0rd!"
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    new_password = "BrandNewPassw0rd!"
    delivery = c.forgot_password(ClientId=client_id, Username=username)["CodeDeliveryDetails"]
    assert delivery["AttributeName"] == "email", (
        f"expected the reset code delivered to email, got {delivery['AttributeName']!r}"
    )
    assert delivery["DeliveryMedium"] == "EMAIL", (
        f"expected EMAIL delivery medium, got {delivery['DeliveryMedium']!r}"
    )

    code = _error(
        lambda: c.confirm_forgot_password(
            ClientId=client_id,
            Username=username,
            ConfirmationCode="000000",
            Password=new_password,
        )
    )
    assert code == ("CodeMismatchException", "Invalid verification code provided, please try again."), (
        f"expected CodeMismatchException, got {code!r}"
    )

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    assert auth["AccessToken"], "original password should still work unchanged"

    new_pw_code = _error(
        lambda: c.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": new_password},
        )
    )
    assert new_pw_code == ("NotAuthorizedException", "Incorrect username or password."), (
        f"expected the rejected reset's new password to be unusable, got {new_pw_code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
