"""forgot-password-code-expires-after-ttl."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forgot-password-code-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A wrong code against a fresh ForgotPassword code is CodeMismatchException (not Expired),
    and the original password still signs in. The fixed code TTL cannot be shortened, so actual
    expiry is not exercised.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        AutoVerifiedAttributes=["email"],
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))

    username = ctx.unique_name("sim2real-user-")
    email = f"{username}@example.com"
    password = "Sim2Real!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
        ],
        TemporaryPassword="Temp0rary!Passw0rd",
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: _ignore(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    forgot = idp.forgot_password(ClientId=client_id, Username=username)
    assert "CodeDeliveryDetails" in forgot, "ForgotPassword must issue a real delivered reset code"

    code = _error(lambda: idp.confirm_forgot_password(
        ClientId=client_id,
        Username=username,
        ConfirmationCode="000000",
        Password="NewSim2Real!Passw0rd",
    ))
    assert code == ("CodeMismatchException", "Invalid verification code provided, please try again."), (
        f"expected CodeMismatchException for a wrong-but-not-yet-expired code, got {code!r}"
    )

    # The rejected reset must have no side effect: the original password still signs in.
    auth = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in auth, (
        "the original password must still authenticate after the rejected reset attempt"
    )


def _error(fn):
    """Call fn() and return its error (Code, Message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
