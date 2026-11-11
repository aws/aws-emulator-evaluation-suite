"""op-contract-confirmSignUp."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-confirmSignUp"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfirmSignUp rejects a nonexistent username and a wrong code for an UNCONFIRMED user,
    with exact messages; AdminConfirmSignUp then confirms the same user and login succeeds,
    so the rejections are specific rather than a blanket failure."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]
    client_id = client["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    email = f"{ctx.unique_name('sim2real-su-')}@example.com"
    try:
        signup = cognito.sign_up(
            ClientId=client_id,
            Username=username,
            Password="SignUp!234",
            UserAttributes=[{"Name": "email", "Value": email}],
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "CodeDeliveryFailureException":
            raise AssertionError("sign-up code delivery is unavailable in this environment")
        raise
    assert signup["UserConfirmed"] is False, f"expected UserConfirmed False right after SignUp, got {signup['UserConfirmed']}"

    got = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got["UserStatus"] == "UNCONFIRMED", got["UserStatus"]

    code1 = _client_error(
        lambda: cognito.confirm_sign_up(ClientId=client_id, Username="no-such-user-xyz", ConfirmationCode="000000")
    )
    assert code1.get("Code") == "UserNotFoundException", code1
    assert code1.get("Message") == "Username/client id combination not found.", code1.get("Message")

    code2 = _client_error(
        lambda: cognito.confirm_sign_up(ClientId=client_id, Username=username, ConfirmationCode="000000")
    )
    assert code2.get("Code") == "CodeMismatchException", code2
    assert code2.get("Message") == "Invalid verification code provided, please try again.", code2.get("Message")

    still = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still["UserStatus"] == "UNCONFIRMED", still["UserStatus"]

    # Positive control: proves the rejections above are specific to the bad inputs.
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    confirmed = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert confirmed["UserStatus"] == "CONFIRMED", confirmed["UserStatus"]
    auth = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": "SignUp!234"},
    )
    assert "AccessToken" in auth["AuthenticationResult"], auth


def _client_error(fn) -> dict:
    """Call fn() and return its botocore Error dict; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
