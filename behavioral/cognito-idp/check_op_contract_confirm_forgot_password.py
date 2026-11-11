"""op-contract-confirmForgotPassword."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-confirmForgotPassword"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmForgotPassword fails with UserNotFoundException for an unknown username and with
    CodeMismatchException for a wrong code on a real reset, each with its exact message; the old
    password still signs in and the proposed one fails with NotAuthorizedException."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]
    client_id = client["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    email = f"{ctx.unique_name('sim2real-fp-')}@example.com"
    old_password = "TempPass!23"
    new_password = "Other!789"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=old_password,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=old_password, Permanent=True
    )

    try:
        cognito.forgot_password(ClientId=client_id, Username=username)
    except ClientError as err:
        if err.response["Error"]["Code"] == "CodeDeliveryFailureException":
            raise AssertionError("forgot-password code delivery is unavailable in this environment")
        raise

    # error boundary #1: nonexistent username
    code1 = _client_error(
        lambda: cognito.confirm_forgot_password(
            ClientId=client_id, Username="no-such-user-xyz", ConfirmationCode="000000", Password="Other!789"
        )
    )
    assert code1.get("Code") == "UserNotFoundException", code1
    assert code1.get("Message") == "Username/client id combination not found.", code1.get("Message")

    # error boundary #2: real user, real in-flight flow, wrong code
    code2 = _client_error(
        lambda: cognito.confirm_forgot_password(
            ClientId=client_id, Username=username, ConfirmationCode="000000", Password=new_password
        )
    )
    assert code2.get("Code") == "CodeMismatchException", code2
    assert code2.get("Message") == "Invalid verification code provided, please try again.", code2.get("Message")

    # terminal read: an independent auth call, not the rejecting call's own response,
    # proves the reset never took effect -- the old password still authenticates and
    # the "new" one does not
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": old_password},
    )
    assert "AuthenticationResult" in auth, "old password no longer authenticates after a rejected reset"

    new_pw_code = _client_error(
        lambda: cognito.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": new_password},
        )
    )
    assert new_pw_code.get("Code") == "NotAuthorizedException", f"expected new password rejected, got {new_pw_code}"
    assert new_pw_code.get("Message") == "Incorrect username or password.", new_pw_code.get("Message")


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
