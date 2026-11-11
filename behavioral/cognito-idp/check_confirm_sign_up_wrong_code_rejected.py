"""confirm-sign-up-wrong-code-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confirm-sign-up-wrong-code-rejected"
GROUP = 'signup-state-machine'
SERVICES = ['cognito-idp']

# A password that satisfies the default Cognito password policy
# (min length 8, upper, lower, number, symbol).
DEFAULT_PASSWORD = "TempPassw0rd!23"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _create_user_pool(idp, ctx, **kwargs):
    """Create a user pool with cleanup; deleting it cascades to its clients and users."""
    name = ctx.unique_name("sim2real-behav-cip-pool-")
    pool = idp.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        **kwargs,
    )["UserPool"]
    ctx.on_cleanup(lambda _id=pool["Id"]: idp.delete_user_pool(UserPoolId=_id))
    return pool


def _create_user_pool_client(idp, ctx, pool_id, explicit_auth_flows=None, **kwargs):
    """Create an app client. Tracking is implicit: deleting the pool cascades."""
    if explicit_auth_flows is None:
        explicit_auth_flows = [
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_SRP_AUTH",
        ]
    return idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=explicit_auth_flows,
        GenerateSecret=False,
        **kwargs,
    )["UserPoolClient"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmSignUp with a never-issued code fails with ExpiredCodeException and leaves the user
    UNCONFIRMED and unable to log in; AdminConfirmSignUp then confirms the user and login works."""
    idp = ctx.client("cognito-idp")
    pool = _create_user_pool(idp, ctx)
    client = _create_user_pool_client(idp, ctx, pool["Id"])
    username = ctx.unique_name("sim2real-behav-cip-signup-")

    idp.sign_up(
        ClientId=client["ClientId"], Username=username, Password=DEFAULT_PASSWORD
    )

    code, message = _error(
        lambda: idp.confirm_sign_up(
            ClientId=client["ClientId"], Username=username, ConfirmationCode="000000"
        )
    )
    # No live code exists to compare against, so AWS reports ExpiredCodeException, not
    # CodeMismatchException.
    assert code == "ExpiredCodeException", f"expected ExpiredCodeException, got {code}"
    assert message == "Invalid code provided, please request a code again.", (
        f"expected the exact never-issued-code message, got {message!r}"
    )

    status = idp.admin_get_user(UserPoolId=pool["Id"], Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", f"expected UNCONFIRMED after rejected confirm, got {status}"
    login_code, login_message = _error(
        lambda: idp.initiate_auth(
            ClientId=client["ClientId"],
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": DEFAULT_PASSWORD},
        )
    )
    assert login_code == "UserNotConfirmedException", (
        f"expected UserNotConfirmedException, got {login_code}"
    )
    assert login_message == "User is not confirmed.", (
        f"expected the exact unconfirmed-user message, got {login_message!r}"
    )

    idp.admin_confirm_sign_up(UserPoolId=pool["Id"], Username=username)
    status = idp.admin_get_user(UserPoolId=pool["Id"], Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED after admin bypass, got {status}"
    auth = idp.initiate_auth(
        ClientId=client["ClientId"],
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": DEFAULT_PASSWORD},
    )
    assert "AccessToken" in auth["AuthenticationResult"], f"expected AccessToken, got {auth}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
