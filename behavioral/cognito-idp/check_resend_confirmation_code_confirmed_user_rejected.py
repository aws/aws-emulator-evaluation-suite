"""resend-confirmation-code-confirmed-user-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resend-confirmation-code-confirmed-user-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResendConfirmationCode succeeds and reissues delivery only while the user is
    UNCONFIRMED; once the user is confirmed, calling it again is rejected with
    InvalidParameterException rather than silently succeeding."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    email = f"{username}@example.com"

    cognito.sign_up(
        ClientId=client_id,
        Username=username,
        Password=_PASSWORD,
        UserAttributes=[{"Name": "email", "Value": email}],
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    status = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", f"expected UNCONFIRMED after sign_up, got {status}"

    resend = cognito.resend_confirmation_code(ClientId=client_id, Username=username)
    medium = resend["CodeDeliveryDetails"]["DeliveryMedium"]
    assert medium == "EMAIL", f"expected EMAIL delivery, got {medium}"

    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    status = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED after admin_confirm_sign_up, got {status}"

    code, message = _rejection(
        lambda: cognito.resend_confirmation_code(ClientId=client_id, Username=username)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "User is already confirmed.", f"expected message 'User is already confirmed.', got {message!r}"

    still = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still["UserStatus"] == "CONFIRMED", f"status drifted to {still['UserStatus']}"


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    # Real Cognito rejects ResendConfirmationCode with NotAuthorizedException
    # ("Cannot resend codes. Auto verification not turned on.") for ANY user --
    # confirmed or not -- unless the pool has an AutoVerifiedAttributes entry for
    # the attribute the code targets.
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"},
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    client_id = client["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
