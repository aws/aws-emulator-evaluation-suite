"""confirm-forgot-password-invalid-code."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confirm-forgot-password-invalid-code"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd1"
_NEW_PASSWORD = "Sim2Real!Passw0rd2"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ForgotPassword delivers a code; ConfirmForgotPassword with a wrong code is
    rejected with CodeMismatchException and leaves the password unchanged."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    email = f"{username}@example.com"
    _admin_create_confirmed_user(ctx, pool_id, username, _PASSWORD, email=email, email_verified=True)

    fp_resp = cognito.forgot_password(ClientId=client_id, Username=username)
    details = fp_resp["CodeDeliveryDetails"]
    assert details["AttributeName"] == "email", f"expected delivery to email, got {details['AttributeName']}"
    assert details["DeliveryMedium"] == "EMAIL", f"expected EMAIL delivery, got {details['DeliveryMedium']}"

    code, message = _error(
        lambda: cognito.confirm_forgot_password(
            ClientId=client_id,
            Username=username,
            ConfirmationCode="000000",
            Password=_NEW_PASSWORD,
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    assert message == "Invalid verification code provided, please try again.", (
        f"expected the exact code-mismatch message, got {message!r}"
    )

    # effect absent, both sides: the original password still authenticates...
    auth = _admin_login(ctx, pool_id, client_id, username, _PASSWORD)
    assert "AccessToken" in auth, f"expected original password to still authenticate, got {auth}"

    # ...and the password the rejected call tried to set never took effect.
    new_pw_code, new_pw_message = _error(
        lambda: _admin_login(ctx, pool_id, client_id, username, _NEW_PASSWORD)
    )
    assert new_pw_code == "NotAuthorizedException", (
        f"expected rejected new password to not authenticate, got {new_pw_code}"
    )
    assert new_pw_message == "Incorrect username or password.", (
        f"expected the exact wrong-password message, got {new_pw_message!r}"
    )


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool-"},
        DeletionProtection="INACTIVE",
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


def _admin_create_confirmed_user(ctx, pool_id, username, password, email=None, email_verified=False):
    cognito = ctx.client("cognito-idp")
    attrs = []
    if email:
        attrs.append({"Name": "email", "Value": email})
        if email_verified:
            attrs.append({"Name": "email_verified", "Value": "true"})
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=attrs,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_login(ctx, pool_id, client_id, username, password):
    cognito = ctx.client("cognito-idp")
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
