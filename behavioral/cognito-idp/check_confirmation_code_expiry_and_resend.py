"""confirmation-code-expiry-and-resend."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confirmation-code-expiry-and-resend"
GROUP = 'signup-state-machine'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_AUTH_FLOWS = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


def _err(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResendConfirmationCode for an unconfirmed user reports EMAIL delivery; ConfirmSignUp with a
    wrong code is then rejected with CodeMismatchException and the user stays UNCONFIRMED, while
    AdminConfirmSignUp (no code needed) moves the account to CONFIRMED."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    username = ctx.unique_name("sim2real-behav-cip-confcode-")
    password = "Str0ngPassw0rd!"

    c.sign_up(
        ClientId=client_id,
        Username=username,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))

    resend1 = c.resend_confirmation_code(ClientId=client_id, Username=username)
    assert resend1["CodeDeliveryDetails"]["DeliveryMedium"] == "EMAIL", resend1

    code, message = _err(
        lambda: c.confirm_sign_up(
            ClientId=client_id, Username=username, ConfirmationCode="000000"
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    assert message == "Invalid verification code provided, please try again.", (
        f"expected the exact code-mismatch message, got {message!r}"
    )

    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", f"user should remain UNCONFIRMED, got {status}"

    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"AdminConfirmSignUp should confirm the account, got {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
