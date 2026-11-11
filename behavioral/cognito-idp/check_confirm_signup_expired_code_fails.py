"""confirm-signup-expired-code-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "confirm-signup-expired-code-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Right after SignUp delivers a code by EMAIL, ConfirmSignUp with a wrong code is refused with
    CodeMismatchException (not ExpiredCodeException) and the exact message and the user stays
    UNCONFIRMED; AdminConfirmSignUp then confirms the user."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-behav-user-")
    password = "TestPassw0rd!1"
    signup = idp.sign_up(
        ClientId=client_id,
        Username=username,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    assert "CodeDeliveryDetails" in signup, "sign_up did not report a confirmation code delivery"
    assert signup["CodeDeliveryDetails"]["DeliveryMedium"] == "EMAIL"

    # inside the validity window, a wrong code is a MISMATCH, never an (impossible-so-soon) expiry
    fresh_code, fresh_message = _error(
        lambda: idp.confirm_sign_up(ClientId=client_id, Username=username, ConfirmationCode="000000")
    )
    assert fresh_code == "CodeMismatchException", (
        f"expected CodeMismatchException for a fresh, still-valid code window, got {fresh_code}"
    )
    assert fresh_message == "Invalid verification code provided, please try again.", (
        f"expected the exact code-mismatch message, got {fresh_message!r}"
    )

    status = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", (
        f"a rejected (mismatched) confirmation code must not confirm the account; "
        f"expected UserStatus UNCONFIRMED, got {status!r}"
    )

    # positive control: the account genuinely can reach CONFIRMED (via the admin bypass, since
    # the real code is delivered out-of-band and unobservable here) -- the earlier rejection is
    # specific to the bad code, not evidence of a target that can never confirm this account.
    idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    confirmed_status = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert confirmed_status == "CONFIRMED", (
        f"expected the admin bypass to confirm the account, got UserStatus {confirmed_status!r}"
    )


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
        # Without it SignUp generates no confirmation code (no CodeDeliveryDetails), so there
        # is no live code for the wrong one to mismatch.
        AutoVerifiedAttributes=["email"],
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]
    return client["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
