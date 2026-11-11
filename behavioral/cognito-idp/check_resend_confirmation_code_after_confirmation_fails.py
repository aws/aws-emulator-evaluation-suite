"""resend-confirmation-code-after-confirmation-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "resend-confirmation-code-after-confirmation-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResendConfirmationCode succeeds and reissues delivery for an UNCONFIRMED user (positive
    control, on the same pool/client wiring); once the same user reaches CONFIRMED, the identical
    call is rejected and the status is unaffected by the rejected attempt."""
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

    unconfirmed = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert unconfirmed["UserStatus"] == "UNCONFIRMED", (
        f"expected UNCONFIRMED, got {unconfirmed['UserStatus']}"
    )

    # positive control: resend must succeed and reissue delivery while UNCONFIRMED, on the exact
    # pool/client wiring the later rejection is asserted against -- otherwise a pool that rejects
    # ResendConfirmationCode unconditionally (e.g. no AutoVerifiedAttributes) would pass this
    # check for a reason that has nothing to do with confirmation status.
    resend = idp.resend_confirmation_code(ClientId=client_id, Username=username)
    details = resend["CodeDeliveryDetails"]
    assert details["DeliveryMedium"] == "EMAIL", details

    # confirm administratively (no real code needed) to reach CONFIRMED status
    idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    confirmed = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert confirmed["UserStatus"] == "CONFIRMED", f"expected CONFIRMED, got {confirmed['UserStatus']}"

    code, message = _rejection(lambda: idp.resend_confirmation_code(ClientId=client_id, Username=username))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "User is already confirmed.", f"expected message 'User is already confirmed.', got {message!r}"

    # status must remain CONFIRMED, unaffected by the rejected resend attempt
    still = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still["UserStatus"] == "CONFIRMED", f"status drifted to {still['UserStatus']}"


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        AutoVerifiedAttributes=["email"],
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        },
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
