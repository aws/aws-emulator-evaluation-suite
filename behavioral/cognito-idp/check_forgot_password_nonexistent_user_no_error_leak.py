"""forgot-password-nonexistent-user-no-error-leak."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forgot-password-nonexistent-user-no-error-leak"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ForgotPassword doesn't leak user existence: real and fake usernames get the same shape."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    # explicitly enable existence-error masking so behavior is deterministic regardless
    # of account-level defaults
    client_id = _create_client(ctx, pool_id, prevent_user_existence_errors="ENABLED")

    real_username = ctx.unique_name("sim2real-behav-user-")
    password = "TestPassw0rd!1"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=real_username,
        UserAttributes=[
            {"Name": "email", "Value": f"{real_username}@example.com"},
            # ForgotPassword requires a verified attribute to deliver the reset code to;
            # real Cognito rejects with InvalidParameterException otherwise.
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=real_username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=real_username, Password=password, Permanent=True)

    real_resp = idp.forgot_password(ClientId=client_id, Username=real_username)
    real_status = real_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert real_status == 200, f"expected HTTP 200 for a real user, got {real_status}"
    assert "CodeDeliveryDetails" in real_resp, "real user should get real CodeDeliveryDetails"
    real_details = real_resp["CodeDeliveryDetails"]
    assert real_details["AttributeName"] == "email", (
        f"expected AttributeName 'email', got {real_details['AttributeName']!r}"
    )
    assert real_details["DeliveryMedium"] == "EMAIL", (
        f"expected DeliveryMedium 'EMAIL', got {real_details['DeliveryMedium']!r}"
    )
    # real destination must be masked (e.g. "s***@example.com"), never the raw address
    assert "*" in real_details["Destination"], f"unmasked destination leaked: {real_details['Destination']!r}"
    assert f"{real_username}@example.com" not in real_details["Destination"], (
        f"raw email address leaked in destination: {real_details['Destination']!r}"
    )

    fake_username = ctx.unique_name("sim2real-behav-nouser-")
    try:
        fake_resp = idp.forgot_password(ClientId=client_id, Username=fake_username)
    except ClientError as err:
        raise AssertionError(
            f"ForgotPassword for a nonexistent user leaked existence via error "
            f"{err.response['Error'].get('Code')!r}; with PreventUserExistenceErrors=ENABLED it "
            "must respond like a real user"
        ) from err
    fake_status = fake_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert fake_status == 200, f"expected HTTP 200 for a nonexistent user, got {fake_status}"
    # both responses must share the same top-level shape (both carry CodeDeliveryDetails,
    # or both omit it) -- no asymmetry that would let a caller distinguish real from fake
    assert ("CodeDeliveryDetails" in real_resp) == ("CodeDeliveryDetails" in fake_resp), (
        "real vs nonexistent-user ForgotPassword responses have different shapes, "
        "which leaks user existence"
    )

    # the fabricated details for the nonexistent user must mimic a REAL delivery channel's
    # shape/pattern, not just an empty/absent placeholder. Real Cognito does NOT mirror the
    # probed username's own verified attribute here: the fabricated channel varies between
    # email/EMAIL and phone_number/SMS from call to call for the same pool and client (the
    # account has no phone attribute verified at all). The contract that actually holds is narrower: whichever channel is fabricated,
    # AttributeName/DeliveryMedium/Destination must be a self-consistent, real delivery
    # triple, never a channel Cognito cannot deliver to and never a destination shaped for
    # the wrong medium.
    fake_details = fake_resp["CodeDeliveryDetails"]
    fake_attribute = fake_details["AttributeName"]
    fake_medium = fake_details["DeliveryMedium"]
    fake_destination = fake_details["Destination"]
    assert fake_attribute in ("email", "phone_number"), (
        f"fabricated AttributeName must be a real delivery channel, got {fake_attribute!r}"
    )
    if fake_attribute == "email":
        assert fake_medium == "EMAIL", (
            f"AttributeName 'email' must pair with DeliveryMedium 'EMAIL', got {fake_medium!r}"
        )
        email_pattern = re.compile(r"^.+\*+.*@.+$")
        assert email_pattern.match(fake_destination), (
            f"fake-user email Destination {fake_destination!r} doesn't follow the masked "
            "email pattern"
        )
    else:
        assert fake_medium == "SMS", (
            f"AttributeName 'phone_number' must pair with DeliveryMedium 'SMS', got {fake_medium!r}"
        )
        phone_pattern = re.compile(r"^\+\*+\d+$")
        assert phone_pattern.match(fake_destination), (
            f"fake-user phone Destination {fake_destination!r} doesn't follow the masked "
            "phone pattern"
        )


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        # email must be auto-verified so ForgotPassword can deliver to the REAL known user's
        # verified email at all. It does NOT constrain what real Cognito fabricates for the
        # nonexistent user below -- that is chosen independently of pool config (see the
        # fabricated-channel assertions further down).
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


def _create_client(ctx, pool_id: str, prevent_user_existence_errors: str = "LEGACY") -> str:
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
        PreventUserExistenceErrors=prevent_user_existence_errors,
    )["UserPoolClient"]
    return client["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
