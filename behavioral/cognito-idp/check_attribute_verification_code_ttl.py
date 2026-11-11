"""attribute-verification-code-ttl."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-verification-code-ttl"
GROUP = 'overly-permissive'
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
PASSWORD = "Str0ngPassw0rd!"
_AUTH_FLOWS = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


def _err(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _new_confirmed_user(ctx, c, pool_id, password=PASSWORD, **extra_attrs):
    username = ctx.unique_name("sim2real-behav-cip-user-")
    attrs = [{"Name": "email", "Value": f"{username}@example.com"}]
    attrs.extend({"Name": k, "Value": v} for k, v in extra_attrs.items())
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


def _admin_login(c, pool_id, client_id, username, password):
    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUserAttributeVerificationCode for email reports delivery by EMAIL, VerifyUserAttribute
    with a wrong code is refused with CodeMismatchException and the exact message and leaves email
    unverified, and an admin update can still verify it."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    username, password = _new_confirmed_user(ctx, c, pool_id)
    auth = _admin_login(c, pool_id, client_id, username, password)
    access_token = auth["AccessToken"]

    first = c.get_user_attribute_verification_code(AccessToken=access_token, AttributeName="email")
    delivery = first["CodeDeliveryDetails"]
    assert delivery["AttributeName"] == "email", delivery
    assert delivery["DeliveryMedium"] == "EMAIL", delivery

    code, code_msg = _err(
        lambda: c.verify_user_attribute(
            AccessToken=access_token, AttributeName="email", Code="000000"
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    assert code_msg == 'Invalid verification code provided, please try again.', f"expected the exact {code} message, got {code_msg!r}"

    got = c.get_user(AccessToken=access_token)
    email_verified = next(
        (a["Value"] for a in got["UserAttributes"] if a["Name"] == "email_verified"), None
    )
    # Cognito omits "email_verified" entirely rather than emitting an explicit "false" for a
    # never-verified attribute; either absence or "false" means "still unverified" -- only an
    # explicit "true" would indicate the rejected code somehow succeeded.
    assert email_verified in (None, "false"), (
        f"attribute must remain unverified after a rejected code, got {email_verified}"
    )

    # Positive control: the admin path still verifies the same user's email, so the rejection
    # above is specific to the wrong code.
    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email_verified", "Value": "true"}],
    )
    restored = c.get_user(AccessToken=access_token)
    restored_verified = next(
        (a["Value"] for a in restored["UserAttributes"] if a["Name"] == "email_verified"), None
    )
    assert restored_verified == "true", (
        f"a legitimate (admin) path to verified must still work for this user, got {restored_verified}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
