"""admin-reset-password-code-ttl."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-reset-password-code-ttl"
GROUP = 'user-lifecycle'
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


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _admin_initiate_auth_raw(c, pool_id, client_id, username, password):
    return c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )


def _admin_login(c, pool_id, client_id, username, password):
    resp = _admin_initiate_auth_raw(c, pool_id, client_id, username, password)
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminResetUserPassword moves a CONFIRMED user to RESET_REQUIRED (old password refused with
    PasswordResetRequiredException); AdminSetUserPassword(Permanent=False) then yields
    FORCE_CHANGE_PASSWORD and a NEW_PASSWORD_REQUIRED challenge that resolves back to CONFIRMED."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    username, old_password = _new_confirmed_user(ctx, c, pool_id, email_verified="true")

    # Positive control: the login succeeds before the reset, so the later rejection is the reset's.
    control = _admin_login(c, pool_id, client_id, username, old_password)
    assert control["AccessToken"], control

    c.admin_reset_user_password(UserPoolId=pool_id, Username=username)
    status1 = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status1 == "RESET_REQUIRED", status1

    code, message = _error(lambda: _admin_login(c, pool_id, client_id, username, old_password))
    assert code == "PasswordResetRequiredException", (
        f"expected PasswordResetRequiredException for a RESET_REQUIRED user, got {code}"
    )
    expected_message = "Password reset required for the user"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    temp_password = "FreshTempCred0!"
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=temp_password, Permanent=False
    )
    status2 = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status2 == "FORCE_CHANGE_PASSWORD", status2

    challenge = _admin_initiate_auth_raw(c, pool_id, client_id, username, temp_password)
    assert challenge.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", challenge.get("ChallengeName")

    final_password = "AfterResetPermanent0!"
    completed = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=challenge["Session"],
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": final_password},
    )
    assert "AuthenticationResult" in completed, completed

    status3 = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status3 == "CONFIRMED", status3


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
