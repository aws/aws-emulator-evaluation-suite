"""change-password-wrong-previous-password-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-password-wrong-previous-password-rejected"
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
    """Overly-permissive boundary: ChangePassword with an incorrect PreviousPassword MUST be
    rejected with NotAuthorizedException -- a stolen access token must not be sufficient to rotate
    the password without also knowing the current one."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    username, password = _new_confirmed_user(ctx, c, pool_id)
    auth = _admin_login(c, pool_id, client_id, username, password)
    access_token = auth["AccessToken"]

    # Positive control: ChangePassword must actually succeed with the CORRECT previous password
    # first. Without this, "rejects a wrong previous password" is indistinguishable from "rejects
    # every ChangePassword call" -- a target that never allows rotation would pass the rejection
    # assertion below for the wrong reason.
    rotated_password = "R0tatedContr0lPassw0rd!"
    c.change_password(
        AccessToken=access_token, PreviousPassword=password, ProposedPassword=rotated_password
    )
    control_auth = _admin_login(c, pool_id, client_id, username, rotated_password)
    assert control_auth["AccessToken"], "positive control: rotated password did not authenticate"

    code, code_msg = _err(
        lambda: c.change_password(
            AccessToken=access_token,
            PreviousPassword="TotallyWrongPassw0rd!",
            ProposedPassword="SomeNewPassw0rd!",
        )
    )
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    assert code_msg == 'Incorrect username or password.', f"expected the exact {code} message, got {code_msg!r}"

    auth2 = _admin_login(c, pool_id, client_id, username, rotated_password)
    assert auth2["AccessToken"], "expected the rotated password to still authenticate after the rejected attempt"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
