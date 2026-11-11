"""get-user-auth-factors-baseline-empty-before-mfa-setup."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-auth-factors-baseline-empty-before-mfa-setup"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUserAuthFactors returns an empty MFA settings list and no preferred
    MFA setting for a freshly created, confirmed user that has never
    configured any MFA factor."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    _create_confirmed_user(ctx, pool_id, username, password)
    access_token = _admin_password_auth(ctx, pool_id, client_id, username, password)["AccessToken"]

    resp = idp.get_user_auth_factors(AccessToken=access_token)

    assert "UserMFASettingList" not in resp, f"expected no UserMFASettingList key for a user with no MFA configured, got {resp.get('UserMFASettingList')!r}"
    assert "PreferredMfaSetting" not in resp, f"expected no PreferredMfaSetting key for a user with no MFA configured, got {resp.get('PreferredMfaSetting')!r}"
    assert resp["Username"] == username, f"expected Username={username!r}, got {resp.get('Username')!r}"


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    resp = idp.create_user_pool(PoolName=name, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-client-")
    kwargs.setdefault("ExplicitAuthFlows", ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])
    resp = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=name, GenerateSecret=False, **kwargs)
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username, password, user_attributes=None):
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
        UserAttributes=user_attributes or [],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_password_auth(ctx, pool_id, client_id, username, password):
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
