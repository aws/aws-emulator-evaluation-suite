"""unlink-identity-unknown-login-provider-accepted."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "unlink-identity-unknown-login-provider-accepted"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnlinkIdentity removing a provider the identity was never linked to is accepted as a no-op
    and leaves the real login intact; removing the real provider marks the identity DISABLED."""
    region = ctx.region
    cidp = ctx.client("cognito-idp")
    cip = ctx.client("cognito-identity")

    pool_id, client_id, username, password = _create_confirmed_user_pool_user(ctx, cidp)
    provider_name = f"cognito-idp.{region}.amazonaws.com/{pool_id}"

    auth = cidp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]

    ci_pool_id = cip.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=ci_pool_id))

    logins = {provider_name: id_token}
    identity_id = cip.get_id(IdentityPoolId=ci_pool_id, Logins=logins)["IdentityId"]

    before = cip.describe_identity(IdentityId=identity_id)
    assert before["Logins"] == [provider_name], before

    unrelated_provider = "graph.facebook.com"

    # A refusal raises ClientError here and fails the check: real AWS accepts this call.
    cip.unlink_identity(
        IdentityId=identity_id,
        Logins=logins,
        LoginsToRemove=[unrelated_provider],
    )

    # the no-op left the real, linked login untouched
    mid = cip.describe_identity(IdentityId=identity_id)
    assert mid["Logins"] == [provider_name], (
        f"a no-op removal must not touch the real linked login, got {mid['Logins']}"
    )

    # removing the REAL, linked provider (as opposed to the unrelated one above) does
    # detach it -- proving the earlier call was a no-op about the unrelated entry, not
    # a call that never does anything. Real AWS leaves an identity that has lost its
    # only login as Logins=["DISABLED"], not an empty list: an identity created
    # through an authenticated GetId can no longer be resolved by any Logins map once
    # its one login is gone, so it is marked unusable rather than reset to bare.
    cip.unlink_identity(IdentityId=identity_id, Logins=logins, LoginsToRemove=[provider_name])
    after = cip.describe_identity(IdentityId=identity_id)
    assert after.get("Logins") == ["DISABLED"], (
        f"the real provider should now be detached and the identity marked DISABLED, "
        f"got {after.get('Logins')}"
    )


def _create_confirmed_user_pool_user(ctx, cidp: Any) -> tuple[str, str, str, str]:
    pool_id = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-userpool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))

    client_id = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2realuser")
    password = "TestPassw0rd1"
    cidp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    cidp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    return pool_id, client_id, username, password


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
