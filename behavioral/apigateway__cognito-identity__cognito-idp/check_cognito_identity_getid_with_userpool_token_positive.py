"""cognito-identity-getid-with-userpool-token-positive."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cognito-identity-getid-with-userpool-token-positive"
GROUP = "arn-resolution"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetId with a valid User Pool token resolves to a stable IdentityId tied to the
    configured provider, and DescribeIdentity records that provider against it."""
    pool = _create_confirmed_user_pool(ctx, "sim2real-uidp-")
    identity_pool_id = _create_identity_pool(
        ctx,
        "sim2real-ip-",
        providers=[
            {
                "ProviderName": pool["provider_name"],
                "ClientId": pool["client_id"],
                "ServerSideTokenCheck": False,
            }
        ],
    )

    cid = ctx.client("cognito-identity")
    logins = {pool["provider_name"]: pool["id_token"]}

    resp1 = cid.get_id(IdentityPoolId=identity_pool_id, Logins=logins)
    identity_id_1 = resp1["IdentityId"]
    assert identity_id_1.startswith(f"{ctx.region}:"), (
        f"expected IdentityId to be prefixed with region {ctx.region!r}, got {identity_id_1!r}"
    )

    # A second GetId call with the SAME login token must resolve to the SAME identity
    # (Cognito Identity deterministically maps a given provider subject to one identity).
    resp2 = cid.get_id(IdentityPoolId=identity_pool_id, Logins=logins)
    identity_id_2 = resp2["IdentityId"]
    assert identity_id_2 == identity_id_1, (
        f"second GetId with the identical login diverged: {identity_id_2!r} vs {identity_id_1!r}"
    )

    described = cid.describe_identity(IdentityId=identity_id_1)
    assert pool["provider_name"] in described["Logins"], (
        f"expected provider {pool['provider_name']!r} in DescribeIdentity Logins, "
        f"got {described['Logins']!r}"
    )


def _create_confirmed_user_pool(ctx, name_prefix: str) -> dict:
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name(name_prefix)
    pool_id = idp.create_user_pool(
        PoolName=pool_name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-uidp"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=pool_name + "-client",
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("user-")
    password = "Sim2Real1!Aa"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return {
        "pool_id": pool_id,
        "client_id": client_id,
        "username": username,
        "id_token": id_token,
        "provider_name": provider_name,
    }


def _create_identity_pool(ctx, name_prefix: str, providers=None, allow_unauth: bool = False) -> str:
    cid = ctx.client("cognito-identity")
    name = ctx.unique_name(name_prefix)
    pool_id = cid.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        CognitoIdentityProviders=providers or [],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
