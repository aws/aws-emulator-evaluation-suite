"""merge-developer-identities-preserves-login-insertion-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "merge-developer-identities-preserves-login-insertion-order"
GROUP = "ordering"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """MergeDeveloperIdentities keeps the survivor's existing Logins order unchanged and leaves both
    the developer provider and the user-pool provider in it, the developer provider first."""
    cid = ctx.client("cognito-identity")
    up = _create_user_pool_and_id_token(ctx)
    provider_name = up["provider_name"]

    # Chosen so it sorts BEFORE the "cognito-idp...." provider name alphabetically: if a merge
    # implementation resorted Logins alphabetically instead of preserving insertion order, the
    # assertions below would catch it.
    dev_provider = "aaa-" + ctx.unique_name("sim2real-dev-")

    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": up["client_id"], "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    dest_user = ctx.unique_name("sim2real-destuser-")
    src_user = ctx.unique_name("sim2real-srcuser-")

    # Destination identity: Cognito user-pool login added first (via GetId), developer login
    # linked second (via GetOpenIdTokenForDeveloperIdentity with an existing IdentityId).
    dest_identity_id = cid.get_id(IdentityPoolId=pool_id, Logins={provider_name: up["id_token"]})[
        "IdentityId"
    ]
    ctx.on_cleanup(lambda: cid.delete_identities(IdentityIdsToDelete=[dest_identity_id]))
    cid.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        IdentityId=dest_identity_id,
        Logins={provider_name: up["id_token"], dev_provider: dest_user},
    )

    before = cid.describe_identity(IdentityId=dest_identity_id)["Logins"]
    assert sorted(before) == sorted([provider_name, dev_provider]), (
        f"expected both providers linked pre-merge, got {before}"
    )

    # Source identity: developer login only, to be merged away.
    src_identity_id = cid.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: src_user}
    )["IdentityId"]
    ctx.on_cleanup(lambda: cid.delete_identities(IdentityIdsToDelete=[src_identity_id]))

    merged = cid.merge_developer_identities(
        SourceUserIdentifier=src_user,
        DestinationUserIdentifier=dest_user,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    # MergeDeveloperIdentities returns the surviving IdentityId (the source on AWS); either
    # pre-merge identity is accepted as survivor, and the Logins-order comparison below uses the
    # one the service designates.
    survivor_id = merged["IdentityId"]
    assert survivor_id in (dest_identity_id, src_identity_id), (
        f"merge produced an IdentityId ({survivor_id}) that is neither pre-merge identity "
        f"(dest={dest_identity_id}, src={src_identity_id})"
    )

    after = cid.describe_identity(IdentityId=survivor_id)["Logins"]
    if survivor_id == dest_identity_id:
        assert after == before, (
            f"merge changed the destination's pre-existing Logins order: before={before}, after={after}"
        )
    else:
        # The source survived: its pre-merge Logins was exactly [dev_provider], which must stay
        # ahead of whatever the merge appends from the retired destination identity.
        assert dev_provider in after and provider_name in after, (
            f"expected both providers linked on the surviving identity, got {after}"
        )
        assert after.index(dev_provider) < after.index(provider_name), (
            f"merge reordered the surviving source identity's pre-existing login: {after}"
        )


def _create_user_pool_and_id_token(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-userpool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Behav-Pw1!"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return {
        "user_pool_id": pool_id,
        "client_id": client_id,
        "id_token": id_token,
        "provider_name": provider_name,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
