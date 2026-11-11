"""get-id-consistent-across-multiple-logins-same-identity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-id-consistent-across-multiple-logins-same-identity"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once two login providers have been linked to the same identity (via a single GetId call
    naming both), calling GetId again with either provider alone resolves back to that same
    IdentityId."""
    ci = ctx.client("cognito-identity")

    pool1_id, client1_id, provider1 = _create_user_pool_client(ctx)
    pool2_id, client2_id, provider2 = _create_user_pool_client(ctx)

    email1 = f"{ctx.unique_name('sim2real-behav-p1-')}@example.com"
    email2 = f"{ctx.unique_name('sim2real-behav-p2-')}@example.com"
    token1 = _create_confirmed_user_id_token(ctx, pool1_id, client1_id, email1)
    token2 = _create_confirmed_user_id_token(ctx, pool2_id, client2_id, email2)

    identity_pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[
            {"ProviderName": provider1, "ClientId": client1_id, "ServerSideTokenCheck": False},
            {"ProviderName": provider2, "ClientId": client2_id, "ServerSideTokenCheck": False},
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )
    identity_pool_id = identity_pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=identity_pool_id))

    # Link both providers to the same identity in one call.
    linked_id = ci.get_id(
        IdentityPoolId=identity_pool_id,
        Logins={provider1: token1, provider2: token2},
    )["IdentityId"]

    # Each provider used alone must now resolve back to the same linked identity.
    id_from_provider1 = ci.get_id(IdentityPoolId=identity_pool_id, Logins={provider1: token1})["IdentityId"]
    id_from_provider2 = ci.get_id(IdentityPoolId=identity_pool_id, Logins={provider2: token2})["IdentityId"]

    assert id_from_provider1 == linked_id, f"provider1-only GetId diverged: {id_from_provider1!r} vs {linked_id!r}"
    assert id_from_provider2 == linked_id, f"provider2-only GetId diverged: {id_from_provider2!r} vs {linked_id!r}"

    # Independent read at the destination (DescribeIdentity, not GetId again): the identity's
    # persisted Logins actually carries both providers, not just three GetId calls agreeing by luck.
    described = ci.describe_identity(IdentityId=linked_id)
    assert set(described["Logins"]) == {provider1, provider2}, (
        f"expected DescribeIdentity Logins to carry both linked providers, got {described['Logins']!r}"
    )


def _create_user_pool_client(ctx):
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-upc-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    client_id = client["UserPoolClient"]["ClientId"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return pool_id, client_id, provider_name


def _create_confirmed_user_id_token(ctx, pool_id, client_id, email_value):
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Pass-1!"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": email_value},
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
