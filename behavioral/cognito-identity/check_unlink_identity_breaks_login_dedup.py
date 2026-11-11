"""unlink-identity-breaks-login-dedup."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "unlink-identity-breaks-login-dedup"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnlinkIdentity removes a login mapping, so a later GetId with that login creates a new identity."""
    idp = ctx.client("cognito-idp")
    ci = ctx.client("cognito-identity")

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!2024"

    user_pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]
    user_pool_id = user_pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))

    client = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    client_id = client["ClientId"]

    idp.admin_create_user(
        UserPoolId=user_pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True
    )

    auth = idp.admin_initiate_auth(
        UserPoolId=user_pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[{"ProviderName": provider_name, "ClientId": client_id}],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    logins = {provider_name: id_token}

    identity_id_1 = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    # Same login again resolves to the same identity while it's still linked.
    identity_id_1_again = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    assert identity_id_1_again == identity_id_1, "GetId with the same login must dedup to the same identity"

    ci.unlink_identity(IdentityId=identity_id_1, Logins=logins, LoginsToRemove=[provider_name])

    identity_id_2 = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    assert identity_id_2 != identity_id_1, (
        f"expected a new, distinct identity after UnlinkIdentity broke the login mapping, "
        f"but GetId resolved back to the original identity {identity_id_1}"
    )

    # The state machine must not just mint a new identity once -- dedup has to resume working
    # under the *new* mapping too, or every subsequent GetId would mint yet another identity.
    identity_id_2_again = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    assert identity_id_2_again == identity_id_2, (
        f"GetId with the same login must dedup to the new identity {identity_id_2} once the "
        f"mapping is re-established, but a repeat call resolved to {identity_id_2_again}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
