"""get-client-token-invalid-secret-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-client-token-invalid-secret-rejected"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetClientToken rejects a request with an incorrect client Secret."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id, client_secret, resource_server_id = _setup_m2m_client(ctx, cognito)
    scopes = [f"{resource_server_id}/read"]

    # Positive control: the correct secret issues a token for this client, so the
    # rejection below cannot be "this client can never authenticate".
    good = cognito.get_client_token(ClientId=client_id, Secret=client_secret, Scopes=scopes)
    assert "AccessToken" in good["ClientAuthenticationResult"], good

    wrong_secret = "wrongsecretvaluethatdoesnotmatch1234"
    code = _error(
        lambda: cognito.get_client_token(
            ClientId=client_id,
            Secret=wrong_secret,
            Scopes=scopes,
        )
    )
    assert code == ("NotAuthorizedException", "Invalid client or secret"), (
        f"expected NotAuthorizedException, got {code!r}"
    )

    # The correct secret still works after the rejected attempt: the failed
    # authentication did not disable or otherwise mutate the client.
    good2 = cognito.get_client_token(ClientId=client_id, Secret=client_secret, Scopes=scopes)
    assert "AccessToken" in good2["ClientAuthenticationResult"], good2


def _setup_m2m_client(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-m2mneg-pool"),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-m2mneg"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    resource_server_id = ctx.unique_name("sim2real-rs-neg")
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=resource_server_id,
        Name="sim2real resource server neg",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )

    created = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-m2mneg-client"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=[f"{resource_server_id}/read"],
    )["UserPoolClient"]
    client_id = created["ClientId"]
    client_secret = created["ClientSecret"]
    return pool_id, client_id, client_secret, resource_server_id


def _error(fn):
    """Call fn(); return its botocore (Code, Message); an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
