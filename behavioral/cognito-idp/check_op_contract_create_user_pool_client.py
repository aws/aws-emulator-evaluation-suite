"""op-contract-createUserPoolClient."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-createUserPoolClient"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolClient returns the requested auth flows without a secret; an AllowedOAuthScopes entry
    fails with ScopeDoesNotExistException and its exact message while its resource server is missing
    and creates no client, and is accepted once the resource server exists."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"))["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_name = ctx.unique_name("sim2real-client-")
    resp = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    client = resp["UserPoolClient"]
    assert client["ClientName"] == client_name, client
    assert set(client["ExplicitAuthFlows"]) == {
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
    }, client
    assert "ClientSecret" not in client, client

    described = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])[
        "UserPoolClient"
    ]
    assert described["ClientName"] == client_name, described

    # OAuth-scope boundary. Positive control first: a scope backed by a resource server
    # that exists is accepted.
    good_server_id = ctx.unique_name("sim2real-server-good-")
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=good_server_id,
        Name=good_server_id,
        Scopes=[{"ScopeName": "widgets.read", "ScopeDescription": "read access"}],
    )
    ctx.on_cleanup(lambda: cognito.delete_resource_server(UserPoolId=pool_id, Identifier=good_server_id))

    good_scope = f"{good_server_id}/widgets.read"
    good_client_name = ctx.unique_name("sim2real-oauth-client-good-")
    good_oauth = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=good_client_name,
        SupportedIdentityProviders=["COGNITO"],
        CallbackURLs=["https://example.com/cb"],
        AllowedOAuthFlows=["code"],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=["openid", good_scope],
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=good_oauth["ClientId"])
    )
    assert set(good_oauth["AllowedOAuthScopes"]) == {"openid", good_scope}, good_oauth

    # Break exactly one thing: the same shape of request, but the scope's resource
    # server does not exist yet.
    bad_server_id = ctx.unique_name("sim2real-server-bad-")
    bad_scope = f"{bad_server_id}/widgets.read"
    bad_client_name = ctx.unique_name("sim2real-oauth-client-bad-")
    bad_kwargs = dict(
        UserPoolId=pool_id,
        ClientName=bad_client_name,
        SupportedIdentityProviders=["COGNITO"],
        CallbackURLs=["https://example.com/cb"],
        AllowedOAuthFlows=["code"],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=["openid", bad_scope],
    )
    err = _client_error(lambda: cognito.create_user_pool_client(**bad_kwargs))
    assert err.get("Code") == "ScopeDoesNotExistException", f"expected ScopeDoesNotExistException, got {err!r}"
    want = f"Invalid scope requested: {bad_scope}"
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"

    # The rejection must not have created the client.
    names = {
        c["ClientName"]
        for c in cognito.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)["UserPoolClients"]
    }
    assert bad_client_name not in names, names

    # Restore: define the resource server the scope belongs to, then reissue the
    # identical request. It now succeeds.
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=bad_server_id,
        Name=bad_server_id,
        Scopes=[{"ScopeName": "widgets.read", "ScopeDescription": "read access"}],
    )
    ctx.on_cleanup(lambda: cognito.delete_resource_server(UserPoolId=pool_id, Identifier=bad_server_id))

    restored = cognito.create_user_pool_client(**bad_kwargs)["UserPoolClient"]
    ctx.on_cleanup(
        lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=restored["ClientId"])
    )
    assert restored["ClientName"] == bad_client_name, restored
    assert set(restored["AllowedOAuthScopes"]) == {"openid", bad_scope}, restored


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
