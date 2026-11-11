"""get-client-token-scoped-to-requested-resource-server."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-client-token-scoped-to-requested-resource-server"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetClientToken (machine-to-machine client_credentials-style grant) issues an access token
    scoped to exactly the resource-server scope requested, excluding a sibling scope defined on
    the same resource server that was not requested."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    identifier = f"https://{ctx.unique_name('sim2real-api-')}.example.com"
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="sim2real M2M API",
        Scopes=[
            {"ScopeName": "read", "ScopeDescription": "read access"},
            {"ScopeName": "write", "ScopeDescription": "write access"},
        ],
    )
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        AllowedOAuthScopes=[f"{identifier}/read", f"{identifier}/write"],
    )["UserPoolClient"]

    read_scope = f"{identifier}/read"
    write_scope = f"{identifier}/write"

    result = cognito.get_client_token(
        ClientId=client["ClientId"], Secret=client["ClientSecret"], Scopes=[read_scope]
    )
    granted = set(
        _decode_jwt_claims(result["ClientAuthenticationResult"]["AccessToken"])["scope"].split()
    )

    assert read_scope in granted, f"expected requested scope {read_scope!r} in granted set, got {granted!r}"
    assert granted == {read_scope}, (
        f"expected the token to carry exactly {{{read_scope!r}}} (only the requested scope, "
        f"excluding the client's other allowed scope {write_scope!r}), got {granted!r}"
    )


def _create_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _decode_jwt_claims(token: str) -> dict:
    import base64
    import json

    payload = token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
