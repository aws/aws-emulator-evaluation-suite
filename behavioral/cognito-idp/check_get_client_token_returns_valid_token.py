"""get-client-token-returns-valid-token."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "get-client-token-returns-valid-token"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetClientToken issues a server-signed token whose claims match the client's configuration."""
    cognito = ctx.client("cognito-idp")

    pool_id, client_id, client_secret, resource_server_id = _setup_m2m_client(ctx, cognito)

    resp = cognito.get_client_token(
        ClientId=client_id,
        Secret=client_secret,
        Scopes=[f"{resource_server_id}/read"],
    )
    result = resp["ClientAuthenticationResult"]
    assert result["TokenType"] == "Bearer", result["TokenType"]
    assert result["ExpiresIn"] > 0, f"expected a positive ExpiresIn, got {result['ExpiresIn']!r}"

    claims = _decode_jwt_payload(result["AccessToken"])
    assert claims.get("token_use") == "access", claims
    assert claims.get("client_id") == client_id, claims
    scope_claim = claims.get("scope", "")
    assert f"{resource_server_id}/read" in scope_claim, (
        f"expected scope {resource_server_id}/read in token, got {scope_claim!r}"
    )
    claim_ttl = claims["exp"] - claims["iat"]
    assert abs(claim_ttl - result["ExpiresIn"]) <= 5, (
        f"ExpiresIn {result['ExpiresIn']}s doesn't match token's own exp-iat {claim_ttl}s"
    )


def _setup_m2m_client(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-m2m-pool"),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-m2m"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    resource_server_id = ctx.unique_name("sim2real-rs")
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=resource_server_id,
        Name="sim2real resource server",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )

    created = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-m2m-client"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=[f"{resource_server_id}/read"],
    )["UserPoolClient"]
    client_id = created["ClientId"]
    client_secret = created["ClientSecret"]
    return pool_id, client_id, client_secret, resource_server_id


def _decode_jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    return json.loads(raw)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
