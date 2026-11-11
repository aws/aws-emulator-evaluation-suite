"""client-token-opaque-value-unchanged-within-ttl."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "client-token-opaque-value-unchanged-within-ttl"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two GetClientToken calls for the same ClientId and scope return different tokens whose
    client_id, token_use (access) and scope claims are identical."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-m2mpool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-m2mpool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    resource_id = ctx.unique_name("sim2real-m2mres-")
    idp.create_resource_server(
        UserPoolId=pool_id,
        Identifier=resource_id,
        Name="M2M resource server",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )

    scope = f"{resource_id}/read"
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-m2mclient-"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=[scope],
    )["UserPoolClient"]
    client_id = client["ClientId"]
    client_secret = client["ClientSecret"]

    first = idp.get_client_token(ClientId=client_id, Secret=client_secret, Scopes=[scope])
    second = idp.get_client_token(ClientId=client_id, Secret=client_secret, Scopes=[scope])

    token_first = first["ClientAuthenticationResult"]["AccessToken"]
    token_second = second["ClientAuthenticationResult"]["AccessToken"]
    assert token_first != token_second, (
        "two GetClientToken calls for the same client+scopes returned the identical opaque "
        "token bytes -- Cognito documents no server-side cache for this flow, so a second call "
        "must mint a fresh JWT rather than replay the first one"
    )

    claims_first = _decode_jwt_claims(token_first)
    claims_second = _decode_jwt_claims(token_second)

    assert claims_first["client_id"] == client_id, (
        f"first token's client_id claim {claims_first.get('client_id')!r} != requesting "
        f"ClientId {client_id!r}"
    )
    assert claims_second["client_id"] == client_id, (
        f"second token's client_id claim {claims_second.get('client_id')!r} != requesting "
        f"ClientId {client_id!r}"
    )
    assert claims_first["token_use"] == "access", f"first token_use was {claims_first.get('token_use')!r}, expected 'access'"
    assert claims_second["token_use"] == "access", f"second token_use was {claims_second.get('token_use')!r}, expected 'access'"
    assert claims_first["scope"] == scope, f"first token scope claim {claims_first.get('scope')!r} != requested scope {scope!r}"
    assert claims_second["scope"] == scope, f"second token scope claim {claims_second.get('scope')!r} != requested scope {scope!r}"
    assert claims_first["scope"] == claims_second["scope"], (
        f"scope claim changed between two issuances of the same request: "
        f"{claims_first['scope']!r} != {claims_second['scope']!r}"
    )


def _decode_jwt_claims(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    return json.loads(decoded)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
