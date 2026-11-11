"""get-identity-provider-by-identifier-resolves-matching-provider."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-identity-provider-by-identifier-resolves-matching-provider"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIdentityProviderByIdentifier resolves the specific provider that owns an IdP identifier,
    distinguishing it from a second provider configured on the same pool."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    name_a = ctx.unique_name("sim2real-idpa-")
    name_b = ctx.unique_name("sim2real-idpb-")
    ident_a = ctx.unique_name("sim2real-identa-")
    ident_b = ctx.unique_name("sim2real-identb-")

    cognito.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=name_a,
        ProviderType="OIDC",
        ProviderDetails=_oidc_details("a"),
        IdpIdentifiers=[ident_a],
    )
    cognito.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=name_b,
        ProviderType="OIDC",
        ProviderDetails=_oidc_details("b"),
        IdpIdentifiers=[ident_b],
    )

    resolved_a = cognito.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=ident_a)
    resolved_b = cognito.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=ident_b)

    got_a = resolved_a["IdentityProvider"]["ProviderName"]
    got_b = resolved_b["IdentityProvider"]["ProviderName"]
    assert got_a == name_a, f"expected identifier {ident_a!r} to resolve to {name_a!r}, got {got_a!r}"
    assert got_a != name_b, f"identifier {ident_a!r} resolved to the other pool's provider {name_b!r}"
    assert got_b == name_b, f"expected identifier {ident_b!r} to resolve to {name_b!r}, got {got_b!r}"
    assert got_b != name_a, f"identifier {ident_b!r} resolved to the other pool's provider {name_a!r}"


def _create_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _oidc_details(tag: str) -> dict:
    # Providing every endpoint explicitly means Cognito never needs to fetch the issuer's
    # discovery document, so CreateIdentityProvider succeeds without a reachable IdP.
    return {
        "client_id": f"dummy-client-{tag}",
        "client_secret": f"dummy-client-secret-{tag}-0123456789",
        "authorize_scopes": "openid",
        "oidc_issuer": f"https://example.com/{tag}",
        "authorize_url": f"https://example.com/{tag}/authorize",
        "token_url": f"https://example.com/{tag}/token",
        "attributes_url": f"https://example.com/{tag}/userinfo",
        "jwks_uri": f"https://example.com/{tag}/.well-known/jwks.json",
        "attributes_request_method": "GET",
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
