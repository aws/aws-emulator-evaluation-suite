"""get-identity-provider-by-identifier-resolves-correct-provider."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-identity-provider-by-identifier-resolves-correct-provider"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIdentityProviderByIdentifier resolves the exact provider even when two
    providers' IdpIdentifiers overlap as string prefixes of each other."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    ident_a = ctx.unique_name("idp-tenant-")
    ident_b = ident_a + "-extended"  # overlapping prefix, but a distinct identifier

    name_a = ctx.unique_name("sim2real-google-a-")
    name_b = ctx.unique_name("sim2real-google-b-")

    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=name_a,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "sim2real-client-a",
            "client_secret": "provider-app-client-secret-a",
            "attributes_request_method": "GET",
            "oidc_issuer": "https://sim2real-a.example.com",
            "authorize_url": "https://sim2real-a.example.com/authorize",
            "token_url": "https://sim2real-a.example.com/token",
            "attributes_url": "https://sim2real-a.example.com/userInfo",
            "jwks_uri": "https://sim2real-a.example.com/.well-known/jwks.json",
            "authorize_scopes": "openid profile email",
        },
        IdpIdentifiers=[ident_a],
    )
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=name_b,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "sim2real-client-b",
            "client_secret": "provider-app-client-secret-b",
            "attributes_request_method": "GET",
            "oidc_issuer": "https://sim2real-b.example.com",
            "authorize_url": "https://sim2real-b.example.com/authorize",
            "token_url": "https://sim2real-b.example.com/token",
            "attributes_url": "https://sim2real-b.example.com/userInfo",
            "jwks_uri": "https://sim2real-b.example.com/.well-known/jwks.json",
            "authorize_scopes": "openid profile email",
        },
        IdpIdentifiers=[ident_b],
    )

    resolved_a = idp.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=ident_a)
    resolved_b = idp.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=ident_b)

    assert resolved_a["IdentityProvider"]["ProviderName"] == name_a, (
        f"expected IdpIdentifier {ident_a!r} to resolve to {name_a!r}, "
        f"got {resolved_a['IdentityProvider']['ProviderName']!r}"
    )
    assert resolved_b["IdentityProvider"]["ProviderName"] == name_b, (
        f"expected IdpIdentifier {ident_b!r} to resolve to {name_b!r}, "
        f"got {resolved_b['IdentityProvider']['ProviderName']!r}"
    )
    assert resolved_a["IdentityProvider"]["IdpIdentifiers"] == [ident_a], (
        f"expected provider {name_a!r} to report IdpIdentifiers {[ident_a]!r}, "
        f"got {resolved_a['IdentityProvider']['IdpIdentifiers']!r}"
    )
    assert resolved_b["IdentityProvider"]["IdpIdentifiers"] == [ident_b], (
        f"expected provider {name_b!r} to report IdpIdentifiers {[ident_b]!r}, "
        f"got {resolved_b['IdentityProvider']['IdpIdentifiers']!r}"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    resp = idp.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        **kwargs,
    )
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
