"""create-identity-provider-duplicate-identifier-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-identity-provider-duplicate-identifier-rejected"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdentityProvider with a ProviderName already in the pool is refused with
    DuplicateProviderException and the exact message, and the existing provider keeps its issuer and
    still resolves by its identifier."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    name_a = ctx.unique_name("sim2real-oidc-a-")[:32]
    identifier_a = "tenant-a-id"

    _create_oidc_provider(ctx, pool_id, name_a, "https://issuer-a.example.com", [identifier_a])

    # Re-creating a provider with the SAME ProviderName (even with different
    # ProviderDetails) is the documented DuplicateProviderException trigger.
    code, message = _error(
        lambda: idp.create_identity_provider(
            UserPoolId=pool_id,
            ProviderName=name_a,
            ProviderType="OIDC",
            ProviderDetails={
                "client_id": "example-client-id-2",
                "client_secret": "example-client-secret-2",
                "attributes_request_method": "GET",
                "oidc_issuer": "https://issuer-b.example.com",
                "authorize_scopes": "openid",
                "authorize_url": "https://issuer-b.example.com/authorize",
                "token_url": "https://issuer-b.example.com/token",
                "attributes_url": "https://issuer-b.example.com/userInfo",
                "jwks_uri": "https://issuer-b.example.com/.well-known/jwks.json",
            },
            IdpIdentifiers=["tenant-b-id"],
        )
    )
    assert code == "DuplicateProviderException", f"expected DuplicateProviderException, got {code}"
    expected_message = f"{name_a} already exists for tenant {pool_id}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the original provider's ProviderDetails/issuer were not
    # overwritten by the rejected re-create attempt.
    described = idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=name_a)[
        "IdentityProvider"
    ]
    assert described["ProviderDetails"]["oidc_issuer"] == "https://issuer-a.example.com", (
        f"expected issuer-a to survive the rejected duplicate, got "
        f"{described['ProviderDetails'].get('oidc_issuer')!r}"
    )

    # Positive control: the original mapping still resolves correctly.
    resolved = idp.get_identity_provider_by_identifier(
        UserPoolId=pool_id, IdpIdentifier=identifier_a
    )["IdentityProvider"]
    assert resolved["ProviderName"] == name_a, (
        f"expected {identifier_a!r} to resolve to {name_a!r}, got {resolved['ProviderName']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_oidc_provider(ctx, pool_id: str, provider_name: str, issuer: str, idp_identifiers: list[str]) -> None:
    idp = ctx.client("cognito-idp")
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "example-client-id",
            "client_secret": "example-client-secret",
            "attributes_request_method": "GET",
            "oidc_issuer": issuer,
            "authorize_scopes": "openid",
            "authorize_url": f"{issuer}/authorize",
            "token_url": f"{issuer}/token",
            "attributes_url": f"{issuer}/userInfo",
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
        },
        IdpIdentifiers=idp_identifiers,
    )
    ctx.on_cleanup(
        lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
