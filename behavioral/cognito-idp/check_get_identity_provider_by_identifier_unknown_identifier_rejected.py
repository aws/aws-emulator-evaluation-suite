"""get-identity-provider-by-identifier-unknown-identifier-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-identity-provider-by-identifier-unknown-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIdentityProviderByIdentifier resolves each registered identifier to its own provider and fails
    with ResourceNotFoundException and its exact message for an identifier no provider in the pool has."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    # Social IdP types (Google/Facebook/LoginWithAmazon/SignInWithApple) require the
    # ProviderName to be the exact reserved canonical name -- a custom/unique name is
    # rejected with InvalidParameterException at creation time. Use the literal "Google"
    # name (scoped to this fresh, throwaway pool, so no cross-test collision) so creation
    # itself succeeds and we can test the identifier-lookup boundary.
    provider_name = "Google"
    idp_identifier = ctx.unique_name("sim2real-idp-id-")

    cognito.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="Google",
        ProviderDetails={
            "client_id": "example.apps.googleusercontent.com",
            "client_secret": "example-client-secret",
            "authorize_scopes": "openid email profile",
        },
        IdpIdentifiers=[idp_identifier],
    )
    ctx.on_cleanup(lambda: cognito.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name))

    # A second, unrelated provider registered in the SAME pool under its own identifier.
    # Without this, "an identifier registered nowhere is rejected" is indistinguishable
    # from "any identifier resolves to the only provider that happens to exist" -- the
    # docstring's "never matching an unrelated provider" claim needs an unrelated
    # provider actually present to be worth anything.
    unrelated_provider_name = ctx.unique_name("s2rUnrelatedIdp-")[:32].rstrip("-_")
    unrelated_identifier = ctx.unique_name("sim2real-unrelated-idp-id-")
    cognito.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=unrelated_provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "sim2real-unrelated-client",
            "client_secret": "sim2real-unrelated-client-secret",
            "attributes_request_method": "GET",
            "oidc_issuer": "https://sim2real-unrelated.example.com",
            "authorize_url": "https://sim2real-unrelated.example.com/authorize",
            "token_url": "https://sim2real-unrelated.example.com/token",
            "attributes_url": "https://sim2real-unrelated.example.com/userinfo",
            "jwks_uri": "https://sim2real-unrelated.example.com/.well-known/jwks.json",
            "authorize_scopes": "openid",
        },
        IdpIdentifiers=[unrelated_identifier],
    )
    ctx.on_cleanup(
        lambda: cognito.delete_identity_provider(UserPoolId=pool_id, ProviderName=unrelated_provider_name)
    )

    # Positive control: the real, registered identifier resolves to the right provider,
    # not the unrelated one that also exists in this pool.
    resp = cognito.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=idp_identifier)
    assert resp["IdentityProvider"]["ProviderName"] == provider_name
    resp_unrelated = cognito.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=unrelated_identifier)
    assert resp_unrelated["IdentityProvider"]["ProviderName"] == unrelated_provider_name

    # Negative: an identifier never registered on any provider in this pool -- even
    # though a different, unrelated provider IS registered here under its own identifier.
    unknown_identifier = "never-registered-identifier-xyz"
    code, message = _error(
        lambda: cognito.get_identity_provider_by_identifier(
            UserPoolId=pool_id, IdpIdentifier=unknown_identifier
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Identity provider {unknown_identifier} for tenantId {pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
