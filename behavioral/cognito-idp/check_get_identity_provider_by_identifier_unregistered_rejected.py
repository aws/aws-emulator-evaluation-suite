"""get-identity-provider-by-identifier-unregistered-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-identity-provider-by-identifier-unregistered-rejected"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIdentityProviderByIdentifier rejects an IdpIdentifier that isn't registered
    on ANY provider in the pool with ResourceNotFoundException, even though a provider
    with a different, registered identifier exists in the same pool."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    registered_identifier = ctx.unique_name("sim2real-idp-registered-")[:40]
    unregistered_identifier = ctx.unique_name("sim2real-idp-unregistered-")[:40]
    provider_name = (ctx.unique_name("s2rIdpX-"))[:32].rstrip("-_ ")

    cognito.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "dummy-client",
            "client_secret": "dummy-secret",
            "attributes_request_method": "GET",
            "oidc_issuer": "https://example.com/oidc",
            "authorize_scopes": "openid",
            "authorize_url": "https://example.com/oidc/authorize",
            "token_url": "https://example.com/oidc/token",
            "attributes_url": "https://example.com/oidc/userinfo",
            "jwks_uri": "https://example.com/oidc/jwks",
        },
        IdpIdentifiers=[registered_identifier],
    )

    code, message = _error(
        lambda: cognito.get_identity_provider_by_identifier(
            UserPoolId=pool_id, IdpIdentifier=unregistered_identifier
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Identity provider {unregistered_identifier} for tenantId {pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected lookup did not silently attach the unregistered
    # identifier to the existing provider -- an independent read of the provider's
    # own identifier list, not the lookup call itself, must still show only the one
    # identifier we actually registered.
    idp_after = cognito.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert idp_after.get("IdpIdentifiers", []) == [registered_identifier], (
        f"expected IdpIdentifiers == [{registered_identifier!r}], got {idp_after.get('IdpIdentifiers')!r}"
    )

    # Positive control: the registered identifier resolves fine in the same pool.
    resolved = cognito.get_identity_provider_by_identifier(
        UserPoolId=pool_id, IdpIdentifier=registered_identifier
    )["IdentityProvider"]
    assert resolved["ProviderName"] == provider_name, (
        f"expected ProviderName == {provider_name!r}, got {resolved.get('ProviderName')!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
