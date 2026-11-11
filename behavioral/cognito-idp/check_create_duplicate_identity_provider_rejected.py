"""create-duplicate-identity-provider-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-duplicate-identity-provider-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED: {result!r}")


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIdentityProvider with an existing ProviderName is refused with
    DuplicateProviderException and the exact message and leaves the provider unchanged; after the
    provider is deleted the identical create succeeds."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c)
    provider_name = ctx.unique_name("idp-")
    identifier = ctx.unique_name("tenant-")
    details = {
        "client_id": "dummy-client-id",
        "client_secret": "dummy-client-secret-0123456789",
        "attributes_request_method": "GET",
        "authorize_scopes": "openid",
        "authorize_url": "https://auth.example.com/authorize",
        "attributes_url": "https://auth.example.com/userInfo",
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "oidc_issuer": "https://auth.example.com",
        "token_url": "https://auth.example.com/token",
    }
    c.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails=details,
        IdpIdentifiers=[identifier],
    )
    ctx.on_cleanup(
        lambda: c.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )

    # Break: reuse the SAME ProviderName with DIFFERENT details, so the rejection is provably
    # about the name colliding, not about the request being a byte-identical resubmission.
    conflicting_details = dict(details)
    conflicting_details["oidc_issuer"] = "https://auth-conflicting.example.com"
    code, message = _error(
        lambda: c.create_identity_provider(
            UserPoolId=pool_id,
            ProviderName=provider_name,
            ProviderType="OIDC",
            ProviderDetails=conflicting_details,
            IdpIdentifiers=[ctx.unique_name("conflicting-tenant-")],
        )
    )
    assert code == "DuplicateProviderException", f"expected DuplicateProviderException, got {code}"
    assert message == f"{provider_name} already exists for tenant {pool_id}.", (
        f"expected the exact duplicate-provider message, got {message!r}"
    )

    # Effect absent, via an independent read: the rejected re-create must not have overwritten
    # the original provider's details.
    described = c.describe_identity_provider(
        UserPoolId=pool_id, ProviderName=provider_name
    )["IdentityProvider"]
    assert described["ProviderDetails"]["oidc_issuer"] == "https://auth.example.com", (
        f"rejected duplicate create must not overwrite the original provider, "
        f"got {described['ProviderDetails']}"
    )

    # Restore: remove the pre-existing provider, so the name no longer collides, and prove the
    # identical create call now succeeds -- the constraint is live, not a permanent block.
    c.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    gone_code, gone_message = _error(
        lambda: c.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {gone_code}"
    assert gone_message == (
        f"Identity provider {provider_name} for tenantId {pool_id} does not exist."
    ), f"expected the exact deleted-provider message, got {gone_message!r}"

    c.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails=details,
        IdpIdentifiers=[identifier],
    )

    # Terminal assertion: an independent read at a DIFFERENT operation than the one that just
    # mutated, resolving through the identifier mapping rather than echoing the create response.
    resolved = c.get_identity_provider_by_identifier(
        UserPoolId=pool_id, IdpIdentifier=identifier
    )["IdentityProvider"]
    assert resolved["ProviderName"] == provider_name, (
        f"expected the restored provider {provider_name!r} to resolve by identifier, "
        f"got {resolved['ProviderName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
