"""describe-nonexistent-identity-provider-fails."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "describe-nonexistent-identity-provider-fails"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityProvider for a never-created provider name fails with
    ResourceNotFoundException; the same call succeeds for a real IdP in the pool."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    provider_name = ctx.unique_name("sim2real-behav-oidc-").replace("-", "")[:32]
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "attributes_request_method": "GET",
            "oidc_issuer": "https://example.com/oidc",
            "authorize_scopes": "openid",
            "authorize_url": "https://example.com/oidc/authorize",
            "token_url": "https://example.com/oidc/token",
            "attributes_url": "https://example.com/oidc/userinfo",
            "jwks_uri": "https://example.com/oidc/jwks.json",
        },
    )
    ctx.on_cleanup(lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name))

    # Positive control: the real provider describes successfully.
    described = idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    got_name = described["IdentityProvider"]["ProviderName"]
    assert got_name == provider_name, f"expected ProviderName {provider_name!r}, got {got_name!r}"
    got_type = described["IdentityProvider"]["ProviderType"]
    assert got_type == "OIDC", f"expected ProviderType OIDC, got {got_type!r}"

    # Negative: a provider name that was never created must fail, not return an empty/fabricated payload.
    missing_name = ctx.unique_name("sim2real-behav-missing-").replace("-", "")[:32]
    code, message = _error(lambda: idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Identity provider {missing_name} for tenantId {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _error(fn) -> Any:
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an
    emulator accepting a lookup real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
