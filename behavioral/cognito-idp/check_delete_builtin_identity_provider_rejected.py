"""delete-builtin-identity-provider-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-builtin-identity-provider-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_PROVIDER_DETAILS = {
    "client_id": "sim2real-dummy-client-id",
    "client_secret": "sim2real-dummy-client-secret",
    "attributes_request_method": "GET",
    "oidc_issuer": "https://sim2real-behav.example.com/oidc",
    "authorize_scopes": "openid",
    "authorize_url": "https://sim2real-behav.example.com/oidc/authorize",
    "token_url": "https://sim2real-behav.example.com/oidc/token",
    "attributes_url": "https://sim2real-behav.example.com/oidc/userinfo",
    "jwks_uri": "https://sim2real-behav.example.com/oidc/jwks",
}


def _error(fn):
    """Call fn(); return its ClientError code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, it SUCCEEDED and returned {result!r}")


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIdentityProvider for the built-in COGNITO provider is refused with
    ResourceNotFoundException and the exact message, while deleting a user-created provider in the
    same pool succeeds and DescribeIdentityProvider then answers ResourceNotFoundException."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    code, message = _error(
        lambda: c.delete_identity_provider(UserPoolId=pool_id, ProviderName="COGNITO")
    )
    assert code == "ResourceNotFoundException", (
        f"expected a rejection for deleting the built-in provider, got {code}"
    )
    expected_message = f"Identity provider COGNITO for tenantId {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    provider_name = ctx.unique_name("sim2realbehavidp").replace("-", "")[:32]
    c.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails=_PROVIDER_DETAILS,
        AttributeMapping={"username": "sub"},
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(
            lambda: c.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
        )
    )
    c.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)

    gone_code, gone_message = _error(
        lambda: c.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted real IdP to 404 on an independent read, got {gone_code}"
    )
    expected_gone_message = f"Identity provider {provider_name} for tenantId {pool_id} does not exist."
    assert gone_message == expected_gone_message, f"expected message {expected_gone_message!r}, got {gone_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
