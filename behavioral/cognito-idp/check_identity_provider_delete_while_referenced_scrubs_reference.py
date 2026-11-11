"""identity-provider-delete-while-referenced-scrubs-reference."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-provider-delete-while-referenced-scrubs-reference"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIdentityProvider succeeds while a client's SupportedIdentityProviders references the
    provider, and Cognito then removes that reference from the client (eventually consistent)."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    provider_name = ctx.unique_name("sim2real-idp-").replace("-", "")[:32]
    cognito.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "sim2real-dummy-client-id",
            "client_secret": "sim2real-dummy-client-secret",
            "attributes_request_method": "GET",
            "oidc_issuer": "https://sim2real-behav.example.com/oidc",
            "authorize_scopes": "openid",
            "authorize_url": "https://sim2real-behav.example.com/oidc/authorize",
            "token_url": "https://sim2real-behav.example.com/oidc/token",
            "attributes_url": "https://sim2real-behav.example.com/oidc/userinfo",
            "jwks_uri": "https://sim2real-behav.example.com/oidc/jwks",
        },
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(
            lambda: cognito.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
        )
    )

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        SupportedIdentityProviders=["COGNITO", provider_name],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    # Confirm the client's reference to the provider is actually visible before exercising
    # DeleteIdentityProvider against it; real AWS can lag briefly after CreateUserPoolClient.
    _poll_until(
        lambda: provider_name
        in cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"].get(
            "SupportedIdentityProviders", []
        ),
        description=f"client {client_id} to list {provider_name} in SupportedIdentityProviders",
    )

    # Cognito does not refuse this delete although a client still references the provider.
    cognito.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)

    code_after_delete, code_after_delete_message = _error(
        lambda: cognito.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code_after_delete}"
    )
    code_after_delete_expected = f"Identity provider {provider_name} for tenantId {pool_id} does not exist."
    assert code_after_delete_message == code_after_delete_expected, (
        f"expected message {code_after_delete_expected!r}, got {code_after_delete_message!r}"
    )

    # The reference removal can lag the DeleteIdentityProvider response, so poll for it.
    def _reference_scrubbed() -> bool:
        current = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
        return provider_name not in current.get("SupportedIdentityProviders", [])

    _poll_until(
        _reference_scrubbed,
        timeout=30.0,
        interval=2.0,
        description=(
            "AWS to remove the deleted identity provider from the client's "
            "SupportedIdentityProviders automatically"
        ),
    )

    client_after = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert provider_name not in client_after.get("SupportedIdentityProviders", []), client_after

    cognito.update_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id, SupportedIdentityProviders=["COGNITO"]
    )
    after_update = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert after_update.get("SupportedIdentityProviders") == ["COGNITO"], (
        f"expected the no-op update to leave SupportedIdentityProviders=['COGNITO'], "
        f"got {after_update.get('SupportedIdentityProviders')}"
    )


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(predicate, timeout: float = 15.0, interval: float = 1.0, description: str = "condition"):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for: {description} (last={last!r})")



def _error(fn):
    """Call fn() and return its error (code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
