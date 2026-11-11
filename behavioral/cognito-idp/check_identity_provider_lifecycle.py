"""identity-provider-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-provider-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdentityProvider is describable/listable/resolvable, updates persist, delete 404s."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    provider_name = ctx.unique_name("sim2real-idp-").replace("-", "")[:32]
    idp_identifier = ctx.unique_name("sim2real-ident-").replace("-", "")[:32]
    provider_details = {
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

    cognito.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails=provider_details,
        IdpIdentifiers=[idp_identifier],
        AttributeMapping={"username": "sub"},
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(
            lambda: cognito.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
        )
    )

    described = cognito.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert described["ProviderType"] == "OIDC", f"expected ProviderType OIDC, got {described['ProviderType']!r}"
    assert described["ProviderDetails"]["client_id"] == "sim2real-dummy-client-id", (
        f"expected client_id sim2real-dummy-client-id, got {described['ProviderDetails'].get('client_id')!r}"
    )

    names = {p["ProviderName"] for p in cognito.list_identity_providers(UserPoolId=pool_id)["Providers"]}
    assert provider_name in names, f"expected {provider_name!r} in {names}"

    by_ident = cognito.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=idp_identifier)[
        "IdentityProvider"
    ]
    assert by_ident["ProviderName"] == provider_name, (
        f"expected identifier lookup to resolve {provider_name!r}, got {by_ident['ProviderName']!r}"
    )

    cognito.update_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        AttributeMapping={"username": "sub", "email": "email"},
    )
    updated = cognito.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert updated["AttributeMapping"].get("email") == "email", (
        f"expected updated AttributeMapping to persist email->email, got {updated['AttributeMapping']!r}"
    )

    cognito.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)

    code, code_message = _error(
        lambda: cognito.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    code_expected = f"Identity provider {provider_name} for tenantId {pool_id} does not exist."
    assert code_message == code_expected, (
        f"expected message {code_expected!r}, got {code_message!r}"
    )

    names_after = {p["ProviderName"] for p in cognito.list_identity_providers(UserPoolId=pool_id)["Providers"]}
    assert provider_name not in names_after, f"expected {provider_name!r} absent from {names_after}"

    code2, code2_message = _error(
        lambda: cognito.get_identity_provider_by_identifier(UserPoolId=pool_id, IdpIdentifier=idp_identifier)
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    code2_expected = f"Identity provider {idp_identifier} for tenantId {pool_id} does not exist."
    assert code2_message == code2_expected, (
        f"expected message {code2_expected!r}, got {code2_message!r}"
    )

    code3, code3_message = _error(
        lambda: cognito.update_identity_provider(
            UserPoolId=pool_id,
            ProviderName=provider_name,
            AttributeMapping={"username": "sub"},
        )
    )
    assert code3 == "ResourceNotFoundException", (
        f"expected mutating the deleted provider to 404, got {code3}"
    )
    code3_expected = f"Identity provider {provider_name} in User Pool {pool_id} does not exist."
    assert code3_message == code3_expected, (
        f"expected message {code3_expected!r}, got {code3_message!r}"
    )


def _create_pool(ctx) -> str:
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
