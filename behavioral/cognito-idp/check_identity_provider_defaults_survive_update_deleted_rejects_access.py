"""identity-provider-defaults-survive-update-deleted-rejects-access."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-provider-defaults-survive-update-deleted-rejects-access"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

_DETAILS_V1 = {
    "client_id": "sim2real-behav-client-id",
    "client_secret": "sim2real-behav-client-secret",
    "attributes_request_method": "GET",
    "oidc_issuer": "https://sim2real-behav.example.com/oidc",
    "authorize_scopes": "openid",
    "authorize_url": "https://sim2real-behav.example.com/oidc/authorize",
    "token_url": "https://sim2real-behav.example.com/oidc/token",
    "attributes_url": "https://sim2real-behav.example.com/oidc/userinfo",
    "jwks_uri": "https://sim2real-behav.example.com/oidc/jwks",
}
_DETAILS_V2 = dict(_DETAILS_V1, authorize_url="https://sim2real-behav.example.com/oidc/authorize-v2")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating an OIDC provider with no AttributeMapping/IdpIdentifiers defaults to
    username:sub, empty IdpIdentifiers persists and update-without-them survives; an
    unknown ProviderType and the deleted provider's reads and delete are refused."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    provider_name = ctx.unique_name("sim2realbehavoidc").replace("-", "")[:32]

    created = idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails=_DETAILS_V1,
    )["IdentityProvider"]
    ctx.on_cleanup(_teardown(
        lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name),
        "ResourceNotFoundException",
    ))
    assert created["AttributeMapping"] == {"username": "sub"}, (
        f"expected default AttributeMapping username:sub, got {created['AttributeMapping']!r}"
    )
    assert "IdpIdentifiers" not in created, (
        f"expected no IdpIdentifiers key on a create that supplied none, "
        f"got {created.get('IdpIdentifiers')!r}"
    )

    described = idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert described["IdpIdentifiers"] == [], (
        f"expected Describe to report IdpIdentifiers as an empty list, got {described['IdpIdentifiers']!r}"
    )
    assert described["AttributeMapping"] == {"username": "sub"}, (
        f"expected Describe to report the default AttributeMapping, got {described['AttributeMapping']!r}"
    )

    listed = idp.list_identity_providers(UserPoolId=pool_id)["Providers"]
    matches = [p for p in listed if p["ProviderName"] == provider_name]
    assert len(matches) == 1, f"expected exactly one listed provider named {provider_name!r}, got {listed!r}"
    assert set(matches[0]) == {"ProviderName", "ProviderType", "CreationDate", "LastModifiedDate"}, (
        f"expected List to return only name/type/dates, got keys {sorted(matches[0])}"
    )

    updated = idp.update_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderDetails=_DETAILS_V2,
    )["IdentityProvider"]
    assert updated["ProviderDetails"]["authorize_url"] == _DETAILS_V2["authorize_url"], (
        f"expected the ProviderDetails member the update sent to apply, "
        f"got authorize_url={updated['ProviderDetails'].get('authorize_url')!r}"
    )

    after_update = idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)[
        "IdentityProvider"
    ]
    assert after_update["AttributeMapping"] == {"username": "sub"}, (
        f"expected AttributeMapping to survive an update that omitted it, "
        f"got {after_update['AttributeMapping']!r}"
    )
    assert after_update["IdpIdentifiers"] == [], (
        f"expected IdpIdentifiers to survive an update that omitted it, "
        f"got {after_update['IdpIdentifiers']!r}"
    )

    # Positive control for the refusal below: OIDC is a valid ProviderType and just succeeded above.
    bogus_name = ctx.unique_name("sim2realbehavbogus").replace("-", "")[:32]
    code, message = _error(lambda: idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=bogus_name,
        ProviderType="NotARealType",
        ProviderDetails={"client_id": "x"},
    ))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_enum_message = (
        "1 validation error detected: Value 'NotARealType' at 'providerType' failed to satisfy "
        "constraint: Member must satisfy enum value set: "
        "[Facebook, SAML, SignInWithApple, LoginWithAmazon, OIDC, Google]"
    )
    assert message == expected_enum_message, f"expected {expected_enum_message!r}, got {message!r}"

    # Positive control for the two refusals below: the same Describe just succeeded above.
    idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    expected_not_found = f"Identity provider {provider_name} for tenantId {pool_id} does not exist."

    code2, message2 = _error(
        lambda: idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert message2 == expected_not_found, f"expected {expected_not_found!r}, got {message2!r}"

    code3, message3 = _error(
        lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    assert code3 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code3}"
    assert message3 == expected_not_found, f"expected {expected_not_found!r}, got {message3!r}"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; a not-found code means it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
