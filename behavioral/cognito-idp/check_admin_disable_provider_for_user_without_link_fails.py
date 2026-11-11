"""admin-disable-provider-for-user-without-link-fails."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "admin-disable-provider-for-user-without-link-fails"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminDisableProviderForUser on an unlinked federated identity fails with
    InvalidParameterException (not UserNotFoundException); after AdminLinkProviderForUser it
    succeeds and removes the link, so a second disable fails again."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    provider_name = _create_oidc_provider(ctx, pool_id)
    username = _create_confirmed_user(ctx, pool_id)

    # Negative: this federated subject was never linked to anyone.
    never_linked_subject = "never-linked-subject-001"
    code, message = _error(
        lambda: idp.admin_disable_provider_for_user(
            UserPoolId=pool_id,
            User={
                "ProviderName": provider_name,
                "ProviderAttributeName": "Cognito_Subject",
                "ProviderAttributeValue": never_linked_subject,
            },
        )
    )
    assert (code, message) == ("InvalidParameterException", "Account isn't linked to anyone else, verify that the account has been linked"), f"expected InvalidParameterException, got {(code, message)!r}"

    linked_subject = "linked-subject-002"
    idp.admin_link_provider_for_user(
        UserPoolId=pool_id,
        DestinationUser={"ProviderAttributeValue": username, "ProviderName": "Cognito"},
        SourceUser={
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": linked_subject,
            "ProviderName": provider_name,
        },
    )

    # Cognito records each linked federated identity in the user's "identities" attribute.
    linked_identities = _linked_identities(idp, pool_id, username)
    assert any(
        i.get("providerName") == provider_name and i.get("userId") == linked_subject
        for i in linked_identities
    ), f"expected {provider_name}/{linked_subject} in identities after linking, got {linked_identities}"

    source_user = {
        "ProviderName": provider_name,
        "ProviderAttributeName": "Cognito_Subject",
        "ProviderAttributeValue": linked_subject,
    }
    idp.admin_disable_provider_for_user(UserPoolId=pool_id, User=source_user)

    remaining_identities = _linked_identities(idp, pool_id, username)
    assert not any(
        i.get("providerName") == provider_name and i.get("userId") == linked_subject
        for i in remaining_identities
    ), f"expected {provider_name}/{linked_subject} removed from identities, got {remaining_identities}"

    # With the link removed, disabling the same identifier fails again.
    code_after, message_after = _error(
        lambda: idp.admin_disable_provider_for_user(UserPoolId=pool_id, User=source_user)
    )
    assert (code_after, message_after) == ("InvalidParameterException", "Account isn't linked to anyone else, verify that the account has been linked"), (
        f"link should be removed after the first disable, got {(code_after, message_after)!r}"
    )


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_oidc_provider(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
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
    return provider_name


def _create_confirmed_user(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-behav-user-")
    password = "TestPassw0rd!23"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    return username


def _linked_identities(idp, pool_id: str, username: str) -> list[dict[str, Any]]:
    """Return the user's "identities" attribute (linked federated identities) via AdminGetUser."""
    attrs = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    raw = next((a["Value"] for a in attrs if a["Name"] == "identities"), None)
    if raw is None:
        return []
    return json.loads(raw)


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
