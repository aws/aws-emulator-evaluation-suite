"""provider-linking-alias."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provider-linking-alias"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminLinkProviderForUser creates a federated alias visible in the local user's
    "identities" attribute, and AdminDisableProviderForUser removes that federated sign-in
    path without deleting the local user."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-link-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-link"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    provider_name = "Google"
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="Google",
        ProviderDetails={
            "client_id": "1234567890-example.apps.googleusercontent.com",
            "client_secret": "example-client-secret-value",
            "authorize_scopes": "openid email",
        },
        AttributeMapping={"username": "sub"},
    )

    username = ctx.unique_name("sim2real-link-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )

    external_sub = ctx.unique_name("google-sub-")

    before = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    assert all(a["Name"] != "identities" for a in before)

    idp.admin_link_provider_for_user(
        UserPoolId=pool_id,
        DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": username},
        SourceUser={
            "ProviderName": provider_name,
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": external_sub,
        },
    )

    linked = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert linked["Enabled"] is True
    identities_attr = next((a for a in linked["UserAttributes"] if a["Name"] == "identities"), None)
    assert identities_attr is not None, linked["UserAttributes"]
    identities = json.loads(identities_attr["Value"])
    assert any(
        ident.get("providerName") == provider_name and ident.get("userId") == external_sub
        for ident in identities
    ), identities

    # the federated alias ("{ProviderName}_{ProviderAttributeValue}") resolves to the
    # SAME native user while the link is live
    alias_username = f"{provider_name}_{external_sub}"
    via_alias = idp.admin_get_user(UserPoolId=pool_id, Username=alias_username)
    assert via_alias["Username"] == username, (
        f"federated alias {alias_username!r} should resolve to native user {username!r}, "
        f"got {via_alias['Username']!r}"
    )

    idp.admin_disable_provider_for_user(
        UserPoolId=pool_id,
        User={
            "ProviderName": provider_name,
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": external_sub,
        },
    )

    # the federated sign-in path is actually gone: the alias is no longer resolvable
    alias_code, alias_message = _error(lambda: idp.admin_get_user(UserPoolId=pool_id, Username=alias_username))
    assert alias_code == "UserNotFoundException", (
        f"expected the disabled federated alias to be unresolvable, got {alias_code}"
    )
    expected = "User does not exist."
    assert alias_message == expected, f"expected message {expected!r}, got {alias_message!r}"

    # the local Cognito user account survives disabling the federated link
    still_there = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still_there["Username"] == username
    assert still_there["Enabled"] is True


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
