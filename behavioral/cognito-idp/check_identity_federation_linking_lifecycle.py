"""identity-federation-linking-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-federation-linking-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminLinkProviderForUser attaches a federated identity; AdminDisableProviderForUser detaches it."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_TAGS
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

    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    )

    sub_value = ctx.unique_name("sim2real-sub-")
    federated_username = f"{provider_name}_{sub_value}"
    source_user = {
        "ProviderName": provider_name,
        "ProviderAttributeName": "Cognito_Subject",
        "ProviderAttributeValue": sub_value,
    }

    cognito.admin_link_provider_for_user(
        UserPoolId=pool_id,
        DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": username},
        SourceUser=source_user,
    )

    linked = cognito.admin_get_user(UserPoolId=pool_id, Username=federated_username)
    linked_attrs = {a["Name"]: a["Value"] for a in linked["UserAttributes"]}
    destination_attrs = {
        a["Name"]: a["Value"]
        for a in cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert linked_attrs["email"] == destination_attrs["email"], (
        f"federated alias {federated_username!r} resolved to email {linked_attrs.get('email')!r}, "
        f"expected the destination user's email {destination_attrs.get('email')!r}"
    )

    cognito.admin_disable_provider_for_user(UserPoolId=pool_id, User=source_user)

    code, code_message = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=federated_username))
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    code_expected = "User does not exist."
    assert code_message == code_expected, (
        f"expected message {code_expected!r}, got {code_message!r}"
    )

    # the unlink must really have removed the link, not just returned 200: disabling the
    # same (provider, subject) pair again finds nothing left to disable.
    code_after, code_after_message = _error(
        lambda: cognito.admin_disable_provider_for_user(UserPoolId=pool_id, User=source_user)
    )
    assert code_after == "InvalidParameterException", (
        f"expected the already-removed link to be rejected again, got {code_after}"
    )
    code_after_expected = "Account isn't linked to anyone else, verify that the account has been linked"
    assert code_after_message == code_after_expected, (
        f"expected message {code_after_expected!r}, got {code_after_message!r}"
    )

    # the destination user itself must be unaffected by unlinking its federated identity
    still_there = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still_there["Username"] == username, (
        f"expected destination user {username!r} to remain after unlinking, got {still_there['Username']!r}"
    )


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
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
