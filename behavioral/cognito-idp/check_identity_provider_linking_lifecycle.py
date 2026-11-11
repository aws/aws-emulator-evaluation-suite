"""identity-provider-linking-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-provider-linking-lifecycle"
GROUP = 'state-machine'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_LENIENT_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After AdminLinkProviderForUser the federated alias resolves in AdminGetUser to the native user;
    after AdminDisableProviderForUser the alias fails with UserNotFoundException and its exact message
    while the native user remains."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password="Str0ngPassw0rd!", Permanent=True
    )

    # ProviderName is capped at 32 chars; unique_name appends 12 hex chars, so keep the prefix short.
    idp_name = ctx.unique_name("sim2real-idp-")
    c.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=idp_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "dummy-client-id",
            "client_secret": "dummy-client-secret-0123456789",
            "attributes_request_method": "GET",
            "authorize_scopes": "openid",
            "authorize_url": "https://auth.example.com/authorize",
            "attributes_url": "https://auth.example.com/userInfo",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "oidc_issuer": "https://auth.example.com",
            "token_url": "https://auth.example.com/token",
        },
    )
    ctx.on_cleanup(lambda: c.delete_identity_provider(UserPoolId=pool_id, ProviderName=idp_name))

    external_sub = "external-sub-123"
    c.admin_link_provider_for_user(
        UserPoolId=pool_id,
        DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": username},
        SourceUser={
            "ProviderName": idp_name,
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": external_sub,
        },
    )

    alias_username = f"{idp_name}_{external_sub}"
    linked = c.admin_get_user(UserPoolId=pool_id, Username=alias_username)
    assert linked["Username"] == username, (
        f"federated alias resolved to {linked['Username']!r}, expected {username!r}"
    )

    c.admin_disable_provider_for_user(
        UserPoolId=pool_id,
        User={
            "ProviderName": idp_name,
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": external_sub,
        },
    )

    code, code_message = _error(lambda: c.admin_get_user(UserPoolId=pool_id, Username=alias_username))
    assert code == "UserNotFoundException", (
        f"expected the unlinked federated alias to be unresolvable, got {code}"
    )
    code_expected = "User does not exist."
    assert code_message == code_expected, (
        f"expected message {code_expected!r}, got {code_message!r}"
    )
    # The native user itself must remain untouched by the unlink.
    still_there = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still_there["Username"] == username, (
        f"native user must survive AdminDisableProviderForUser, got {still_there!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
