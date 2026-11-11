"""identity-provider-delete-blocked-while-referenced-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-provider-delete-blocked-while-referenced-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIdentityProvider for the built-in COGNITO name fails with ResourceNotFoundException and its
    exact message and COGNITO sign-in keeps working; a created OIDC provider deletes, and
    DescribeIdentityProvider on it then fails with ResourceNotFoundException and its exact message."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-idpblk-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-idpblk-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-idpblk-user-")
    password = "Sim2Real-Pw!23456"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    def _auth():
        return idp.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["AccessToken"]

    # Baseline: the default COGNITO identity source works before the rejected delete attempt.
    assert _auth(), "expected the default COGNITO sign-in to succeed before the rejected delete attempt"

    code, code_message = _error(lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName="COGNITO"))
    assert code == "ResourceNotFoundException", (
        f"expected DeleteIdentityProvider(ProviderName='COGNITO') to fail with "
        f"ResourceNotFoundException, got {code}"
    )
    code_expected = f"Identity provider COGNITO for tenantId {pool_id} does not exist."
    assert code_message == code_expected, (
        f"expected message {code_expected!r}, got {code_message!r}"
    )

    # effect absent: COGNITO sign-in is unaffected by the rejected delete attempt.
    assert _auth(), "expected COGNITO sign-in to still succeed after the rejected delete attempt"

    # positive control: a real, unreferenced IdP deletes cleanly (not a general delete failure).
    provider_name = ctx.unique_name("TestOidcProvider")
    idp.create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=provider_name,
        ProviderType="OIDC",
        ProviderDetails={
            "client_id": "example-oidc-client-id",
            "client_secret": "example-oidc-client-secret",
            "attributes_request_method": "GET",
            "authorize_scopes": "openid email",
            "oidc_issuer": "https://example.com",
            "authorize_url": "https://example.com/oauth2/authorize",
            "token_url": "https://example.com/oauth2/token",
            "attributes_url": "https://example.com/oauth2/userInfo",
            "jwks_uri": "https://example.com/oauth2/jwks",
        },
        AttributeMapping={"username": "sub"},
    )
    idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    code_after_delete, code_after_delete_message = _error(
        lambda: idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected the deleted IdP {provider_name!r} to be gone (ResourceNotFoundException), "
        f"got {code_after_delete}"
    )
    code_after_delete_expected = f"Identity provider {provider_name} for tenantId {pool_id} does not exist."
    assert code_after_delete_message == code_after_delete_expected, (
        f"expected message {code_after_delete_expected!r}, got {code_after_delete_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
