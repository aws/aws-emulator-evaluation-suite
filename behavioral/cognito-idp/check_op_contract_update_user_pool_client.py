"""op-contract-update-user-pool-client."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-user-pool-client"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserPoolClient changes the name, auth flows and RefreshTokenValidity as DescribeUserPoolClient
    reads them; a scope no resource server defines fails with ScopeDoesNotExistException and its exact
    message and keeps the prior scopes, and is accepted once that scope exists."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-updclient-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-")
    )["UserPoolClient"]["ClientId"]

    updated = cognito.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        ClientName="renamed-client",
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        RefreshTokenValidity=45,
        TokenValidityUnits={"RefreshToken": "days"},
    )["UserPoolClient"]
    assert updated["ClientName"] == "renamed-client", updated
    assert set(updated["ExplicitAuthFlows"]) == {
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
    }, updated
    assert updated["RefreshTokenValidity"] == 45, updated

    described = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert described["ClientName"] == "renamed-client", described
    assert described["RefreshTokenValidity"] == 45, described

    # Positive control: a real resource server defines the scope, so the same
    # OAuth-shaped update succeeds.
    real_identifier = ctx.unique_name("sim2real-rs-")
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=real_identifier,
        Name=real_identifier,
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )
    real_scope = f"{real_identifier}/read"
    cognito.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        AllowedOAuthFlows=["code"],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=[real_scope],
        CallbackURLs=["https://example.com/callback"],
        SupportedIdentityProviders=["COGNITO"],
    )
    controlled = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert controlled["AllowedOAuthScopes"] == [real_scope], controlled

    # Error boundary: an OAuth scope that no resource server defines is rejected, and
    # the client's OAuth scopes are left exactly as the positive control set them.
    bogus_identifier = ctx.unique_name("sim2real-no-such-rs-")
    bogus_scope = f"{bogus_identifier}/no-such-scope"
    code, message = _error(
        lambda: cognito.update_user_pool_client(
            UserPoolId=pool_id,
            ClientId=client_id,
            AllowedOAuthFlows=["code"],
            AllowedOAuthFlowsUserPoolClient=True,
            AllowedOAuthScopes=[bogus_scope],
            CallbackURLs=["https://example.com/callback"],
            SupportedIdentityProviders=["COGNITO"],
        )
    )
    assert code == "ScopeDoesNotExistException", code
    expected = f"Invalid scope requested: {bogus_scope}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unaffected = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert unaffected["AllowedOAuthScopes"] == [real_scope], (
        f"a rejected update must not change AllowedOAuthScopes, got {unaffected['AllowedOAuthScopes']}"
    )

    # Restore: once the resource server and scope exist, the identical call succeeds.
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=bogus_identifier,
        Name=bogus_identifier,
        Scopes=[{"ScopeName": "no-such-scope", "ScopeDescription": "now exists"}],
    )
    cognito.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        AllowedOAuthFlows=["code"],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=[bogus_scope],
        CallbackURLs=["https://example.com/callback"],
        SupportedIdentityProviders=["COGNITO"],
    )
    restored = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert restored["AllowedOAuthScopes"] == [bogus_scope], (
        f"expected AllowedOAuthScopes {[bogus_scope]} once the scope exists, got "
        f"{restored['AllowedOAuthScopes']}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected update_user_pool_client to be rejected with ScopeDoesNotExistException, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
