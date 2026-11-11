"""get-client-token-disallowed-scope-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-client-token-disallowed-scope-rejected"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetClientToken rejects a requested scope that doesn't belong to any resource server in
    the pool, while a scope that is actually defined still succeeds for the same client."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    identifier = f"https://{ctx.unique_name('sim2real-api-')}.example.com"
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=identifier,
        Name="sim2real M2M API",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        AllowedOAuthScopes=[f"{identifier}/read"],
    )["UserPoolClient"]

    bogus_scope = f"{identifier}/does-not-exist"
    code = _error(
        lambda: cognito.get_client_token(
            ClientId=client["ClientId"], Secret=client["ClientSecret"], Scopes=[bogus_scope]
        )
    )
    assert code == ("NotAuthorizedException", "Invalid scopes requested"), (
        f"expected NotAuthorizedException for undefined scope "
        f"{bogus_scope!r}, got {code!r}"
    )

    # Positive control: a scope that genuinely exists on the resource server still works for
    # this same client, proving the rejection above is specific to the bogus scope. The terminal
    # read decodes the issued JWT rather than trusting the response envelope, so a target that
    # echoes back an empty or unscoped token still fails here.
    result = cognito.get_client_token(
        ClientId=client["ClientId"], Secret=client["ClientSecret"], Scopes=[f"{identifier}/read"]
    )
    granted = _decode_jwt_claims(result["ClientAuthenticationResult"]["AccessToken"])["scope"].split()
    assert f"{identifier}/read" in granted, (
        f"expected granted scope {identifier}/read in issued token, got {granted!r}"
    )


def _create_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _error(fn):
    """Call fn(); return its botocore (Code, Message); an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected GetClientToken to be rejected for the disallowed scope, but it succeeded "
        f"and returned {result!r}"
    )


def _decode_jwt_claims(token: str) -> dict:
    import base64
    import json

    payload = token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
