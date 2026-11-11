"""invalid-oauth-flow-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-oauth-flow-error"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolClient with client_credentials alongside the code grant fails with
    InvalidOAuthFlowException and its exact message and creates no client, while a code-only client
    is created and is the only one listed."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    # Positive control: the same account, pool and call shape accept a coherent single-flow
    # client, so a rejection below is attributable to the conflicting flow combination and not
    # to something else about the request (a missing callback URL, a bad scope, ...).
    control_name = ctx.unique_name("sim2real-behav-cip-control-")
    control_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=control_name,
        GenerateSecret=True,
        AllowedOAuthFlows=["code"],
        AllowedOAuthScopes=["aws.cognito.signin.user.admin"],
        AllowedOAuthFlowsUserPoolClient=True,
        CallbackURLs=["https://example.com/callback"],
        SupportedIdentityProviders=["COGNITO"],
    )["UserPoolClient"]["ClientId"]
    assert control_id, "positive control: a client with only the code grant must be created"

    client_name = ctx.unique_name("sim2real-behav-cip-client-")

    code, message = _error(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=client_name,
            GenerateSecret=True,
            AllowedOAuthFlows=["client_credentials", "code"],
            AllowedOAuthScopes=["aws.cognito.signin.user.admin"],
            AllowedOAuthFlowsUserPoolClient=True,
            CallbackURLs=["https://example.com/callback"],
            SupportedIdentityProviders=["COGNITO"],
        )
    )
    assert code == "InvalidOAuthFlowException", (
        f"expected InvalidOAuthFlowException for client_credentials+code, got {code}"
    )
    expected = "client_credentials flow can not be selected along with code flow or implicit flow."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    names = [
        cl["ClientName"]
        for cl in c.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)["UserPoolClients"]
    ]
    assert client_name not in names, (
        "a client that failed InvalidOAuthFlowException validation must not persist"
    )
    assert names == [control_name], (
        f"only the positive control client should exist in the pool, got {names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
