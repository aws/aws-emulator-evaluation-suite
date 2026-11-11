"""create-user-pool-client-conflicting-oauth-flows-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-pool-client-conflicting-oauth-flows-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolClient with client_credentials and implicit in AllowedOAuthFlows is refused
    with InvalidOAuthFlowException and the exact message and creates no client; only the control
    client is listed."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    # positive control: client_credentials ALONE (no conflicting browser flow) must succeed,
    # so a target that rejects everything cannot be mistaken for one that enforces the boundary.
    resource_server_id = ctx.unique_name("sim2real-behav-cip-res-")
    c.create_resource_server(
        UserPoolId=pool_id,
        Identifier=resource_server_id,
        Name=resource_server_id,
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )
    control_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-control-"),
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[f"{resource_server_id}/read"],
        AllowedOAuthFlowsUserPoolClient=True,
    )["UserPoolClient"]["ClientId"]

    error = _client_error(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
            GenerateSecret=True,
            AllowedOAuthFlows=["client_credentials", "implicit"],
            AllowedOAuthScopes=["openid"],
            AllowedOAuthFlowsUserPoolClient=True,
            CallbackURLs=["https://example.com/callback"],
        )
    )
    code = error.get("Code")
    assert code == "InvalidOAuthFlowException", f"expected InvalidOAuthFlowException, got {code}"
    expected_message = "client_credentials flow can not be selected along with code flow or implicit flow."
    message = error.get("Message")
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    client_ids = [
        c_["ClientId"]
        for c_ in c.list_user_pool_clients(UserPoolId=pool_id)["UserPoolClients"]
    ]
    assert client_ids == [control_id], (
        "a rejected CreateUserPoolClient must not create a client record beyond the "
        f"positive control: {client_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
