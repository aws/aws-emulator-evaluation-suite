"""update-user-pool-client-callback-urls-replaced."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "update-user-pool-client-callback-urls-replaced"
GROUP = 'scope-consistency'
SERVICES = ['cognito-idp']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserPoolClient's CallbackURLs/LogoutURLs are a full REPLACE, not
    a merge: after updating to a new set, DescribeUserPoolClient reflects
    exactly the new URLs and the original ones are gone."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    original_callback = "https://a.example.com/cb"
    original_logout = "https://a.example.com/logout"
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False,
        AllowedOAuthFlows=["code"],
        AllowedOAuthScopes=["openid"],
        AllowedOAuthFlowsUserPoolClient=True,
        CallbackURLs=[original_callback],
        LogoutURLs=[original_logout],
        SupportedIdentityProviders=["COGNITO"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    desc0 = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert desc0["CallbackURLs"] == [original_callback], desc0["CallbackURLs"]
    assert desc0["LogoutURLs"] == [original_logout], desc0["LogoutURLs"]

    new_callback = "https://b.example.com/cb"
    new_logout = "https://b.example.com/logout"
    c.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        CallbackURLs=[new_callback],
        LogoutURLs=[new_logout],
        AllowedOAuthFlows=["code"],
        AllowedOAuthScopes=["openid"],
        AllowedOAuthFlowsUserPoolClient=True,
        SupportedIdentityProviders=["COGNITO"],
    )
    desc1 = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert desc1["CallbackURLs"] == [new_callback], (
        f"expected CallbackURLs to be fully replaced with {[new_callback]}, got {desc1['CallbackURLs']}"
    )
    assert desc1["LogoutURLs"] == [new_logout], desc1["LogoutURLs"]
    assert original_callback not in desc1["CallbackURLs"], (
        "the original callback URL must not survive a replacing update"
    )
    assert original_logout not in desc1["LogoutURLs"], (
        "the original logout URL must not survive a replacing update"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
